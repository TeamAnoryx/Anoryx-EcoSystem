"""Bedrock adapter translation + error-mapping tests (F-006, ADR-0008 §2.5).

NEVER touches aioboto3 or the network: a hand-rolled async stub client is
injected via session_factory. Covers request -> Converse translation, response
-> OpenAI shape, ConverseStream -> OpenAI SSE, model-id resolution, botocore
error -> ProviderError kind, content_filtered terminal, and n>1 terminal.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

from gateway.router.exceptions import ProviderError
from gateway.router.providers.bedrock_provider import (
    BedrockAdapter,
    _build_converse_kwargs,
    resolve_model_id,
)
from tests.gateway.router.conftest import (
    REPLACE_ME_AWS_KEY,
    REPLACE_ME_AWS_SECRET,
    make_body,
    make_ctx,
)


class _FakeClientError(Exception):
    """Mimics botocore.exceptions.ClientError shape (has .response)."""

    def __init__(self, status, code):
        self.response = {
            "ResponseMetadata": {"HTTPStatusCode": status},
            "Error": {"Code": code},
        }
        super().__init__(code)


class _StubBedrockClient:
    def __init__(self, *, converse_result=None, stream_events=None, raise_exc=None):
        self._converse_result = converse_result
        self._stream_events = stream_events or []
        self._raise = raise_exc

    async def converse(self, **kwargs):
        if self._raise:
            raise self._raise
        return self._converse_result

    async def converse_stream(self, **kwargs):
        if self._raise:
            raise self._raise

        async def _gen():
            for ev in self._stream_events:
                yield ev

        return {"stream": _gen()}


class _StubSession:
    def __init__(self, client: _StubBedrockClient):
        self._client = client
        self.client_kwargs: dict = {}

    def client(self, *args, **kwargs):
        client = self._client
        # MEDIUM-2: capture kwargs (incl. botocore `config`) for inspection.
        self.client_kwargs = kwargs

        @asynccontextmanager
        async def _cm():
            yield client

        return _cm()


def _adapter(client: _StubBedrockClient) -> BedrockAdapter:
    return BedrockAdapter(
        region="us-east-1",
        access_key_id=REPLACE_ME_AWS_KEY,
        secret_access_key=REPLACE_ME_AWS_SECRET,
        session_factory=lambda: _StubSession(client),
    )


# ---------------------------------------------------------------------------
# Request translation (golden) + model-id resolution
# ---------------------------------------------------------------------------


def test_resolve_model_id_maps_known_and_passes_through_bedrock_ids():
    assert resolve_model_id("claude-3-haiku").startswith("anthropic.claude-3-haiku")
    # An already-Bedrock-style id (contains a dot) passes through.
    assert resolve_model_id("amazon.titan-text-lite-v1") == "amazon.titan-text-lite-v1"


def test_request_translation_to_converse_shape():
    body = make_body(
        model="claude-3-haiku",
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ],
        max_tokens=100,
        temperature=0.2,
        top_p=0.8,
        stop=["A", "B"],
    )
    kwargs = _build_converse_kwargs(body)
    assert kwargs["modelId"].startswith("anthropic.claude-3-haiku")
    assert kwargs["system"] == [{"text": "sys"}]
    assert kwargs["messages"] == [{"role": "user", "content": [{"text": "hi"}]}]
    ic = kwargs["inferenceConfig"]
    assert ic["maxTokens"] == 100
    assert ic["temperature"] == 0.2
    assert ic["topP"] == 0.8
    assert ic["stopSequences"] == ["A", "B"]


# ---------------------------------------------------------------------------
# Response translation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_complete_translates_converse_response():
    result = {
        "output": {"message": {"role": "assistant", "content": [{"text": "Hi!"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 9, "outputTokens": 4, "totalTokens": 13},
    }
    adapter = _adapter(_StubBedrockClient(converse_result=result))
    completion, tin, tout = await adapter.complete(
        make_body(model="claude-3-haiku"), make_ctx("bedrock", "claude-3-haiku")
    )
    assert completion.object == "chat.completion"
    assert completion.choices[0].message.content == "Hi!"
    assert completion.choices[0].finish_reason == "stop"
    assert (tin, tout) == (9, 4)


@pytest.mark.asyncio
async def test_content_filtered_is_terminal():
    result = {
        "output": {"message": {"content": [{"text": ""}]}},
        "stopReason": "content_filtered",
        "usage": {"inputTokens": 1, "outputTokens": 0},
    }
    adapter = _adapter(_StubBedrockClient(converse_result=result))
    with pytest.raises(ProviderError) as ei:
        await adapter.complete(make_body(), make_ctx("bedrock", "claude-3-haiku"))
    assert ei.value.kind == "content_policy"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,code,expected",
    [
        (429, "ThrottlingException", "rate_limited"),
        (403, "AccessDeniedException", "auth"),
        (400, "ValidationException", "bad_request"),
        (500, "InternalServerException", "transient"),
    ],
)
async def test_botocore_error_maps_to_kind(status, code, expected):
    adapter = _adapter(_StubBedrockClient(raise_exc=_FakeClientError(status, code)))
    with pytest.raises(ProviderError) as ei:
        await adapter.complete(make_body(), make_ctx("bedrock", "claude-3-haiku"))
    assert ei.value.kind == expected


@pytest.mark.asyncio
async def test_client_built_with_budgeted_botocore_config():
    """MEDIUM-2 (ADR §11): the bedrock-runtime client is built with a botocore
    Config carrying the per-attempt timeout budget and botocore retries DISABLED.
    """
    result = {
        "output": {"message": {"role": "assistant", "content": [{"text": "Hi!"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    client = _StubBedrockClient(converse_result=result)
    session = _StubSession(client)
    adapter = BedrockAdapter(
        region="us-east-1",
        access_key_id=REPLACE_ME_AWS_KEY,
        secret_access_key=REPLACE_ME_AWS_SECRET,
        session_factory=lambda: session,
    )

    # Drive a complete() with a known remaining budget.
    await adapter.complete(
        make_body(model="claude-3-haiku"), make_ctx("bedrock", "claude-3-haiku", budget=25.0)
    )

    cfg = session.client_kwargs.get("config")
    assert cfg is not None, "botocore Config must be passed to session.client(...)"
    # read_timeout is the full remaining budget (<= 25.0 after a small elapsed).
    assert 0.0 < cfg.read_timeout <= 25.0
    # connect_timeout capped at 10s and never exceeds the budget.
    assert 0.0 < cfg.connect_timeout <= 10.0
    # botocore-internal retries disabled — router §6 loop is the sole retry authority.
    assert cfg.retries == {"max_attempts": 0}


def test_build_botocore_config_caps_connect_and_disables_retries():
    """Unit: connect_timeout caps at 10s even with a large budget; read=budget."""
    cfg = BedrockAdapter._build_botocore_config(120.0)
    assert cfg.read_timeout == 120.0
    assert cfg.connect_timeout == 10.0
    assert cfg.retries == {"max_attempts": 0}
    # With a small budget, connect_timeout follows the budget (min of 10, budget).
    cfg2 = BedrockAdapter._build_botocore_config(4.0)
    assert cfg2.connect_timeout == 4.0
    assert cfg2.read_timeout == 4.0


@pytest.mark.asyncio
async def test_bedrock_respects_remaining_budget():
    """MEDIUM-2 (ADR §11): a hung Converse call must NOT exceed the remaining
    wall-clock budget. asyncio.wait_for trips and the adapter raises a retryable
    transient ProviderError — and asyncio.CancelledError never leaks to the caller.
    """

    class _HangingClient(_StubBedrockClient):
        async def converse(self, **kwargs):  # hangs forever (simulates a stuck call)
            await asyncio.Event().wait()

    adapter = _adapter(_HangingClient())
    ctx = make_ctx("bedrock", "claude-3-haiku", budget=0.05)  # tiny budget -> fast trip

    loop = asyncio.get_event_loop()
    start = loop.time()
    with pytest.raises(ProviderError) as ei:
        await adapter.complete(make_body(), ctx)
    elapsed = loop.time() - start

    assert ei.value.kind == "transient"  # retryable timeout, NOT auth/parse
    assert ei.value.is_retryable is True
    assert elapsed < 2.0  # bounded by the budget; the hang did not run away


@pytest.mark.asyncio
async def test_n_gt_1_terminal_bedrock():
    adapter = _adapter(_StubBedrockClient(converse_result={}))
    with pytest.raises(ProviderError) as ei:
        await adapter.complete(make_body(n=3), make_ctx("bedrock", "claude-3-haiku"))
    assert ei.value.kind == "bad_request"


# ---------------------------------------------------------------------------
# Stream translation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_translates_converse_stream_to_openai_sse():
    events = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"delta": {"text": "Hel"}}},
        {"contentBlockDelta": {"delta": {"text": "lo"}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    adapter = _adapter(_StubBedrockClient(stream_events=events))
    lines = []
    async for line in adapter.stream(make_body(stream=True), make_ctx("bedrock", "claude-3-haiku")):
        lines.append(line)

    first = json.loads(lines[0][len("data: ") :])
    assert first["choices"][0]["delta"].get("role") == "assistant"
    contents = [
        json.loads(ln[len("data: ") :])["choices"][0]["delta"].get("content")
        for ln in lines
        if ln.startswith("data: ") and not ln.startswith("data: [DONE]")
    ]
    assert "Hel" in contents and "lo" in contents
    assert lines[-1].strip() == "data: [DONE]"
    finish = json.loads(lines[-2][len("data: ") :])
    assert finish["choices"][0]["finish_reason"] == "stop"
