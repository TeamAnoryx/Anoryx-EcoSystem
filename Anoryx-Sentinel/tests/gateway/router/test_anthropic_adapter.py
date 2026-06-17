"""Anthropic adapter translation + error-mapping tests (F-006, ADR-0008 §2.4).

Stubs the Messages API over httpx via pytest-httpx. Covers:
  - request translation (system split, max_tokens injection, stop_sequences,
    allow-list only),
  - response translation -> OpenAI shape + token counts + finish_reason map,
  - stream translation -> OpenAI-shape SSE chunks ending in [DONE],
  - status -> ProviderError kind mapping (429/401/5xx/4xx),
  - content_policy via stop_reason refusal,
  - n>1 -> bad_request TERMINAL.
"""

from __future__ import annotations

import json

import httpx
import pytest

from gateway.router.exceptions import ProviderError
from gateway.router.providers.anthropic_provider import (
    AnthropicAdapter,
    _build_messages_request,
)
from tests.gateway.router.conftest import REPLACE_ME_ANTHROPIC_KEY, make_body, make_ctx

_BASE = "https://api.anthropic.test"


def _adapter(client: httpx.AsyncClient, default_max_tokens=1024) -> AnthropicAdapter:
    return AnthropicAdapter(
        client=client, api_key=REPLACE_ME_ANTHROPIC_KEY, default_max_tokens=default_max_tokens
    )


# ---------------------------------------------------------------------------
# Request translation (golden) — pure function, no HTTP.
# ---------------------------------------------------------------------------


def test_request_translation_splits_system_and_injects_max_tokens():
    body = make_body(
        model="claude-3-haiku",
        messages=[
            {"role": "system", "content": "be terse"},
            {"role": "system", "content": "and kind"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "yo"},
        ],
        temperature=0.5,
        top_p=0.9,
        stop="STOP",
    )
    req = _build_messages_request(body, default_max_tokens=777)
    assert req["system"] == "be terse\nand kind"
    assert req["messages"] == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "yo"},
    ]
    # max_tokens omitted by client -> default injected (Anthropic requires it).
    assert req["max_tokens"] == 777
    assert req["temperature"] == 0.5
    assert req["top_p"] == 0.9
    assert req["stop_sequences"] == ["STOP"]
    # Allow-list only: no 'n', no 'user', no stray keys.
    assert set(req.keys()) <= {
        "model",
        "messages",
        "max_tokens",
        "stream",
        "system",
        "temperature",
        "top_p",
        "stop_sequences",
    }


def test_request_translation_respects_client_max_tokens():
    body = make_body(max_tokens=42)
    req = _build_messages_request(body, default_max_tokens=1024)
    assert req["max_tokens"] == 42


# ---------------------------------------------------------------------------
# Response translation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_complete_translates_response_to_openai_shape(httpx_mock):
    httpx_mock.add_response(
        url=f"{_BASE}/v1/messages",
        json={
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello "}, {"type": "text", "text": "there"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        },
    )
    async with httpx.AsyncClient(base_url=_BASE) as client:
        adapter = _adapter(client)
        completion, tin, tout = await adapter.complete(
            make_body(model="claude-3-haiku"), make_ctx("anthropic", "claude-3-haiku")
        )

    assert completion.object == "chat.completion"
    assert completion.id.startswith("chatcmpl-")
    assert completion.model == "claude-3-haiku"
    assert completion.choices[0].message.content == "Hello there"
    assert completion.choices[0].finish_reason == "stop"  # end_turn -> stop
    assert (tin, tout) == (11, 7)
    assert completion.usage.total_tokens == 18


@pytest.mark.asyncio
async def test_complete_maps_max_tokens_finish_reason(httpx_mock):
    httpx_mock.add_response(
        url=f"{_BASE}/v1/messages",
        json={
            "content": [{"type": "text", "text": "x"}],
            "stop_reason": "max_tokens",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        },
    )
    async with httpx.AsyncClient(base_url=_BASE) as client:
        completion, _, _ = await _adapter(client).complete(
            make_body(), make_ctx("anthropic", "claude-3-haiku")
        )
    assert completion.choices[0].finish_reason == "length"


# ---------------------------------------------------------------------------
# Error / status mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,expected_kind",
    [(429, "rate_limited"), (401, "auth"), (403, "auth"), (500, "transient"), (400, "bad_request")],
)
async def test_status_maps_to_provider_error_kind(httpx_mock, status, expected_kind):
    httpx_mock.add_response(url=f"{_BASE}/v1/messages", status_code=status, json={"error": "x"})
    async with httpx.AsyncClient(base_url=_BASE) as client:
        with pytest.raises(ProviderError) as ei:
            await _adapter(client).complete(make_body(), make_ctx("anthropic", "claude-3-haiku"))
    assert ei.value.kind == expected_kind
    # No upstream body text leaks onto the exception message (threat #10).
    assert "error" not in str(ei.value)


@pytest.mark.asyncio
async def test_content_policy_refusal_is_terminal(httpx_mock):
    httpx_mock.add_response(
        url=f"{_BASE}/v1/messages",
        json={
            "content": [],
            "stop_reason": "refusal",
            "usage": {"input_tokens": 1, "output_tokens": 0},
        },
    )
    async with httpx.AsyncClient(base_url=_BASE) as client:
        with pytest.raises(ProviderError) as ei:
            await _adapter(client).complete(make_body(), make_ctx("anthropic", "claude-3-haiku"))
    assert ei.value.kind == "content_policy"
    assert ei.value.is_retryable is False


@pytest.mark.asyncio
async def test_n_gt_1_is_bad_request_terminal():
    async with httpx.AsyncClient(base_url=_BASE) as client:
        with pytest.raises(ProviderError) as ei:
            await _adapter(client).complete(make_body(n=2), make_ctx("anthropic", "claude-3-haiku"))
    assert ei.value.kind == "bad_request"


# ---------------------------------------------------------------------------
# Stream translation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_translates_to_openai_sse(httpx_mock):
    def _ev(payload: dict) -> str:
        return f"event: {payload['type']}\ndata: {json.dumps(payload)}\n\n"

    sse = (
        _ev({"type": "message_start"})
        + _ev({"type": "content_block_delta", "delta": {"text": "Hel"}})
        + _ev({"type": "content_block_delta", "delta": {"text": "lo"}})
        + _ev({"type": "message_delta", "delta": {"stop_reason": "end_turn"}})
        + _ev({"type": "message_stop"})
    )
    httpx_mock.add_response(
        url=f"{_BASE}/v1/messages",
        status_code=200,
        content=sse.encode(),
        headers={"content-type": "text/event-stream"},
    )

    lines: list[str] = []
    async with httpx.AsyncClient(base_url=_BASE) as client:
        async for line in _adapter(client).stream(
            make_body(stream=True), make_ctx("anthropic", "claude-3-haiku")
        ):
            lines.append(line)

    # First non-DONE chunk carries delta.role assistant.
    first = json.loads(lines[0][len("data: ") :])
    assert first["object"] == "chat.completion.chunk"
    assert first["choices"][0]["delta"].get("role") == "assistant"
    # Content deltas present, in order.
    contents = [
        json.loads(ln[len("data: ") :])["choices"][0]["delta"].get("content")
        for ln in lines
        if ln.startswith("data: ") and not ln.startswith("data: [DONE]")
    ]
    assert "Hel" in contents and "lo" in contents
    # Terminal finish_reason chunk then [DONE].
    assert lines[-1].strip() == "data: [DONE]"
    finish_chunk = json.loads(lines[-2][len("data: ") :])
    assert finish_chunk["choices"][0]["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_stream_pre_first_byte_error_raises(httpx_mock):
    httpx_mock.add_response(url=f"{_BASE}/v1/messages", status_code=503)
    async with httpx.AsyncClient(base_url=_BASE) as client:
        gen = _adapter(client).stream(
            make_body(stream=True), make_ctx("anthropic", "claude-3-haiku")
        )
        with pytest.raises(ProviderError) as ei:
            await gen.__anext__()
    assert ei.value.kind == "transient"
