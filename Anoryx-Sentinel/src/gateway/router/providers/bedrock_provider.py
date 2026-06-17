"""Bedrock provider adapter — translate + SigV4 (F-006, ADR-0008 §2.5 / §11).

Uses aioboto3's bedrock-runtime Converse / ConverseStream. aioboto3 is
LAZY-IMPORTED inside the method (NEVER at module import) so the gateway imports
and the test suite collects even when aioboto3 is absent (HARD CONSTRAINT).
Tests stub the transport via the injected session factory.

SigV4 credentials and region are PINNED FROM CONFIG (AWS_REGION,
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), never client-influenced (threat #7).
Translates request -> Converse, response/stream -> OpenAI shape, INSIDE the
adapter (threat #8). Maps only allow-listed fields (threat #12). Raises
ProviderError on every failure; never attaches upstream body text (threat #10).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncIterator

from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest
from gateway.router.context import RoutingContext
from gateway.router.exceptions import ProviderError
from gateway.router.providers import _translate

# Static model-map for well-known base models (ADR §7 / §12: fine-tune mapping
# deferred to F-011). An OpenAI-style model name maps to a Bedrock modelId. If
# the client already passes a Bedrock-style id (contains a dot), it is used as-is.
_MODEL_MAP: dict[str, str] = {
    "claude-3-5-sonnet": "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "claude-3-haiku": "anthropic.claude-3-haiku-20240307-v1:0",
    "claude-3-sonnet": "anthropic.claude-3-sonnet-20240229-v1:0",
    "claude-3-opus": "anthropic.claude-3-opus-20240229-v1:0",
}


def resolve_model_id(model: str) -> str:
    """Resolve an OpenAI-style model name to a Bedrock modelId (static map)."""
    if "." in model:  # already a Bedrock modelId (provider.family-...)
        return model
    for prefix, model_id in _MODEL_MAP.items():
        if model.startswith(prefix):
            return model_id
    # Unknown: pass through; Bedrock will reject -> bad_request TERMINAL.
    return model


def _build_converse_kwargs(body: CreateChatCompletionRequest) -> dict[str, Any]:
    """Translate OpenAI request -> Converse kwargs (allow-list only)."""
    system: list[dict[str, str]] = []
    messages: list[dict[str, Any]] = []
    for m in body.messages:
        if m.role == "system":
            system.append({"text": m.content})
        elif m.role in ("user", "assistant"):
            messages.append({"role": m.role, "content": [{"text": m.content}]})
        else:  # tool -> fold into system context (no F-006 1:1 mapping)
            system.append({"text": m.content})

    inference: dict[str, Any] = {}
    if body.max_tokens is not None:
        inference["maxTokens"] = body.max_tokens
    if body.temperature is not None:
        inference["temperature"] = body.temperature
    if body.top_p is not None:
        inference["topP"] = body.top_p
    if body.stop is not None:
        inference["stopSequences"] = [body.stop] if isinstance(body.stop, str) else list(body.stop)

    kwargs: dict[str, Any] = {
        "modelId": resolve_model_id(body.model),
        "messages": messages,
    }
    if system:
        kwargs["system"] = system
    if inference:
        kwargs["inferenceConfig"] = inference
    return kwargs


def _translate_converse_response(
    resp: dict[str, Any], model: str
) -> tuple[ChatCompletionResponse, int, int]:
    """Translate a Converse response -> OpenAI shape + token counts."""
    try:
        message = (resp.get("output", {}) or {}).get("message", {}) or {}
        blocks = message.get("content", []) or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and "text" in b)
        finish = _translate.map_finish_reason(resp.get("stopReason"))
        usage = resp.get("usage", {}) or {}
        tokens_in = int(usage.get("inputTokens", 0) or 0)
        tokens_out = int(usage.get("outputTokens", 0) or 0)
        completion = _translate.build_response(
            model=model,
            content=text,
            finish_reason=finish,
            prompt_tokens=tokens_in,
            completion_tokens=tokens_out,
        )
        return completion, tokens_in, tokens_out
    except ProviderError:
        raise
    except Exception:
        raise ProviderError(kind="parse") from None


def _classify_botocore_error(exc: Exception) -> str:
    """Map a botocore ClientError / transport error to a ProviderError kind."""
    # Inspect the error structure without importing botocore at module scope.
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        meta = response.get("ResponseMetadata", {}) or {}
        status = meta.get("HTTPStatusCode")
        code = (response.get("Error", {}) or {}).get("Code", "")
        if status == 429 or code in ("ThrottlingException", "TooManyRequestsException"):
            return "rate_limited"
        if status in (401, 403) or code in (
            "AccessDeniedException",
            "UnrecognizedClientException",
            "ExpiredTokenException",
        ):
            return "auth"
        if code in ("ValidationException",):
            return "bad_request"
        if isinstance(status, int) and status >= 500:
            return "transient"
    return "transient"


class BedrockAdapter:
    """Bedrock Converse adapter. aioboto3 is imported lazily inside methods."""

    name = "bedrock"

    def __init__(
        self,
        region: str,
        access_key_id: str,
        secret_access_key: str,
        *,
        session_factory: Any = None,
    ) -> None:
        # region + creds are CONFIG-PINNED (threat #7). session_factory is a test
        # seam: when None, aioboto3.Session is lazy-imported at call time.
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._session_factory = session_factory

    def _session(self) -> Any:
        if self._session_factory is not None:
            return self._session_factory()
        # LAZY import — module import must not require aioboto3 (HARD CONSTRAINT).
        import aioboto3  # noqa: PLC0415

        return aioboto3.Session()

    def _client_cm(self, session: Any, timeout: float) -> Any:
        """Return the bedrock-runtime client context manager (region/creds pinned).

        MEDIUM-2 (ADR §11): enforce the per-attempt timeout BUDGET on botocore.
        connect_timeout is capped at 10s but never exceeds the remaining budget;
        read_timeout is the full remaining budget; botocore-internal retries are
        DISABLED (max_attempts=0) so the router's §6 fallback loop is the single
        retry authority (no hidden double-retries / budget burn). botocore.config
        is lazy-imported alongside aioboto3 so module import without aioboto3 still
        works (HARD CONSTRAINT). A test session_factory may ignore `config`.
        """
        time_left = max(0.0, float(timeout))
        cfg = self._build_botocore_config(time_left)
        return session.client(
            "bedrock-runtime",
            region_name=self._region,
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self._secret_access_key,
            config=cfg,
        )

    @staticmethod
    def _build_botocore_config(time_left: float) -> Any:
        """Build a botocore Config with budgeted timeouts (lazy import)."""
        from botocore.config import Config  # noqa: PLC0415 — lazy (HARD CONSTRAINT)

        return Config(
            connect_timeout=min(10.0, time_left),
            read_timeout=time_left,
            retries={"max_attempts": 0},
        )

    async def complete(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> tuple[ChatCompletionResponse, int, int]:
        if validated_body.n > 1:
            raise ProviderError(kind="bad_request")

        kwargs = _build_converse_kwargs(validated_body)
        budget = ctx.time_left()
        if budget <= 0:
            # No wall-clock budget left for this attempt -> retryable timeout.
            raise ProviderError(kind="transient")
        session = self._session()
        try:
            async with self._client_cm(session, budget) as client:
                # MEDIUM-2 (ADR §11) belt-and-suspenders: bound the call to the
                # remaining wall-clock budget even if a transport/stub ignores the
                # botocore read_timeout. asyncio.wait_for converts a hang to
                # TimeoutError; asyncio.CancelledError never leaks to the caller.
                resp = await asyncio.wait_for(client.converse(**kwargs), timeout=budget)
        except ProviderError:
            raise
        except asyncio.TimeoutError:
            raise ProviderError(kind="transient") from None
        except Exception as exc:
            raise ProviderError(kind=_classify_botocore_error(exc)) from None

        if resp.get("stopReason") in ("content_filtered", "guardrail_intervened"):
            raise ProviderError(kind="content_policy")

        return _translate_converse_response(resp, validated_body.model)

    async def stream(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> AsyncIterator[str]:
        if validated_body.n > 1:
            raise ProviderError(kind="bad_request")

        kwargs = _build_converse_kwargs(validated_body)
        created = int(time.time())
        chunk_id = _translate.synth_id()
        model = validated_body.model
        role_sent = False
        finish_reason = "stop"

        budget = ctx.time_left()
        if budget <= 0:
            raise ProviderError(kind="transient")
        session = self._session()
        try:
            async with self._client_cm(session, budget) as client:
                # MEDIUM-2 (ADR §11): bound BOTH the open call and each event read to
                # the remaining wall-clock budget. wait_for -> TimeoutError on a hang;
                # asyncio.CancelledError never leaks to the caller.
                resp = await asyncio.wait_for(client.converse_stream(**kwargs), timeout=budget)
                event_iter = resp.get("stream").__aiter__()
                while True:
                    try:
                        event = await asyncio.wait_for(
                            event_iter.__anext__(), timeout=max(0.001, ctx.time_left())
                        )
                    except StopAsyncIteration:
                        break
                    if "messageStart" in event and not role_sent:
                        role_sent = True
                        yield _translate.chunk_line(
                            chunk_id=chunk_id, model=model, created=created, role="assistant"
                        )
                    elif "contentBlockDelta" in event:
                        text = (event["contentBlockDelta"].get("delta", {}) or {}).get("text")
                        if text:
                            if not role_sent:
                                role_sent = True
                                yield _translate.chunk_line(
                                    chunk_id=chunk_id,
                                    model=model,
                                    created=created,
                                    role="assistant",
                                )
                            yield _translate.chunk_line(
                                chunk_id=chunk_id, model=model, created=created, content=text
                            )
                    elif "messageStop" in event:
                        sr = event["messageStop"].get("stopReason")
                        finish_reason = _translate.map_finish_reason(sr)
        except ProviderError:
            raise
        except asyncio.TimeoutError:
            raise ProviderError(kind="transient") from None
        except Exception as exc:
            raise ProviderError(kind=_classify_botocore_error(exc)) from None

        yield _translate.chunk_line(
            chunk_id=chunk_id, model=model, created=created, finish_reason=finish_reason
        )
        yield _translate.DONE_LINE
