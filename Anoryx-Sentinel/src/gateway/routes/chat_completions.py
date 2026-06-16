"""POST /v1/chat/completions route handler (ADR-0006, F-004).

This is the innermost handler (pipeline step 8). By the time a request reaches
here, steps 2–7 have already run:
  2. Body-size / edge guard (RequestValidationMiddleware)
  3. Header presence / format gate (TenantContextMiddleware)
  4. Auth (AuthMiddleware — virtual_key_row on request.state)
  5. ID cross-check + tenant context (resolve_tenant_context, called here)
  6. Rate limit (check_rate_limit, called here after context is resolved)
  7. Request-body validation (Pydantic model on the route)

Audit guarantee: emit_terminal_record() is called in ALL paths — success,
upstream failure, validation failure, etc. (ADR-0006 Decision 3).
If the audit append fails, the response is forced to 500 internal_error.

The request body is read from request.state.raw_body (set by
RequestValidationMiddleware after the 1 MiB capped read).
"""

from __future__ import annotations

import json
import time
import uuid

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from gateway.config import get_settings
from gateway.context import TenantContext
from gateway.exceptions import ERROR_TABLE, GatewayError
from gateway.middleware.audit import emit_terminal_record
from gateway.middleware.rate_limit import check_rate_limit, stream_slot
from gateway.middleware.tenant_context import resolve_tenant_context
from gateway.models import (
    ChatCompletionResponse,
    CreateChatCompletionRequest,
    ErrorResponse,
)
from gateway.upstream.openai_proxy import (
    _proxy_stream_generator,
    proxy_non_stream,
)

log = structlog.get_logger(__name__)

router = APIRouter()

_RATE_LIMIT_HEADERS_KEYS = ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")


def _error_response(
    error_code: str,
    request_id: str,
    *,
    retry_after: int | None = None,
) -> JSONResponse:
    """Build a contract-conformant JSON error response.

    message is looked up from ERROR_TABLE — never derived from request content.
    request_id is echoed in both the X-Request-Id header and the body.
    """
    message, status = ERROR_TABLE[error_code]
    body = ErrorResponse(
        error_code=error_code,  # type: ignore[arg-type]
        message=message,
        request_id=request_id,
    )
    headers = {"X-Request-Id": request_id}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        content=body.model_dump(),
        status_code=status,
        headers=headers,
    )


def _success_headers(
    request_id: str,
    rl_limit: int,
    rl_remaining: int,
    rl_reset: int,
) -> dict[str, str]:
    return {
        "X-Request-Id": request_id,
        "X-RateLimit-Limit": str(rl_limit),
        "X-RateLimit-Remaining": str(rl_remaining),
        "X-RateLimit-Reset": str(rl_reset),
    }


@router.post("/v1/chat/completions", response_model=None)
async def create_chat_completion(request: Request) -> JSONResponse | StreamingResponse:
    """POST /v1/chat/completions — full pipeline handler (non-stream + stream).

    Pipeline steps executed here (steps 5–8):
      5. ID cross-check + tenant context resolution
      6. Rate limit (post-auth, keyed on resolved key_id + tenant_id)
      7. Body validation (Pydantic, closed schema)
      8. Upstream proxy (typed re-serialization, no raw passthrough)

    Audit emitted on every terminal outcome (steps 1 / Decision 3).
    """
    settings = get_settings()
    start_time = time.monotonic()
    request_id = _make_request_id()

    # These will be populated progressively; used by the finally-block emit.
    tenant_context: TenantContext | None = None
    model: str = "unknown"
    tokens_in: int = 0
    tokens_out: int = 0
    rl_limit: int = settings.rate_limit_rpm
    rl_remaining: int = settings.rate_limit_rpm
    rl_reset: int = 0

    try:
        # --- Step 5: ID cross-check + tenant context resolution ---
        tenant_context = resolve_tenant_context(request)

        # --- Step 6: Rate limit (keyed on resolved IDs, never IP) ---
        is_stream_request = _peek_stream_flag(request)
        rl_limit, rl_remaining, rl_reset = await check_rate_limit(
            virtual_key_id=tenant_context.virtual_key_id,
            tenant_id=tenant_context.tenant_id,
            is_stream=is_stream_request,
        )

        # --- Step 7: Body validation ---
        raw_body = getattr(request.state, "raw_body", b"")
        if not raw_body:
            raise GatewayError("invalid_request")

        try:
            body_dict = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            raise GatewayError("invalid_request")

        try:
            validated = CreateChatCompletionRequest(**body_dict)
        except (ValidationError, TypeError):
            raise GatewayError("invalid_request")

        model = validated.model

        # Enforce MAX_TOKENS_PER_REQUEST cap (threat #4, ADR-0006 step 7).
        if validated.max_tokens is not None and validated.max_tokens > settings.max_tokens_per_request:
            raise GatewayError("invalid_request")

        # --- Step 8: Upstream proxy ---
        upstream_api_key: str | None = None  # Phase 0: no upstream key vaulting yet

        if validated.stream:
            # Streaming path (ADR-0006 Decision 7).
            return await _handle_stream(
                validated=validated,
                request_id=request_id,
                tenant_context=tenant_context,
                start_time=start_time,
                rl_limit=rl_limit,
                rl_remaining=rl_remaining,
                rl_reset=rl_reset,
                upstream_api_key=upstream_api_key,
                settings=settings,
            )
        else:
            # Non-streaming path.
            completion, tokens_in, tokens_out = await proxy_non_stream(
                validated_body=validated,
                request_id=request_id,
                upstream_api_key=upstream_api_key,
                overall_timeout=settings.request_timeout_seconds,
            )

            # Audit (success path) — must happen before returning.
            await emit_terminal_record(
                request_id=request_id,
                tenant_context=tenant_context,
                model=model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                start_time=start_time,
            )

            headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
            return JSONResponse(
                content=completion.model_dump(),
                status_code=200,
                headers=headers,
            )

    except GatewayError as exc:
        # Audit on every rejection (ADR-0006 audit guarantee).
        try:
            await emit_terminal_record(
                request_id=request_id,
                tenant_context=tenant_context,
                model=model,
                tokens_in=0,
                tokens_out=0,
                start_time=start_time,
            )
        except GatewayError:
            # Audit-emit itself failed → already GatewayError("internal_error").
            # Surface the audit-failure 500 (overrides the original error code).
            exc = GatewayError("internal_error")
        except Exception:
            exc = GatewayError("internal_error")

        resp = _error_response(exc.error_code, request_id, retry_after=exc.retry_after)
        resp.headers["X-RateLimit-Limit"] = str(rl_limit)
        resp.headers["X-RateLimit-Remaining"] = str(rl_remaining)
        resp.headers["X-RateLimit-Reset"] = str(rl_reset)
        return resp


async def _handle_stream(
    *,
    validated: CreateChatCompletionRequest,
    request_id: str,
    tenant_context: TenantContext,
    start_time: float,
    rl_limit: int,
    rl_remaining: int,
    rl_reset: int,
    upstream_api_key: str | None,
    settings,
) -> StreamingResponse:
    """Build and return a StreamingResponse for stream: true requests.

    The concurrent-stream slot is acquired/released via stream_slot() inside
    the generator — guaranteed decrement on close/complete/error/disconnect.
    Partial-stream audit is emitted in the generator's finally block.
    """
    # Token counters for partial-stream audit.
    token_state: dict = {"tokens_in": 0, "tokens_out": 0}

    async def _generate():
        """Async generator that wraps the upstream stream with audit + slot management."""
        async with stream_slot(tenant_context.tenant_id):
            try:
                async for chunk in _proxy_stream_generator(
                    validated_body=validated,
                    request_id=request_id,
                    upstream_api_key=upstream_api_key,
                    idle_timeout=settings.stream_timeout_seconds,
                    overall_timeout=settings.request_timeout_seconds,
                ):
                    # Accumulate output tokens from content chunks.
                    # Simple whitespace-token estimate — accurate accounting
                    # requires tiktoken (deferred to F-006/F-010).
                    if chunk.startswith("data: ") and not chunk.startswith("data: [DONE]"):
                        raw = chunk[6:].strip()
                        if raw and raw != "[DONE]":
                            try:
                                parsed = json.loads(raw)
                                choices = parsed.get("choices", [])
                                for c in choices:
                                    content = c.get("delta", {}).get("content") or ""
                                    # Approximate: split on whitespace for token estimate.
                                    token_state["tokens_out"] += len(content.split())
                            except (json.JSONDecodeError, KeyError, AttributeError):
                                pass
                    yield chunk
            finally:
                # Partial-stream audit: emit with tokens accumulated so far.
                # This runs on complete, error, timeout, and client disconnect.
                try:
                    # Estimate tokens_in from messages (word count approximation).
                    prompt_words = sum(
                        len(m.content.split()) for m in validated.messages
                    )
                    token_state["tokens_in"] = prompt_words
                    await emit_terminal_record(
                        request_id=request_id,
                        tenant_context=tenant_context,
                        model=validated.model,
                        tokens_in=token_state["tokens_in"],
                        tokens_out=token_state["tokens_out"],
                        start_time=start_time,
                    )
                except Exception:
                    # Audit failure in streaming path: log but cannot force 500
                    # (headers already sent). This is an edge case; the audit-
                    # failure-forces-500 guarantee applies to the response itself,
                    # which for streams means we cannot change the status code
                    # after streaming begins. Log for operator visibility.
                    log.exception("stream_audit_failed", request_id=request_id)

    headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
    return StreamingResponse(
        _generate(),
        status_code=200,
        media_type="text/event-stream",
        headers=headers,
    )


def _make_request_id() -> str:
    """Generate a request_id conforming to events.schema.json pattern ^[A-Za-z0-9._-]{1,64}$."""
    return "req-" + uuid.uuid4().hex[:32]


def _peek_stream_flag(request: Request) -> bool:
    """Peek at the raw body to determine if stream: true, without full validation.

    Used only to pre-check for the concurrent-stream cap before full body parse.
    Returns False on any parse error (safe default — no stream slot consumed).
    """
    try:
        raw = getattr(request.state, "raw_body", b"")
        if raw:
            data = json.loads(raw)
            return bool(data.get("stream", False))
    except Exception:
        pass
    return False
