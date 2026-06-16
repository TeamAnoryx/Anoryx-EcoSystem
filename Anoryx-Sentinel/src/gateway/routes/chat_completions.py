"""POST /v1/chat/completions route handler (ADR-0006, F-004).

This is the innermost handler (pipeline step 8). By the time a request reaches
here, steps 2–7 have already run:
  2. Body-size / edge guard (RequestValidationMiddleware)
  3. Header presence / format gate (TenantContextMiddleware)
  4. Auth (AuthMiddleware — virtual_key_row on request.state)
  5. ID cross-check + tenant context (resolve_tenant_context, called here)
  6. Rate limit (check_rate_limit, called here after context is resolved)
  7. Request-body validation (Pydantic model on the route)

AUDIT COVERAGE (honest scope — HIGH-3 / LOW-4):
  - NON-STREAM: emit_terminal_record() is called in all non-streaming paths —
    success, upstream failure, validation failure, etc. (ADR-0006 Decision 3).
    If the audit append fails, the response is forced to 500 internal_error.
    After successful emit we set request.state.audit_emitted = True so the
    outermost TerminalAuditMiddleware skips double-emission.
  - STREAM: 200 headers are committed before the generator runs. Audit is
    emitted in the generator's finally-block. If that emit fails, it is logged
    at ERROR level out-of-band — the committed 200 cannot be changed to 500.
    This is an inherent SSE constraint. See ADR-0006 Decision 3 amendment.

MED-3: Uses request.state.request_id (set by TerminalAuditMiddleware, the
outermost layer) instead of generating a new ID here. All middleware layers
and the route handler share the ONE canonical request_id.

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


def _make_request_id() -> str:
    """Generate a request_id conforming to events.schema.json pattern ^[A-Za-z0-9._-]{1,64}$.

    Used only as a fallback if request.state.request_id was not set by the
    outermost middleware (e.g. in certain test configurations). Prefer
    request.state.request_id in all normal paths (MED-3).
    """
    return "req-" + uuid.uuid4().hex[:32]


@router.post("/v1/chat/completions", response_model=None)
async def create_chat_completion(request: Request) -> JSONResponse | StreamingResponse:
    """POST /v1/chat/completions — full pipeline handler (non-stream + stream).

    Pipeline steps executed here (steps 5–8):
      5. ID cross-check + tenant context resolution
      6. Rate limit (post-auth, keyed on resolved key_id + tenant_id)
      7. Body validation (Pydantic, closed schema)
      8. Upstream proxy (typed re-serialization, no raw passthrough)

    Audit emitted on every terminal outcome for non-stream requests (step 1 /
    Decision 3). Stream audit is emitted in the generator's finally-block;
    see module docstring for the honest scope of the audit guarantee.
    """
    settings = get_settings()
    start_time = time.monotonic()

    # MED-3: use the ONE canonical request_id set by TerminalAuditMiddleware.
    request_id: str = getattr(request.state, "request_id", None) or _make_request_id()

    # These will be populated progressively; used by the finally-block emit.
    tenant_context: TenantContext | None = None
    model: str = ""
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
            raise GatewayError("invalid_request") from None

        try:
            validated = CreateChatCompletionRequest(**body_dict)
        except (ValidationError, TypeError):
            raise GatewayError("invalid_request") from None

        model = validated.model
        # Store on state so TerminalAuditMiddleware can include it if needed.
        request.state.audit_model = model

        # Enforce MAX_TOKENS_PER_REQUEST cap (threat #4, ADR-0006 step 7).
        if (
            validated.max_tokens is not None
            and validated.max_tokens > settings.max_tokens_per_request
        ):
            raise GatewayError("invalid_request")

        # --- Step 8: Upstream proxy ---
        upstream_api_key: str | None = None  # Phase 0: no upstream key vaulting yet

        if validated.stream:
            # Streaming path (ADR-0006 Decision 7).
            # Note: stream_slot() now only DECREMENTS (MED-1 fix: check_rate_limit
            # already incremented the counter atomically at admission).
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
            # Signal TerminalAuditMiddleware to skip double-emission.
            request.state.audit_emitted = True

            headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
            return JSONResponse(
                content=completion.model_dump(),
                status_code=200,
                headers=headers,
            )

    except GatewayError as _orig_exc:
        # Audit on every non-stream rejection (ADR-0006 audit coverage).
        # Keep a mutable reference so inner handlers can upgrade to internal_error.
        active_exc: GatewayError = _orig_exc
        try:
            await emit_terminal_record(
                request_id=request_id,
                tenant_context=tenant_context,
                model=model,
                tokens_in=0,
                tokens_out=0,
                start_time=start_time,
            )
            # Signal TerminalAuditMiddleware to skip double-emission.
            request.state.audit_emitted = True
        except GatewayError:
            # Audit-emit itself failed → already GatewayError("internal_error").
            # Surface the audit-failure 500 (overrides the original error code).
            active_exc = GatewayError("internal_error")
            request.state.audit_emitted = True
        except Exception:
            active_exc = GatewayError("internal_error")
            request.state.audit_emitted = True

        resp = _error_response(
            active_exc.error_code, request_id, retry_after=active_exc.retry_after
        )
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

    The concurrent-stream slot was already reserved (incremented) atomically
    by check_rate_limit() under the lock (MED-1 fix). stream_slot() here only
    DECREMENTS on exit — guaranteed on close/complete/error/disconnect.

    Partial-stream audit is emitted in the generator's finally block.

    HIGH-3 / honest scope: audit failure in the finally-block logs at ERROR
    level out-of-band. The committed 200 response cannot be retroactively
    changed to 500 once streaming headers are sent. This is an inherent SSE
    constraint documented in ADR-0006 Decision 3 (amended).
    """
    # Token counters for partial-stream audit.
    token_state: dict = {"tokens_in": 0, "tokens_out": 0}

    async def _generate():
        """Async generator that wraps the upstream stream with audit + slot management."""
        # MED-1: stream_slot() only DECREMENTS now. Counter was already incremented
        # by check_rate_limit() at admission time.
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
                # Runs on complete, error, timeout, and client disconnect.
                # HIGH-3 honest scope: if this emit fails after 200 headers are
                # sent, we CANNOT force 500. Log at ERROR level as the out-of-band
                # signal. Operators must monitor this log event.
                try:
                    # Estimate tokens_in from messages (word count approximation).
                    prompt_words = sum(len(m.content.split()) for m in validated.messages)
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
                    # HIGH-3: audit failure in streaming path — cannot force 500
                    # (200 headers already sent). Log at ERROR level as the
                    # documented out-of-band alert. MUST NOT be swallowed silently.
                    log.error(
                        "stream_audit_failed",
                        request_id=request_id,
                        # Never log token counts or content — PII risk.
                    )

    headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
    return StreamingResponse(
        _generate(),
        status_code=200,
        media_type="text/event-stream",
        headers=headers,
    )


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
