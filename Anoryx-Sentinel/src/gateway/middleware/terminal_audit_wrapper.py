"""Outermost terminal-audit ASGI wrapper (HIGH-1 fix, ADR-0006 Decision 3).

This is a pure-ASGI middleware (not BaseHTTPMiddleware) that wraps the ENTIRE
application stack — including CORS, all security middlewares, and the route
handler — so it observes the FINAL status code of EVERY response, including
JSONResponses returned directly by inner middlewares (401, 400, 413, 400 TE+CL)
and 500s from the generic exception handler.

Why pure-ASGI instead of BaseHTTPMiddleware:
  BaseHTTPMiddleware.dispatch() only runs when Starlette calls it. Inner
  middlewares that return a Response object directly (without calling call_next)
  bypass the dispatch call of any outer BaseHTTPMiddleware layers — this is
  precisely the bypass that HIGH-1 proved. A pure-ASGI middleware wraps the
  `send` callable, which is called unconditionally for every response regardless
  of where in the stack the response originated.

Middleware order in create_app() (outermost → innermost, Starlette LIFO):
  [outermost]  TerminalAuditMiddleware   ← THIS file (added LAST)
  [2nd]        CORSMiddleware            ← added 2nd-to-last
  [3rd]        RequestValidationMiddleware
  [4th]        TenantContextMiddleware
  [innermost]  AuthMiddleware            ← added FIRST

Request-id:
  The canonical request_id is generated HERE (outermost) and stored on
  request.state.request_id before any inner layer runs. Inner layers read
  request.state.request_id instead of generating their own (MED-3 fix).
  Pattern: "req-" + 32 hex chars — conforms to events.schema ^[A-Za-z0-9._-]{1,64}$.

Audit on middleware rejections (pre-auth / no TenantContext):
  When an inner middleware rejects before auth resolves (e.g. 401, 400, 413),
  request.state.tenant_context will not be set. build_usage_event() handles
  None tenant_context by substituting safe sentinel IDs (all-zeros UUIDs,
  agent 'gateway-core') per the existing audit.py contract. We pass model=''
  and tokens_in/out=0; latency_ms = elapsed wall time records the attempt.

Audit failure on already-final 4xx/5xx (cannot change the response):
  For non-stream requests the route handler's finally-block already raised
  GatewayError("internal_error") which forces 500 before this wrapper sends
  the response. For responses that were already committed by inner middleware
  (direct JSONResponse from auth / tenant_context / request_validation), this
  wrapper sees the final status AFTER the response bytes are in-flight. If the
  audit append fails at that point we CANNOT change the response code. We log
  at ERROR level (structured, no PII) — this is the documented out-of-band
  signal. The failure is not swallowed silently.

Streaming note (HIGH-3 — honest scope):
  For stream requests (status 200, text/event-stream), 200 headers are sent
  before the generator runs. Audit for the stream body is emitted inside the
  generator's finally-block (chat_completions.py). The outermost wrapper sees
  the 200 start and does NOT emit a second audit row for the stream itself —
  it skips emission when content_type indicates SSE. This avoids double-audit
  and is consistent with ADR-0006 Decision 3 amendment (stream audit is
  best-effort in the generator; only non-stream + pre-route rejections are
  covered by the forced-500 guarantee).

NEVER LOG:
  - DATABASE_URL, APP_DATABASE_URL, SENTINEL_KEY_SECRET
  - virtual API keys (plaintext OR fingerprint)
  - full request bodies (PII risk)
  - raw client-supplied header values
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Awaitable, Callable, MutableMapping

import structlog

from gateway.exceptions import GatewayError
from gateway.middleware.audit import emit_terminal_record

log = structlog.get_logger(__name__)

# Sentinel IDs used when no TenantContext was resolved (pre-auth rejections).
_SENTINEL_TENANT_ID = "00000000-0000-0000-0000-000000000000"
_SENTINEL_AGENT_ID = "gateway-core"

# SSE content-type prefix — used to skip double-audit on stream responses.
_SSE_CONTENT_TYPE = b"text/event-stream"

# Paths exempt from audit emit (operational probes — no tenant data, no usage).
_AUDIT_EXEMPT_PATHS = frozenset({"/health", "/ready"})


def _generate_request_id() -> str:
    """Generate a canonical request_id conforming to events.schema ^[A-Za-z0-9._-]{1,64}$."""
    return "req-" + uuid.uuid4().hex[:32]


class TerminalAuditMiddleware:
    """Pure-ASGI outermost wrapper that provides audit coverage for terminal outcomes.

    Wraps the send callable so it intercepts the http.response.start message
    (which carries the final status code) for every response produced anywhere
    in the stack. On each terminal outcome it calls emit_terminal_record().

    Audit guarantee scope (per ADR-0006 Decision 3 amendment):
      - Non-streaming requests (all 4xx, 5xx, and non-SSE 2xx) receive a
        guaranteed audit record written synchronously before this wrapper returns.
      - Streaming responses (status 200, content-type text/event-stream) are
        intentionally skipped here to avoid double-audit. Stream audit is
        best-effort, emitted inside the generator's finally-block in
        chat_completions.py. If the generator is interrupted before its
        finally-block executes, the audit record may not be written.

    Registered via app.add_middleware() as the LAST add_middleware call so it
    becomes the outermost layer in Starlette's LIFO order.
    """

    def __init__(self, app: Callable) -> None:
        self._app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            # Lifespan, websocket, etc. — pass through unchanged.
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if path in _AUDIT_EXEMPT_PATHS:
            await self._app(scope, receive, send)
            return

        start_time = time.monotonic()

        # Generate the ONE canonical request_id for this request.
        # Store it on the scope so we can attach it to the ASGI state dict.
        # Inner middlewares / route handlers read request.state.request_id.
        request_id = _generate_request_id()

        # Attach to scope["state"] which Starlette surfaces as request.state.
        # Starlette creates scope["state"] in Request.__init__ if absent, but
        # some ASGI layers access scope["state"] before Request is constructed,
        # so we initialise it here if needed.
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["request_id"] = request_id

        # Mutable container: populated when http.response.start is seen.
        response_meta: dict[str, Any] = {
            "status_code": None,
            "is_sse": False,
        }

        async def _auditing_send(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_code: int = message["status"]
                response_meta["status_code"] = status_code

                # Detect SSE responses to skip double-audit (stream audit
                # is handled inside the generator's finally-block).
                headers = dict(message.get("headers", []))
                content_type = headers.get(b"content-type", b"")
                if _SSE_CONTENT_TYPE in content_type:
                    response_meta["is_sse"] = True

            await send(message)

            # Emit AFTER the response.start message has been forwarded so the
            # client's response is not delayed by the audit write. For 4xx/5xx
            # from inner middlewares the status is available immediately here.
            if message["type"] == "http.response.start" and not response_meta["is_sse"]:
                await _emit_audit(
                    request_id=request_id,
                    scope=scope,
                    status_code=response_meta["status_code"],
                    start_time=start_time,
                )

        try:
            await self._app(scope, receive, _auditing_send)
        except Exception:
            # Unhandled exception that escaped the entire inner stack (extremely
            # rare — FastAPI's exception handlers should catch everything). Emit
            # audit with 500, then re-raise so the ASGI server handles it.
            if response_meta["status_code"] is None:
                # No response was started yet — we can emit and let the ASGI
                # server generate a plain 500. Emit best-effort here.
                await _emit_audit(
                    request_id=request_id,
                    scope=scope,
                    status_code=500,
                    start_time=start_time,
                )
            raise


async def _emit_audit(
    *,
    request_id: str,
    scope: MutableMapping[str, Any],
    status_code: int | None,
    start_time: float,
) -> None:
    """Emit the terminal usage event for this request.

    Reads tenant_context from scope["state"] if available (set by the route
    handler after auth + ID cross-check). Falls back to None so
    build_usage_event() substitutes safe sentinel IDs.

    Audit failure on an already-committed response: logs at ERROR level.
    Cannot change the response after it has been forwarded to the client.
    """
    state: dict = scope.get("state", {})
    tenant_context = state.get("tenant_context", None)
    model: str = state.get("audit_model", "") or ""

    # If the route handler already emitted (success or GatewayError path),
    # it sets state["audit_emitted"] = True to prevent double-emission.
    if state.get("audit_emitted", False):
        return

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
        # Audit append itself failed. For pre-route rejections (4xx returned
        # directly by inner middleware) the response has already been forwarded
        # to the client — we cannot force 500 retroactively.
        # Log at ERROR level as the documented out-of-band signal.
        log.error(
            "terminal_audit_emit_failed_post_response",
            request_id=request_id,
            status_code=status_code,
            # Never log tenant data or request content here.
        )
    except Exception:
        log.error(
            "terminal_audit_emit_unexpected_error",
            request_id=request_id,
            status_code=status_code,
        )
