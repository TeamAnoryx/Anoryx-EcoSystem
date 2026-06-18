"""Gateway application factory (F-004, ADR-0006).

create_app() wires the middleware pipeline in the EXACT ADR-0006 order.
Starlette adds middleware in LIFO order (last-added = outermost). We add
middlewares in innermost-first order so the last-added is outermost.

Final outermost-to-innermost execution order:

  [outermost]  TerminalAuditMiddleware   — pure-ASGI; generates ONE canonical
                                           request_id; emits audit on EVERY
                                           terminal outcome including direct
                                           JSONResponses from inner middlewares.
                                           Added LAST → outermost.
  [2nd]        CORSMiddleware            — must be outside security middlewares
                                           so OPTIONS preflight resolves before
                                           TenantContext / Auth gate it → 400.
                                           Added 2nd-to-last.
  [3rd]        RequestValidationMiddleware  — body-size / edge guard (step 2)
  [4th]        TenantContextMiddleware      — header-format gate (step 3)
  [innermost]  AuthMiddleware               — Bearer key resolution (step 4)
                                             Added FIRST → innermost.

Steps 5–8 (ID cross-check, rate limit, body validation, upstream proxy) run
inside the route handler.

NOTE: The TerminalAuditMiddleware is a pure-ASGI class (not BaseHTTPMiddleware),
added via app.add_middleware(). This lets it wrap the send callable and observe
the final HTTP status code of EVERY response — including JSONResponses returned
directly by inner BaseHTTPMiddleware layers (which bypass the dispatch() method
of outer BaseHTTPMiddleware wrappers). This is the architectural fix for
audit-bypass on pre-route rejections (HIGH-1).

CORSMiddleware is added AFTER RequestValidation/TenantContext/Auth (so it is
outer) and BEFORE TerminalAuditMiddleware (so audit still observes CORS
responses). This fixes the LIFO ordering bug that placed CORS innermost, causing
OPTIONS preflight to hit TenantContext → 400 (HIGH-2).

Lifespan: initializes the shared httpx.AsyncClient (upstream proxy) and tears
it down on shutdown.

LOW-2: structlog / stdout is configured to use UTF-8 with errors='replace' so
log emission never raises UnicodeEncodeError into the request path on Windows
cp1252 consoles.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

import gateway.redis_client as redis_client
from gateway.config import get_settings
from gateway.exceptions import ERROR_TABLE, GatewayError
from gateway.logging import configure_logging
from gateway.middleware.auth import AuthMiddleware
from gateway.middleware.request_validation import RequestValidationMiddleware
from gateway.middleware.tenant_context import TenantContextMiddleware
from gateway.middleware.terminal_audit_wrapper import TerminalAuditMiddleware
from gateway.models import ErrorResponse
from gateway.observability import metrics
from gateway.observability.tracing import init_tracing
from gateway.router.registry import ProviderRegistry
from gateway.routes.chat_completions import router as chat_router
from gateway.routes.health import router as health_router
from gateway.upstream.openai_proxy import close_http_client, init_http_client

# ---------------------------------------------------------------------------
# LOW-2: Configure stdout to UTF-8 with errors='replace' so structlog never
# raises UnicodeEncodeError on cp1252 consoles (Windows). Must run before any
# log emission so the reconfigured stream is used from the first log call.
# ---------------------------------------------------------------------------
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass  # Non-reconfigurable stdout (e.g. pytest capture) — skip silently.

log = structlog.get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App lifespan: initialize + teardown shared resources."""
    settings = get_settings()
    log.info("gateway_startup")
    await init_http_client(
        base_url=settings.upstream_base_url,
        request_timeout=settings.request_timeout_seconds,
        stream_timeout=settings.stream_timeout_seconds,
    )
    # F-006: build the per-provider registry (OpenAI reuses the global client;
    # Anthropic gets a dedicated httpx client; Bedrock is lazy aioboto3). A
    # provider with no configured credential is fail-closed unavailable (§3).
    registry = ProviderRegistry()
    registry.init(settings)
    app.state.provider_registry = registry

    # F-009: initialise Redis connection pool + start health-loop task (ADR-0011 D2).
    # Failure mode γ: if Redis is unreachable at startup the pool init logs a warning
    # and sets _redis_degraded=True — the gateway continues with in-process fallback.
    await redis_client.init(settings)
    app.state.redis_health_task = redis_client._health_task

    # F-009: warn operators when per-tenant metric labels are enabled (ADR-0011 D4 γ).
    # Linear cardinality growth with tenant count harms Prometheus / Grafana.
    if settings.enable_per_tenant_metrics:
        metrics.log_cardinality_warning()

    try:
        yield
    finally:
        # F-009: shut down health loop + close pool before registry/httpx teardown.
        await redis_client.shutdown()
        await registry.teardown()
        await close_http_client()
        log.info("gateway_shutdown")


def create_app() -> FastAPI:
    """Create and return the configured FastAPI application.

    This is the public factory function used by uvicorn and tests.
    Settings are loaded from the environment at call time (fail-loud on missing
    required values — ADR-0006 Decision 9).
    """
    # F-006 threat #1: install the structlog secret-redaction processor before
    # any request is served (drops *_API_KEY / *_SECRET* / AWS_* log keys).
    configure_logging()

    settings = get_settings()

    app = FastAPI(
        title="Anoryx Sentinel Gateway",
        version="1.0.0",
        description="Zero-trust AI gateway — OpenAI-compatible surface (F-004).",
        docs_url=None,  # disable Swagger UI in production
        redoc_url=None,
        lifespan=_lifespan,
    )

    # --- Exception handlers ---
    # These handle GatewayErrors and bare Exceptions that escape the route
    # handler. The TerminalAuditMiddleware (outermost) will still see the final
    # status code via its send-wrapper and emit the audit record.

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        """Handle GatewayError raised outside the route handler (e.g. in middleware)."""
        _fallback = "req-" + __import__("uuid").uuid4().hex[:32]
        request_id = getattr(request.state, "request_id", None) or _fallback
        message, status = ERROR_TABLE[exc.error_code]
        body = ErrorResponse(
            error_code=exc.error_code,  # type: ignore[arg-type]
            message=message,
            request_id=request_id,
        )
        headers: dict[str, str] = {"X-Request-Id": request_id}
        if exc.retry_after is not None:
            headers["Retry-After"] = str(exc.retry_after)
        log.info(
            "gateway_error",
            error_code=exc.error_code,
            status=status,
            request_id=request_id,
            path=request.url.path,
        )
        return JSONResponse(content=body.model_dump(), status_code=status, headers=headers)

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all for unhandled exceptions — fail-safe BLOCK (never silently pass)."""
        _fallback = "req-" + __import__("uuid").uuid4().hex[:32]
        request_id = getattr(request.state, "request_id", None) or _fallback
        # LOW-2: log.exception uses the reconfigured UTF-8 stdout.
        log.exception(
            "unhandled_exception",
            request_id=request_id,
            path=request.url.path,
            # Never log exc args — may contain PII or sensitive data.
        )
        message, status = ERROR_TABLE["internal_error"]
        body = ErrorResponse(
            error_code="internal_error",
            message=message,
            request_id=request_id,
        )
        return JSONResponse(
            content=body.model_dump(),
            status_code=status,
            headers={"X-Request-Id": request_id},
        )

    # --- Middleware pipeline (Starlette LIFO: last-added = outermost) ---
    #
    # Add INNERMOST first, OUTERMOST last.
    #
    # Step 4 (innermost): AuthMiddleware — closest to the route handler.
    app.add_middleware(AuthMiddleware)
    # Step 3: TenantContextMiddleware — header-format gate.
    app.add_middleware(TenantContextMiddleware)
    # Step 2: RequestValidationMiddleware — body-size / edge guard.
    app.add_middleware(RequestValidationMiddleware)
    # HIGH-2 FIX: CORSMiddleware is added AFTER the three security middlewares
    # so it is OUTER to them. OPTIONS preflight now resolves at the CORS layer
    # before TenantContextMiddleware or AuthMiddleware can produce 400/401.
    # CORSMiddleware is INNER to TerminalAuditMiddleware so audit still sees
    # CORS-handled responses.
    allowed_origins = settings.cors_allowed_origins or []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["POST", "GET", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"]
        + [
            "X-Anoryx-Tenant-Id",
            "X-Anoryx-Team-Id",
            "X-Anoryx-Project-Id",
            "X-Anoryx-Agent-Id",
        ],
    )
    # HIGH-1 FIX: TerminalAuditMiddleware is the TRUE outermost layer.
    # Added LAST so it wraps everything including CORS and the security
    # middlewares. Uses pure-ASGI send-wrapping to observe every terminal
    # response regardless of where in the stack it originated.
    app.add_middleware(TerminalAuditMiddleware)

    # --- Routers ---
    app.include_router(health_router)  # /health, /ready (no /v1 prefix)
    app.include_router(chat_router)  # /v1/chat/completions

    # --- F-009: OTel tracing (ADR-0011 §6 Decision D5) ---
    # init_tracing is called AFTER all middleware is added (instrumentor sits
    # OUTSIDE the middleware stack — no order change, R2). No-op when enable_otel
    # is False (R8: disable path is safe). Idempotent — safe to call once here.
    init_tracing(app, settings)

    # --- F-009: /metrics endpoint (ADR-0011 D4, R5) ---
    # Unauthenticated, read-only. MUST be network-isolated (firewalled) by ops.
    # R9: never exposes secrets, virtual keys, prompt content, or PII.
    # R5: this is the ONLY new HTTP endpoint F-009 adds.
    metrics_path = settings.metrics_path

    @app.get(metrics_path, include_in_schema=False)
    async def prometheus_metrics() -> Response:
        body, content_type = metrics.render()
        return Response(content=body, media_type=content_type)

    return app
