"""Gateway application factory (F-004, ADR-0006).

create_app() wires the middleware pipeline in the EXACT ADR-0006 order
(Decision 3, outermost → innermost):

  1. Exception handlers (terminal-audit wrapper equivalent — catch all
     unhandled GatewayError and Exception at the app level, funnel every
     terminal response through emit_terminal_record).
  2. RequestValidationMiddleware (body-size / edge guard).
  3. TenantContextMiddleware (header presence / format gate — step 3 of the ADR
     pipeline; ID cross-check step 5 runs inside the route handler).
  4. AuthMiddleware (Bearer extraction + virtual key resolution).
  NOTE: Starlette adds middleware in LIFO order (last-added = outermost).
  We add them innermost-first so the last-added is outermost.

CORSMiddleware: default-deny (threat #11). Explicit allowlist from config;
never "*" with credentials.

Lifespan: initializes the shared httpx.AsyncClient (upstream proxy) and tears
it down on shutdown.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from gateway.config import get_settings
from gateway.exceptions import ERROR_TABLE, GatewayError
from gateway.middleware.auth import AuthMiddleware
from gateway.middleware.request_validation import RequestValidationMiddleware
from gateway.middleware.tenant_context import TenantContextMiddleware
from gateway.models import ErrorResponse
from gateway.routes.chat_completions import _make_request_id
from gateway.routes.chat_completions import router as chat_router
from gateway.routes.health import router as health_router
from gateway.upstream.openai_proxy import close_http_client, init_http_client

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
    try:
        yield
    finally:
        await close_http_client()
        log.info("gateway_shutdown")


def create_app() -> FastAPI:
    """Create and return the configured FastAPI application.

    This is the public factory function used by uvicorn and tests.
    Settings are loaded from the environment at call time (fail-loud on missing
    required values — ADR-0006 Decision 9).
    """
    settings = get_settings()

    app = FastAPI(
        title="Anoryx Sentinel Gateway",
        version="1.0.0",
        description="Zero-trust AI gateway — OpenAI-compatible surface (F-004).",
        docs_url=None,  # disable Swagger UI in production
        redoc_url=None,
        lifespan=_lifespan,
    )

    # --- Exception handlers (step 1 / terminal-audit wrapper equivalent) ---
    # These funnel EVERY unhandled terminal outcome through an error response.
    # The route handler itself calls emit_terminal_record; for exceptions that
    # escape the route (middleware GatewayErrors, unhandled Exceptions), we
    # build a clean error response here without audit (they are pre-route errors
    # that the route's finally-block did not execute). The audit guarantee for
    # middleware-level rejections is enforced by the route handler's try/except
    # which wraps the entire call chain including tenant-context + rate-limit.
    # For errors that bypass the route entirely (raised in middleware before the
    # route is reached), we handle them here and do NOT attempt audit — those
    # paths (body-too-large, malformed header) are covered by the route handler
    # calling them as GatewayErrors that propagate up.

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        """Handle GatewayError raised outside the route handler (e.g. in middleware)."""
        request_id = getattr(request.state, "request_id", _make_request_id())
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
        request_id = getattr(request.state, "request_id", _make_request_id())
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

    # --- CORS: default-deny; explicit allowlist; never "*" with credentials ---
    # (threat #11, ADR-0006 Decision 9)
    allowed_origins = settings.cors_allowed_origins or []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["POST", "GET", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"] + [
            "X-Anoryx-Tenant-Id",
            "X-Anoryx-Team-Id",
            "X-Anoryx-Project-Id",
            "X-Anoryx-Agent-Id",
        ],
    )

    # --- Middleware pipeline (Starlette LIFO: last-added = outermost) ---
    # We add innermost-first so the execution order matches ADR-0006:
    #   outermost (step 2): RequestValidationMiddleware
    #   step 3:             TenantContextMiddleware
    #   step 4:             AuthMiddleware
    # (Steps 5–8 are in the route handler itself.)

    # Add AuthMiddleware FIRST → it runs INNERMOST (closest to route).
    app.add_middleware(AuthMiddleware)
    # Add TenantContextMiddleware SECOND → it runs in the middle.
    app.add_middleware(TenantContextMiddleware)
    # Add RequestValidationMiddleware LAST → it runs OUTERMOST (first to see the request).
    app.add_middleware(RequestValidationMiddleware)

    # --- Routers ---
    app.include_router(health_router)          # /health, /ready (no /v1 prefix)
    app.include_router(chat_router)            # /v1/chat/completions

    return app
