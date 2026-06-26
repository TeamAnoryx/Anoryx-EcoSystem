"""Orchestrator FastAPI application factory (O-003, ADR-0003).

Mirrors the Anoryx-Sentinel gateway create_app() convention: a factory that resolves
settings fail-loud at construction, registers routers, and installs a fail-safe
exception handler that BLOCKs (5xx) on any unhandled error — an ingest that could not be
durably recorded must never return a 202.

SCOPE: this app exposes ONLY the ingest seam (POST /v1/ingest/events) plus a health
probe. The GET query/bus read seams (/v1/events, /v1/bus/dlq, /v1/bus/schema-versions)
are O-006. The distribution seams are O-004. mTLS termination is O-008.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from orchestrator.config import get_ingest_settings
from orchestrator.ingest.router import router as ingest_router


def create_app() -> FastAPI:
    """Create and return the configured Orchestrator FastAPI application."""
    # Fail-loud at construction if the HMAC secret is absent (ingest cannot verify).
    ingest_settings = get_ingest_settings()

    app = FastAPI(
        title="Anoryx Orchestrator",
        version="0.1.0",
        description="Event ingest pipeline (O-003). Ingest seam only; query/bus read "
        "seams are O-006.",
        docs_url=None,
        redoc_url=None,
    )
    app.state.ingest_settings = ingest_settings

    @app.exception_handler(Exception)
    async def _fail_safe_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all → fail-safe BLOCK (5xx). Never silently passes; never leaks detail.

        A DB-connectivity error or any unhandled error during the pipeline lands here:
        the event was NOT durably recorded, so we return 503 (not 202). The at-least-once
        emitter retries. exc args are never logged/echoed (may carry sensitive data).
        """
        request_id = request.headers.get("X-Request-Id", "req-orch-unhandled")
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "ingest_unavailable",
                    "message": "ingest could not durably record the event",
                    "request_id": request_id,
                }
            },
            headers={"X-Request-Id": request_id},
        )

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(ingest_router)
    return app
