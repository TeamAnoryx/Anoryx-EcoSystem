"""Delta inbound ingest app factory (D-004) — the first Delta runtime HTTP surface.

Exposes ONLY the consume seam ``POST /v1/ingest/usage`` plus a ``/health`` probe.
Settings (the shared HMAC secret) are resolved fail-loud at construction. A catch-all
handler returns 503 (fail-safe / retryable) for any UNHANDLED error so an unexpected
fault is retried by the dispatcher rather than crashing the worker; the router itself
handles validation and connectivity failures explicitly, so the catch-all only sees
genuine surprises.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import load_settings
from .router import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Delta Ingest",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # Fail-loud: no app without the consume-seam secret (fail-closed auth).
    app.state.ingest_settings = load_settings()

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(Exception)
    async def _failsafe(_request: Request, _exc: Exception) -> JSONResponse:
        # Never leak internals; 503 is retryable so no event is lost to a surprise fault.
        return JSONResponse(status_code=503, content={"status": "retry"})

    app.include_router(router)
    return app
