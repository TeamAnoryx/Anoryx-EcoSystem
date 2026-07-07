"""Delta allocation-admin app factory (D-007) — the budget-allocation admin API.

Exposes ``/v1/admin/*`` (allocations, decisions, history) plus a ``/health`` probe.
Settings (the break-glass bearer token) are resolved fail-loud at construction,
mirroring ``delta.ingest.app.create_app``. No public OpenAPI schema — this is an
internal operator surface, not a versioned external contract.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import load_settings
from .router import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Delta Allocation Admin",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # Fail-loud: no admin app without the break-glass bearer token (fail-closed auth).
    app.state.allocation_admin_settings = load_settings()

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(Exception)
    async def _failsafe(_request: Request, _exc: Exception) -> JSONResponse:
        # Never leak internals to the operator UI; log server-side (structlog/uvicorn
        # captures it), return a generic 500.
        return JSONResponse(status_code=500, content={"status": "error"})

    app.include_router(router)
    return app
