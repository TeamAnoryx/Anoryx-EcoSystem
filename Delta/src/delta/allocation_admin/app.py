"""Delta admin app factory — the operator admin API (D-007 allocations, D-008
dashboards, D-011 forecasting, D-012 chargeback/anomaly, D-013 unified CRM).

Exposes ``/v1/admin/*`` (allocations, decisions, history, dashboards, forecast,
chargeback, crm) plus a ``/health`` probe. One app/port for the whole admin console
(D-008/D-011/D-012/D-013 add routes to the D-007 app rather than standing up a second
process — same operators, same auth, same trust boundary). Settings (the break-glass
bearer token) are resolved fail-loud at construction, mirroring
``delta.ingest.app.create_app``. No public OpenAPI schema — this is an internal
operator surface, not a versioned external contract.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..chargeback.router import router as chargeback_router
from ..crm.router import router as crm_router
from ..dashboards.router import router as dashboards_router
from ..forecasting.router import router as forecasting_router
from .config import load_settings
from .router import router as allocations_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Delta Admin",
        version="0.2.0",
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

    app.include_router(allocations_router)
    app.include_router(dashboards_router)
    app.include_router(forecasting_router)
    app.include_router(chargeback_router)
    app.include_router(crm_router)
    return app
