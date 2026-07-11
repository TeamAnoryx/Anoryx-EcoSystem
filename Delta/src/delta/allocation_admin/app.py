"""Delta admin app factory — the operator admin API (D-007 allocations, D-008
dashboards, D-011 forecasting, D-012 chargeback/anomaly, D-013 unified CRM, D-014 ERP,
D-015 project management, D-016 team capacity, D-017 RBAC, D-018 invoicing, D-019
ERP/procurement/cloud-cost sync, D-020 executive dashboard, D-022 subscriptions).

Exposes ``/v1/admin/*`` (allocations, decisions, history, dashboards, forecast,
chargeback, crm, erp, pm, capacity, rbac, invoicing, integrations, executive,
subscriptions) plus a ``/health`` probe. One app/port for the whole admin console
(D-008/.../D-022 add routes to the D-007 app rather than standing up a second
process — same operators, same auth, same trust boundary).
Settings (the break-glass bearer token) are resolved fail-loud at construction,
mirroring ``delta.ingest.app.create_app``. No public OpenAPI schema — this is an
internal operator surface, not a versioned external contract.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..capacity.router import router as capacity_router
from ..chargeback.router import router as chargeback_router
from ..crm.router import router as crm_router
from ..dashboards.router import router as dashboards_router
from ..erp.router import router as erp_router
from ..executive.router import router as executive_router
from ..forecasting.router import router as forecasting_router
from ..integrations.router import router as integrations_router
from ..invoicing.router import router as invoicing_router
from ..pm.router import router as pm_router
from ..rbac.router import router as rbac_router
from ..subscriptions.router import router as subscriptions_router
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
    app.include_router(erp_router)
    app.include_router(invoicing_router)
    app.include_router(integrations_router)
    app.include_router(pm_router)
    app.include_router(capacity_router)
    app.include_router(rbac_router)
    app.include_router(executive_router)
    app.include_router(subscriptions_router)
    return app
