"""Orchestrator FastAPI application factory (O-003, ADR-0003).

Mirrors the Anoryx-Sentinel gateway create_app() convention: a factory that resolves
settings fail-loud at construction, registers routers, and installs a fail-safe
exception handler that BLOCKs (5xx) on any unhandled error — an ingest that could not be
durably recorded must never return a 202.

SCOPE: this app exposes the ingest seam (POST /v1/ingest/events), the policy-distribution
seams (POST + GET /v1/policies/distributions — O-004, ADR-0004), the multi-Sentinel
coordination seams (registry CRUD /v1/registry/sentinels, /v1/registry/health-check, and the
coordinated push /v1/policies/coordinate — O-005, ADR-0005), the tenant-scoped query/bus read
seams (GET /v1/events, /v1/bus/dlq, /v1/bus/schema-versions — O-006, ADR-0006), the
operator-scoped admin API + minimal UI (GET /v1/admin/events/recent,
/v1/admin/distributions/recent, /admin — O-007, ADR-0007), the governed relay for inter-app
AI traffic (POST /v1/relay/dispatch — O-009, ADR-0009), the cross-product identity-event
correlation seam (POST + GET /v1/identity/events, GET /v1/admin/identity/events/recent —
O-010, ADR-0010), the cross-module automation-rules engine (POST/GET/PATCH/DELETE
/v1/automation/rules, GET /v1/automation/executions — O-011, ADR-0011), plus a health
probe. The query/distribution seams derive a per-tenant principal
(require_tenant_principal); a missing/invalid token → a uniform 401. mTLS termination is
O-008.
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from orchestrator.admin.router import router as admin_router
from orchestrator.automation.router import router as automation_router
from orchestrator.config import (
    get_automation_settings,
    get_coordination_settings,
    get_distribution_settings,
    get_identity_settings,
    get_ingest_settings,
)
from orchestrator.coordination.router import router as coordination_router
from orchestrator.distribution.router import router as distribution_router
from orchestrator.identity.router import router as identity_router
from orchestrator.ingest.router import router as ingest_router
from orchestrator.query.router import router as query_router
from orchestrator.relay.router import router as relay_router
from orchestrator.security import PrincipalAuthError


def create_app() -> FastAPI:
    """Create and return the configured Orchestrator FastAPI application."""
    # Fail-loud at construction if the HMAC secret is absent (ingest cannot verify).
    ingest_settings = get_ingest_settings()

    app = FastAPI(
        title="Anoryx Orchestrator",
        version="0.1.0",
        description="Ingest, policy distribution, coordination, and tenant-scoped "
        "query/bus read seams (O-003…O-006).",
        docs_url=None,
        redoc_url=None,
    )
    app.state.ingest_settings = ingest_settings
    # Distribution settings resolve NON-FATALLY (unlike the fail-loud ingest secret): an
    # ingest-only deployment must not be forced to configure the distribution seam. The
    # request boundary enforces token presence fail-closed, not construction.
    app.state.distribution_settings = get_distribution_settings()
    # Coordination (O-005) settings also resolve NON-FATALLY; the registry request boundary
    # enforces the operator token (ORCH_ADMIN_TOKEN) fail-closed, not construction.
    app.state.coordination_settings = get_coordination_settings()
    # Identity-event correlation (O-010) settings resolve NON-FATALLY; the ingest seam's
    # request boundary enforces a matching source token fail-closed, not construction.
    app.state.identity_settings = get_identity_settings()
    # Cross-module automation-rules engine (O-011) settings resolve NON-FATALLY; the
    # master switch DEFAULTS OFF (ORCH_AUTOMATION_ENABLED), so an unconfigured deployment
    # never silently starts auto-triggering distributions.
    app.state.automation_settings = get_automation_settings()

    @app.exception_handler(Exception)
    async def _fail_safe_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all → fail-safe BLOCK (503). Never silently passes; never leaks detail.

        A DB-connectivity error or any unhandled error below a seam's auth boundary lands
        here: the request was NOT durably recorded, so we return 503 (not 202). exc args are
        never logged/echoed (may carry sensitive data). The error code is PATH-AWARE so the
        ingest seam keeps its O-003 contract code (ingest_unavailable) while the distribution
        (and any other) seam returns a neutral code rather than mislabelling the failure as an
        ingest failure. Still 503, still no detail leak, still a server-generated request_id.
        """
        # Server-generated id — never reflect an unvalidated client X-Request-Id (audit L-3).
        request_id = "req-orch-" + uuid.uuid4().hex[:24]
        if request.url.path.startswith("/v1/ingest"):
            code = "ingest_unavailable"
            message = "ingest could not durably record the event"
        else:
            code = "service_unavailable"
            message = "the orchestrator could not durably complete the request"
        return JSONResponse(
            status_code=503,
            content={"error": {"code": code, "message": message, "request_id": request_id}},
            headers={"X-Request-Id": request_id},
        )

    @app.exception_handler(PrincipalAuthError)
    async def _principal_auth_handler(request: Request, exc: PrincipalAuthError) -> JSONResponse:
        """Render a per-tenant auth failure as a UNIFORM 401 (O-006, ADR-0006).

        A specific handler for PrincipalAuthError so an auth miss is a clean 401, not the
        catch-all 503. Absent/malformed header, unknown token, and disabled token are
        indistinguishable here (no enumeration oracle); the message is generic and PII-free, the
        request_id is server-generated (never a reflected client X-Request-Id).
        """
        request_id = "req-orch-" + uuid.uuid4().hex[:24]
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "unauthorized",
                    "message": "tenant authentication required",
                    "request_id": request_id,
                }
            },
            headers={"X-Request-Id": request_id},
        )

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(ingest_router)
    app.include_router(distribution_router)
    app.include_router(coordination_router)
    app.include_router(query_router)
    app.include_router(admin_router)
    app.include_router(relay_router)
    app.include_router(identity_router)
    app.include_router(automation_router)
    return app
