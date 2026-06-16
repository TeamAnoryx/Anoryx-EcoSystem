"""Operational health endpoints (ADR-0006 Decision 2).

GET /health — liveness probe. No auth, no DB. Returns 200 while the process is up.
GET /ready  — readiness probe. Checks DB connectivity via a non-tenant SELECT 1.
              Returns 200 on success, 503 on failure.
              Uses get_privileged_session() for a lightweight connectivity check
              (no tenant GUC set, no RLS interaction).

These are NOT contract API endpoints (/v1 surface). They are out-of-contract
operational endpoints for Kubernetes liveness/readiness probes and load-balancer
health checks. They carry no tenant data, require none of the four ID headers,
and emit no events (ADR-0006 Decision 2, reconciliation with "never invent endpoints").
They are NOT added to contracts/openapi.yaml.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from persistence.database import get_privileged_session

log = structlog.get_logger(__name__)

router = APIRouter(tags=["operational"])


@router.get("/health")
async def liveness() -> JSONResponse:
    """Liveness probe. Returns 200 while the process is up. No auth, no DB."""
    return JSONResponse({"status": "ok"})


@router.get("/ready")
async def readiness() -> JSONResponse:
    """Readiness probe. Returns 200 if DB is reachable, 503 otherwise.

    Uses a lightweight non-tenant SELECT 1 on the privileged session.
    Does NOT set any tenant GUC. Body is a minimal operational object —
    NOT the Error envelope (that is contract surface for /v1 only).
    """
    try:
        async with get_privileged_session() as session:
            async with session.begin():
                await session.execute(text("SELECT 1"))
        return JSONResponse({"status": "ready"})
    except Exception:
        log.exception("readiness_check_failed")
        return JSONResponse({"status": "unavailable"}, status_code=503)
