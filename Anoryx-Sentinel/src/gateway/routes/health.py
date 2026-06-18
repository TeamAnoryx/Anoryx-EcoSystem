"""Operational health endpoints (ADR-0006 Decision 2; extended F-010 / ADR-0012 §6).

Five endpoints, two response shapes:

  GET /livez   — k8s liveness. NO dependency I/O (R5). 200 while the process is up.
  GET /readyz  — k8s readiness. Gates on Postgres ONLY (200/503). Redis health is a
                 NON-gating informational field (ADR-0012 §12 / F-009 γ fallback).
  GET /healthz — alias for /readyz (common ops-tooling name).
  GET /health  — PRESERVED ADR-0006 D2 liveness. Exact legacy shape {"status":"ok"}.
  GET /ready   — PRESERVED ADR-0006 D2 readiness. Exact legacy shape
                 {"status":"ready"} / 503 {"status":"unavailable"}.

Why /readyz gates on Postgres only (ADR-0012 §12, the dispatch-R6 correction):
  Postgres is a HARD dependency (audit log, RBAC, policy — no fallback). Redis is
  NON-fatal by design: on a Redis outage F-009 (ADR-0011 §3) falls back to in-process
  rate limiting and the gateway KEEPS SERVING. Gating readiness on Redis would make
  Kubernetes pull every pod from the Service on a Redis blip — converting a graceful
  degradation into a self-inflicted outage. So /readyz reports Redis status but never
  fails on it.

Redis status is read from redis_client.is_degraded() — the in-process flag the
F-009 sentinel_redis_health gauge mirrors. This opens NO fresh Redis connection
(vector 3b: no probe storms), staying consistent with what the rate limiter sees.

These are out-of-contract operational endpoints (NOT in contracts/openapi.yaml).
They carry no tenant data, require none of the four ID headers, and emit no events.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

import gateway.redis_client as redis_client
from gateway import __version__
from persistence.database import get_privileged_session

log = structlog.get_logger(__name__)

router = APIRouter(tags=["operational"])

# HTTP 503 — Service Unavailable. Used when a hard dependency (Postgres) is down.
_STATUS_SERVICE_UNAVAILABLE = 503


def _redis_status() -> str:
    """Return Redis health WITHOUT opening a connection (vector 3b).

    Reads the F-009 in-process degraded flag (mirrored by the sentinel_redis_health
    gauge). Never probes Redis — the background health loop owns probing.
    """
    try:
        return "degraded" if redis_client.is_degraded() else "healthy"
    except Exception:
        # Defensive: never let a status read break a probe. Unknown ⇒ degraded
        # (conservative for the informational field; does NOT affect gating).
        return "degraded"


def _liveness_body() -> dict[str, str]:
    """Build the rich /livez body. Performs NO dependency I/O (R5).

    Postgres is reported as "not_checked": liveness MUST NOT touch the DB (a
    liveness probe that fails on a DB outage causes k8s to kill+restart pods,
    masking the real fault and cascading outages — R5). Redis is read from the
    in-process flag (no I/O). Version is the app release version only (vector 4).
    """
    return {
        "status": "alive",
        "postgres": "not_checked",
        "redis": _redis_status(),
        "version": __version__,
    }


async def _check_postgres() -> bool:
    """Return True if Postgres is reachable via a non-tenant SELECT 1.

    Uses the privileged session (no tenant GUC, no RLS interaction). Any failure
    is logged and reported as unreachable (False) — never raised into the probe.
    """
    try:
        async with get_privileged_session() as session:
            async with session.begin():
                await session.execute(text("SELECT 1"))
        return True
    except Exception:
        log.exception("readiness_postgres_check_failed")
        return False


async def _readiness() -> tuple[bool, dict[str, str]]:
    """Evaluate readiness. Returns (postgres_ok, rich_body).

    Gating is on Postgres ONLY. Redis status is informational (non-gating).
    """
    postgres_ok = await _check_postgres()
    body = {
        "status": "ready" if postgres_ok else "not_ready",
        "postgres": "healthy" if postgres_ok else "unhealthy",
        "redis": _redis_status(),
        "version": __version__,
    }
    return postgres_ok, body


# --------------------------------------------------------------------------- #
# k8s-idiomatic endpoints (F-010). Out of OpenAPI (include_in_schema=False).   #
# --------------------------------------------------------------------------- #


@router.get("/livez", include_in_schema=False)
async def livez() -> JSONResponse:
    """Kubernetes liveness probe. Always 200 while the process is up. No DB/Redis I/O."""
    return JSONResponse(_liveness_body())


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Kubernetes readiness probe. 200 iff Postgres reachable; 503 otherwise.

    Redis status is reported in the body but NEVER gates (ADR-0012 §12).
    """
    postgres_ok, body = await _readiness()
    status_code = 200 if postgres_ok else _STATUS_SERVICE_UNAVAILABLE
    return JSONResponse(body, status_code=status_code)


@router.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Alias for /readyz (ops tooling commonly probes /healthz)."""
    postgres_ok, body = await _readiness()
    status_code = 200 if postgres_ok else _STATUS_SERVICE_UNAVAILABLE
    return JSONResponse(body, status_code=status_code)


# --------------------------------------------------------------------------- #
# PRESERVED ADR-0006 Decision 2 endpoints. Exact legacy shapes (back-compat).  #
# Behavior is byte-identical to the pre-F-010 implementation.                  #
# --------------------------------------------------------------------------- #


@router.get("/health")
async def liveness() -> JSONResponse:
    """Liveness probe (ADR-0006 D2). Returns 200 while the process is up. No auth, no DB."""
    return JSONResponse({"status": "ok"})


@router.get("/ready")
async def readiness() -> JSONResponse:
    """Readiness probe (ADR-0006 D2). 200 if DB reachable, 503 otherwise.

    Lightweight non-tenant SELECT 1 on the privileged session. Body is the
    minimal legacy operational object (NOT the rich F-010 shape) to preserve the
    exact ADR-0006 D2 contract.
    """
    postgres_ok = await _check_postgres()
    if postgres_ok:
        return JSONResponse({"status": "ready"})
    return JSONResponse({"status": "unavailable"}, status_code=_STATUS_SERVICE_UNAVAILABLE)
