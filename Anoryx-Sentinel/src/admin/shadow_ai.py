"""Admin shadow-AI candidates read route (F-018, ADR-0021 §8).

GET /admin/tenants/{tenant_id}/shadow-ai/candidates — operator reads a TARGET
tenant's shadow-AI review candidates. Mirrors the audit-log read route
(`admin/audit_log.py`): the cross-tenant DATA read is attributed via a SEPARATE
privileged `admin_audit_accessed` append (D8), then `shadow_ai.service` runs the
analysis on the TARGET tenant session (RLS — vector 10) and returns candidates
plus the non-removable honesty disclaimer (R1).

The response NEVER labels a candidate a verdict (R3): every item carries
`label="candidate"` and a confidence band; attribution is team + project only
(the seam carries no offending-agent id — ADR-0021 §1.1).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from admin.audit import emit_admin_event
from admin.scope import enforce_admin_scope
from admin.util import actor_id, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session
from shadow_ai.service import ShadowAiServiceError, get_candidates

shadow_ai_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


class AdminShadowAiCandidate(BaseModel):
    """One review candidate (NOT a verdict). Attribution is team + project."""

    team_id: str
    project_id: str
    endpoint: str
    provider: str
    call_count: int
    first_seen: str
    last_seen: str
    confidence_band: Literal["low", "medium", "high"]
    fired_signals: list[str]
    label: Literal["candidate"] = "candidate"


class AdminShadowAiCandidateList(BaseModel):
    """Candidates plus the always-present honesty boundary disclaimer (R1)."""

    candidates: list[AdminShadowAiCandidate]
    disclaimer: str = Field(
        description="Through-Sentinel-only scope; candidates are not verdicts (ADR-0021 §4)."
    )


@shadow_ai_router.get(
    "/tenants/{tenant_id}/shadow-ai/candidates",
    response_model=AdminShadowAiCandidateList,
)
async def read_shadow_ai_candidates(
    tenant_id: str,
    request: Request,
) -> AdminShadowAiCandidateList:
    """Operator read of a target tenant's shadow-AI candidates (audited)."""
    rid = request_id(request)
    aid = actor_id(request)

    # R1/D8: attribute the cross-tenant data read via a SEPARATE privileged append,
    # exactly like the audit-log read route — distinct from the analysis below.
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_audit_accessed",
                target_tenant_id=tenant_id,
                request_id=rid,
                actor_id=aid,
            )

    try:
        report = await get_candidates(tenant_id, request_id=rid)
    except ShadowAiServiceError as exc:
        # Fail-closed: surface a clean 500, never a misleading empty list.
        raise HTTPException(
            status_code=500, detail="shadow-AI candidate analysis unavailable"
        ) from exc

    return AdminShadowAiCandidateList(
        candidates=[
            AdminShadowAiCandidate(
                team_id=c.team_id,
                project_id=c.project_id,
                endpoint=c.endpoint,
                provider=c.provider,
                call_count=c.call_count,
                first_seen=c.first_seen,
                last_seen=c.last_seen,
                confidence_band=c.confidence_band,
                fired_signals=list(c.fired_signals),
            )
            for c in report.candidates
        ],
        disclaimer=report.disclaimer,
    )
