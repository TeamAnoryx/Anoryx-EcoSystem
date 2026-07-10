"""Executive financial dashboard HTTP surface: ``GET /v1/admin/executive/summary``
(D-020). ``require_admin`` only — mirrors every admin surface except D-017's
dashboards retrofit (this task does not additionally retrofit RBAC; see
docs/adr/0020-delta-executive-dashboard.md §3).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import TenantId
from ..persistence.database import get_tenant_session
from .schemas import ExecutiveSummaryQuery, ExecutiveSummaryView
from .service import get_executive_summary

router = APIRouter(prefix="/v1/admin/executive", dependencies=[Depends(require_admin)])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _query_error(exc: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/summary", response_model=ExecutiveSummaryView)
async def summary(tenant_id: TenantId, start: datetime, end: datetime) -> ExecutiveSummaryView:
    try:
        query = ExecutiveSummaryQuery(tenant_id=tenant_id, start=start, end=end)
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_executive_summary(session, query, now=_now())
