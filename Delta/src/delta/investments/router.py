"""Investment allocation HTTP surface: ``/v1/admin/investments/*`` (D-023).

Same posture as D-021's own ``personal_finance`` router: ``require_admin`` gates
every route — an internal operator/testing surface until the real B2C onboarding
shell (still unbuilt anywhere in this ecosystem) exists to front it with genuine
end-user auth. Every route resolves a tenant-scoped session via
``get_tenant_session(tenant_id)``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import PersonalAccountId, TenantId
from ..money import DEFAULT_CURRENCY
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    AllocationRecommendationQuery,
    AllocationRecommendationView,
    HoldingRecordRequest,
    HoldingView,
    RiskProfile,
)
from .service import AccountNotFoundError, NotAnInvestmentAccountError

router = APIRouter(prefix="/v1/admin/investments", dependencies=[Depends(require_admin)])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(status_code=422, detail=detail)


# ----------------------------------------------------------------------- holdings


@router.post("/holdings", status_code=201, response_model=HoldingView)
async def post_holding(req: HoldingRecordRequest) -> HoldingView:
    try:
        async with get_tenant_session(req.tenant_id) as session:
            return await service.record_holding(session, req, now=_now())
    except AccountNotFoundError as exc:
        raise _not_found("account_not_found") from exc
    except NotAnInvestmentAccountError as exc:
        raise _unprocessable("account_is_not_investment_type") from exc


@router.get("/holdings", response_model=list[HoldingView])
async def get_holdings(
    tenant_id: TenantId,
    account_id: PersonalAccountId | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[HoldingView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_holding_views(session, account_id=account_id, limit=limit)


# ----------------------------------------------------------- allocation recommendation


@router.get("/allocation-recommendation", response_model=AllocationRecommendationView)
async def get_allocation_recommendation(
    tenant_id: TenantId, risk_profile: RiskProfile, start: datetime, end: datetime
) -> AllocationRecommendationView:
    try:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile=risk_profile, start=start, end=end
        )
    except ValidationError as exc:
        raise _unprocessable(str(exc)) from exc
    async with get_tenant_session(tenant_id) as session:
        return await service.get_allocation_recommendation(
            session, query, now=_now(), currency=DEFAULT_CURRENCY
        )
