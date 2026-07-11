"""Asset-allocation HTTP surface: ``/v1/admin/asset-allocation/*`` (D-023).

Same operator/testing surface shape as `personal_finance.router` — `require_admin`
gates every route, resolves a tenant-scoped session via
`get_tenant_session(tenant_id)`. `GET /risk-tiers` is the one exception: it returns the
fixed, disclosed allocation table with no DB access and no tenant scoping at all (it is
not tenant data).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import PersonalAccountId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import (
    DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT,
)
from .schemas import (
    AllocationRecommendationRequest,
    AllocationRecommendationView,
    RiskTierAllocationView,
)
from .service import AccountNotFoundError, AccountNotInvestmentTypeError

router = APIRouter(prefix="/v1/admin/asset-allocation", dependencies=[Depends(require_admin)])


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/risk-tiers", response_model=list[RiskTierAllocationView])
async def get_risk_tiers() -> list[RiskTierAllocationView]:
    return service.list_risk_tiers()


@router.post("/recommendations", status_code=201, response_model=AllocationRecommendationView)
async def post_recommendation(
    req: AllocationRecommendationRequest,
) -> AllocationRecommendationView:
    try:
        async with get_tenant_session(req.tenant_id) as session:
            return await service.create_recommendation(session, req, now=_now())
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=404, detail="account_not_found") from exc
    except AccountNotInvestmentTypeError as exc:
        raise HTTPException(status_code=422, detail="account_not_investment_type") from exc


@router.get("/recommendations", response_model=list[AllocationRecommendationView])
async def get_recommendations(
    tenant_id: TenantId,
    account_id: PersonalAccountId | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[AllocationRecommendationView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_recommendation_views(session, account_id=account_id, limit=limit)
