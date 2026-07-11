"""Personal-finance HTTP surface: ``/v1/admin/personal-finance/*`` (D-021).

A B2C consumer IS one ``tenant_id`` (ADR-0021 Fork 1) — every route resolves a
tenant-scoped session via ``get_tenant_session(tenant_id)``, the same "per-target
session" shape every other Delta admin surface uses. ``require_admin`` (imported
from ``allocation_admin.auth``, not redefined here) gates every route — this is an
internal operator/testing surface until the real B2C onboarding shell (still
unbuilt anywhere in this ecosystem) exists to front it with genuine end-user auth.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import PersonalAccountId, TenantId
from ..money import DEFAULT_CURRENCY, require_aware_utc
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    AccountCreateRequest,
    AccountView,
    BudgetCreateRequest,
    BudgetView,
    FinancialHealthQuery,
    FinancialHealthView,
    TransactionCategory,
    TransactionCreateRequest,
    TransactionView,
)
from .service import AccountNotFoundError

router = APIRouter(prefix="/v1/admin/personal-finance", dependencies=[Depends(require_admin)])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def _query_error(exc: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


# ------------------------------------------------------------------------ accounts


@router.post("/accounts", status_code=201, response_model=AccountView)
async def post_account(req: AccountCreateRequest) -> AccountView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_account(session, req, now=_now())


@router.get("/accounts", response_model=list[AccountView])
async def get_accounts(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[AccountView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_accounts(session, limit=limit)


# -------------------------------------------------------------------- transactions


@router.post("/transactions", status_code=201, response_model=TransactionView)
async def post_transaction(req: TransactionCreateRequest) -> TransactionView:
    try:
        async with get_tenant_session(req.tenant_id) as session:
            return await service.create_transaction(session, req, now=_now())
    except AccountNotFoundError as exc:
        raise _not_found("account_not_found") from exc


@router.get("/transactions", response_model=list[TransactionView])
async def get_transactions(
    tenant_id: TenantId,
    account_id: PersonalAccountId | None = None,
    category: TransactionCategory | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[TransactionView]:
    # Mirror the health route's window validation: a naive datetime compared against
    # a timestamptz column is either misread or 500s (security audit finding) — 422
    # at the boundary instead.
    try:
        if start is not None:
            require_aware_utc(start, "start")
        if end is not None:
            require_aware_utc(end, "end")
        if start is not None and end is not None and end <= start:
            raise ValueError("end must be after start")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    async with get_tenant_session(tenant_id) as session:
        return await service.list_transactions(
            session, account_id=account_id, category=category, start=start, end=end, limit=limit
        )


# ------------------------------------------------------------------------- budgets


@router.post("/budgets", status_code=201, response_model=BudgetView)
async def post_budget(req: BudgetCreateRequest) -> BudgetView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_budget(session, req, now=_now())


@router.get("/budgets", response_model=list[BudgetView])
async def get_budgets(tenant_id: TenantId) -> list[BudgetView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_budgets(session)


# ------------------------------------------------------------------------- health


@router.get("/health-score", response_model=FinancialHealthView)
async def get_financial_health(
    tenant_id: TenantId, start: datetime, end: datetime
) -> FinancialHealthView:
    try:
        query = FinancialHealthQuery(tenant_id=tenant_id, start=start, end=end)
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await service.get_financial_health(
            session, query, now=_now(), currency=DEFAULT_CURRENCY
        )
