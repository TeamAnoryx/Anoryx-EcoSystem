"""D-007 non-stubbed service-layer DB suite: propose -> approve/reject -> history.

Exercises the REAL path: delta.persistence.database.get_tenant_session (RLS-enforced
delta_app role) end to end, including materializing budget_definitions rows on
approval via the unchanged D-005 create_budget seam (banked rule #2: prove the real
allow AND the real deny on the real path, not a stub).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from delta.allocation_admin.schemas import (
    AllocationCreateRequest,
    AllocationTargetIn,
    ApprovalDecisionRequest,
)
from delta.allocation_admin.service import (
    AllocationAlreadyDecidedError,
    AllocationNotFoundError,
    AllocationReconciliationError,
    create_allocation_request,
    decide_allocation,
    get_allocation_view,
    list_allocation_views,
)
from delta.budget import BudgetPeriod, BudgetScope
from delta.persistence.database import get_tenant_session
from delta.persistence.models import budget_definitions

from .conftest import db_required


def _team_target(*, team_id: str, amount: int) -> AllocationTargetIn:
    return AllocationTargetIn(
        scope=BudgetScope.TEAM,
        team_id=team_id,
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        amount_minor_units=amount,
    )


@db_required
async def test_propose_then_approve_materializes_budgets(tenant_id: str) -> None:
    team_a, team_b = str(uuid.uuid4()), str(uuid.uuid4())
    req = AllocationCreateRequest(
        tenant_id=tenant_id,
        total_minor_units=10_000,
        currency="USD",
        period=BudgetPeriod.MONTHLY,
        targets=[
            _team_target(team_id=team_a, amount=6_000),
            _team_target(team_id=team_b, amount=4_000),
        ],
        requested_by="operator-1",
    )
    async with get_tenant_session(tenant_id) as session:
        proposed = await create_allocation_request(session, req)
    assert proposed.status == "requested"
    assert all(t.budget_id is None for t in proposed.targets)

    async with get_tenant_session(tenant_id) as session:
        decided = await decide_allocation(
            session,
            allocation_id=proposed.allocation_id,
            decision=ApprovalDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="operator-2"
            ),
        )
    assert decided.status == "approved"
    assert decided.decided_by == "operator-2"
    assert all(t.budget_id is not None for t in decided.targets)

    async with get_tenant_session(tenant_id) as session:
        rows = (
            await session.execute(
                select(budget_definitions).where(budget_definitions.c.tenant_id == tenant_id)
            )
        ).all()
    assert len(rows) == 2
    costs = sorted(r.limit_cost_cents for r in rows)
    assert costs == [4_000, 6_000]


@db_required
async def test_reject_materializes_no_budgets(tenant_id: str) -> None:
    req = AllocationCreateRequest(
        tenant_id=tenant_id,
        total_minor_units=5_000,
        currency="USD",
        period=BudgetPeriod.DAILY,
        targets=[_team_target(team_id=str(uuid.uuid4()), amount=5_000)],
        requested_by="operator-1",
    )
    async with get_tenant_session(tenant_id) as session:
        proposed = await create_allocation_request(session, req)

    async with get_tenant_session(tenant_id) as session:
        decided = await decide_allocation(
            session,
            allocation_id=proposed.allocation_id,
            decision=ApprovalDecisionRequest(
                tenant_id=tenant_id, action="reject", actor="operator-2", note="over budget"
            ),
        )
    assert decided.status == "rejected"
    assert all(t.budget_id is None for t in decided.targets)

    async with get_tenant_session(tenant_id) as session:
        rows = (
            await session.execute(
                select(budget_definitions).where(budget_definitions.c.tenant_id == tenant_id)
            )
        ).all()
    assert rows == []


@db_required
async def test_double_decision_conflicts(tenant_id: str) -> None:
    req = AllocationCreateRequest(
        tenant_id=tenant_id,
        total_minor_units=1_000,
        currency="USD",
        period=BudgetPeriod.DAILY,
        targets=[_team_target(team_id=str(uuid.uuid4()), amount=1_000)],
        requested_by="operator-1",
    )
    async with get_tenant_session(tenant_id) as session:
        proposed = await create_allocation_request(session, req)

    decision = ApprovalDecisionRequest(tenant_id=tenant_id, action="approve", actor="operator-2")
    async with get_tenant_session(tenant_id) as session:
        await decide_allocation(session, allocation_id=proposed.allocation_id, decision=decision)

    with pytest.raises(AllocationAlreadyDecidedError):
        async with get_tenant_session(tenant_id) as session:
            await decide_allocation(
                session, allocation_id=proposed.allocation_id, decision=decision
            )


@db_required
async def test_decision_on_unknown_allocation_not_found(tenant_id: str) -> None:
    decision = ApprovalDecisionRequest(tenant_id=tenant_id, action="approve", actor="operator-2")
    with pytest.raises(AllocationNotFoundError):
        async with get_tenant_session(tenant_id) as session:
            await decide_allocation(session, allocation_id=str(uuid.uuid4()), decision=decision)


@db_required
async def test_cross_tenant_allocation_is_invisible(tenant_id: str, other_tenant_id: str) -> None:
    req = AllocationCreateRequest(
        tenant_id=tenant_id,
        total_minor_units=1_000,
        currency="USD",
        period=BudgetPeriod.DAILY,
        targets=[_team_target(team_id=str(uuid.uuid4()), amount=1_000)],
        requested_by="operator-1",
    )
    async with get_tenant_session(tenant_id) as session:
        proposed = await create_allocation_request(session, req)

    async with get_tenant_session(other_tenant_id) as session:
        view = await get_allocation_view(session, allocation_id=proposed.allocation_id)
    assert view is None  # RLS: tenant B's session structurally cannot see tenant A's row


@db_required
async def test_unreconciled_targets_rejected(tenant_id: str) -> None:
    req = AllocationCreateRequest(
        tenant_id=tenant_id,
        total_minor_units=10_000,
        currency="USD",
        period=BudgetPeriod.MONTHLY,
        targets=[_team_target(team_id=str(uuid.uuid4()), amount=4_000)],  # short of total
        requested_by="operator-1",
    )
    with pytest.raises(AllocationReconciliationError):
        async with get_tenant_session(tenant_id) as session:
            await create_allocation_request(session, req)


@db_required
async def test_list_allocations_respects_limit(tenant_id: str) -> None:
    for _ in range(3):
        req = AllocationCreateRequest(
            tenant_id=tenant_id,
            total_minor_units=1_000,
            currency="USD",
            period=BudgetPeriod.DAILY,
            targets=[_team_target(team_id=str(uuid.uuid4()), amount=1_000)],
            requested_by="operator-1",
        )
        async with get_tenant_session(tenant_id) as session:
            await create_allocation_request(session, req)

    async with get_tenant_session(tenant_id) as session:
        capped = await list_allocation_views(session, limit=2)
        uncapped = await list_allocation_views(session, limit=100)
    assert len(capped) == 2
    assert len(uncapped) == 3
