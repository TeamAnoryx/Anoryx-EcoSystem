"""Allocation-admin orchestration (D-007, ADR-0007 §5).

Propose -> decide. A propose call NEVER touches ``budget_definitions``; only an
explicit ``approve`` decision materializes targets into real budget caps, reusing
D-005's ``create_budget`` seam unchanged (no new budget-creation code path).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from ..allocation import Allocation, AllocationTarget
from ..budget import BudgetConcept
from ..budget_engine.definitions import create_budget
from ..money import Money
from . import store
from .schemas import (
    AllocationCreateRequest,
    AllocationTargetView,
    AllocationView,
    ApprovalDecisionRequest,
)


class AllocationReconciliationError(ValueError):
    """The proposed targets do not sum (in currency + amount) to the total."""


class AllocationNotFoundError(LookupError):
    pass


class AllocationAlreadyDecidedError(RuntimeError):
    """A decision was attempted on an allocation that is no longer 'requested'."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def target_scope_ref(
    *, scope: str, tenant_id: str, team_id: str, project_id: str, agent_id: str
) -> str:
    """The D-001 ``AllocationTarget.scope_ref`` for a given scope (ADR-0001 four-id shape)."""
    return {
        "tenant": tenant_id,
        "team": team_id,
        "project": project_id,
        "agent": agent_id,
    }[scope]


def _record_to_view(record: store.AllocationRecord) -> AllocationView:
    return AllocationView(
        allocation_id=record.allocation_id,
        tenant_id=record.tenant_id,
        total_minor_units=record.total_minor_units,
        currency=record.currency,
        period=record.period,
        status=record.status,  # type: ignore[arg-type]
        requested_by=record.requested_by,
        requested_at=record.requested_at,
        decided_by=record.decided_by,
        decided_at=record.decided_at,
        targets=[
            AllocationTargetView(
                scope=t.scope,
                team_id=t.team_id,
                project_id=t.project_id,
                agent_id=t.agent_id,
                amount_minor_units=t.amount_minor_units,
                budget_id=t.budget_id,
            )
            for t in record.targets
        ],
    )


async def create_allocation_request(
    session: AsyncSession, req: AllocationCreateRequest
) -> AllocationView:
    """Validate reconciliation (vector 4) via the shared D-001 ``Allocation`` model,
    then persist status='requested' + a 'requested' history entry. Commits the txn."""
    try:
        Allocation(
            allocation_id="00000000-0000-0000-0000-000000000000",
            tenant_id=req.tenant_id,
            total=Money(minor_units=req.total_minor_units, currency=req.currency),
            targets=tuple(
                AllocationTarget(
                    scope_ref=target_scope_ref(
                        scope=t.scope.value,
                        tenant_id=req.tenant_id,
                        team_id=t.team_id,
                        project_id=t.project_id,
                        agent_id=t.agent_id,
                    ),
                    amount=Money(minor_units=t.amount_minor_units, currency=req.currency),
                )
                for t in req.targets
            ),
            period=req.period,
        )
    except ValidationError as exc:
        raise AllocationReconciliationError(str(exc)) from exc

    now = _now()
    record = await store.create_allocation(
        session,
        tenant_id=req.tenant_id,
        total_minor_units=req.total_minor_units,
        currency=req.currency,
        period=req.period,
        targets=[
            {
                "scope": t.scope,
                "team_id": t.team_id,
                "project_id": t.project_id,
                "agent_id": t.agent_id,
                "amount_minor_units": t.amount_minor_units,
            }
            for t in req.targets
        ],
        requested_by=req.requested_by,
        now=now,
    )
    await store.record_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="allocation",
        entity_id=record.allocation_id,
        action="requested",
        actor=req.requested_by,
        now=now,
        note=f"{len(req.targets)} target(s), total {req.total_minor_units} {req.currency}",
    )
    await session.commit()
    return _record_to_view(record)


async def get_allocation_view(
    session: AsyncSession, *, allocation_id: str
) -> AllocationView | None:
    record = await store.get_allocation(session, allocation_id=allocation_id)
    return None if record is None else _record_to_view(record)


async def list_allocation_views(
    session: AsyncSession, *, status: str | None = None, limit: int = store.DEFAULT_LIST_LIMIT
) -> list[AllocationView]:
    records = await store.list_allocations(session, status=status, limit=limit)
    return [_record_to_view(r) for r in records]


async def decide_allocation(
    session: AsyncSession, *, allocation_id: str, decision: ApprovalDecisionRequest
) -> AllocationView:
    """Approve or reject a 'requested' allocation. Commits the txn.

    Approve materializes every target into a ``budget_definitions`` row via D-005's
    ``create_budget`` (unchanged) and records the resulting ``budget_id`` on each
    target. Reject has no side effect beyond the status transition. Both are recorded
    to change-history. Raises :class:`AllocationNotFoundError` (404) or
    :class:`AllocationAlreadyDecidedError` (409) — the caller (router) maps these to
    HTTP status codes.
    """
    record = await store.get_allocation(session, allocation_id=allocation_id)
    if record is None or record.tenant_id != decision.tenant_id:
        raise AllocationNotFoundError(allocation_id)

    now = _now()
    new_status = "approved" if decision.action == "approve" else "rejected"
    transitioned = await store.try_decide_allocation(
        session,
        allocation_id=allocation_id,
        new_status=new_status,
        decided_by=decision.actor,
        now=now,
    )
    if not transitioned:
        raise AllocationAlreadyDecidedError(allocation_id)

    updated_targets = record.targets
    if decision.action == "approve":
        materialized: list[store.AllocationTargetRecord] = []
        for target in record.targets:
            concept = BudgetConcept(
                tenant_id=record.tenant_id,
                team_id=target.team_id,
                project_id=target.project_id,
                agent_id=target.agent_id,
                scope=target.scope,
                period=record.period,
                limit_cost_cents=target.amount_minor_units,
                currency=record.currency,
            )
            budget = await create_budget(session, concept, now=now)
            await store.set_target_budget_id(
                session, target_id=target.target_id, budget_id=budget.budget_id
            )
            materialized.append(replace(target, budget_id=budget.budget_id))
        updated_targets = tuple(materialized)

    await store.record_history(
        session,
        tenant_id=record.tenant_id,
        entity_type="allocation",
        entity_id=allocation_id,
        action=new_status,
        actor=decision.actor,
        now=now,
        note=decision.note,
    )
    await session.commit()

    # NOT a post-commit re-query: get_tenant_session's tenant GUC is transaction-local
    # (is_local=true) and clears on commit, so a SELECT in a new transaction on this
    # same session would see zero rows (fail-closed RLS, not a bug to work around by
    # re-opening a session) — build the result from what this call already wrote.
    updated_record = replace(
        record,
        status=new_status,
        decided_by=decision.actor,
        decided_at=now,
        targets=updated_targets,
    )
    return _record_to_view(updated_record)
