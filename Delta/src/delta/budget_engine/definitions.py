"""Budget-definition store — the caps to evaluate (ADR-0005 §7).

One row per Sentinel ``policy_id``; mirrors ``delta.budget.BudgetConcept`` (the locked
``budget_limit`` shape). Budgets are seeded via :func:`create_budget` (an internal create
path; the full allocation UI is D-007). Evaluation looks budgets up by the scope key the
affected usage event touches (:func:`budgets_for_event`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import and_, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..budget import BudgetConcept, BudgetPeriod, BudgetScope
from ..persistence.models import budget_definitions

# List-response bound (mirrors D-007's store.MAX_LIST_LIMIT / D-008's dashboards row cap).
MAX_LIST_LIMIT = 100


@dataclass(frozen=True)
class BudgetDefinition:
    """A persisted budget cap (the row the engine evaluates and publishes)."""

    budget_id: str
    tenant_id: str
    scope: BudgetScope
    team_id: str
    project_id: str
    agent_id: str
    period: BudgetPeriod
    limit_tokens: int | None
    limit_cost_cents: int | None
    currency: str
    policy_id: str

    def to_concept(self) -> BudgetConcept:
        """Reconstruct the D-002 ``BudgetConcept`` for the emit path."""
        return BudgetConcept(
            tenant_id=self.tenant_id,
            team_id=self.team_id,
            project_id=self.project_id,
            agent_id=self.agent_id,
            scope=self.scope,
            period=self.period,
            limit_tokens=self.limit_tokens,
            limit_cost_cents=self.limit_cost_cents,
            currency=self.currency,
        )


def _row_to_definition(row) -> BudgetDefinition:
    return BudgetDefinition(
        budget_id=row.budget_id,
        tenant_id=row.tenant_id,
        scope=BudgetScope(row.scope),
        team_id=row.team_id,
        project_id=row.project_id,
        agent_id=row.agent_id,
        period=BudgetPeriod(row.period),
        limit_tokens=row.limit_tokens,
        limit_cost_cents=row.limit_cost_cents,
        currency=row.currency,
        policy_id=row.policy_id,
    )


async def create_budget(
    session: AsyncSession,
    concept: BudgetConcept,
    *,
    now: datetime,
    policy_id: str | None = None,
    budget_id: str | None = None,
) -> BudgetDefinition:
    """Persist a budget cap (tenant-scoped INSERT). Does NOT commit (caller owns the txn).

    ``policy_id`` is the stable Sentinel policy id the budget publishes under; a fresh
    UUID is generated when omitted. Re-publishing the same budget bumps the version, never
    this id.
    """
    bid = budget_id or str(uuid.uuid4())
    pid = policy_id or str(uuid.uuid4())
    await session.execute(
        insert(budget_definitions).values(
            budget_id=bid,
            tenant_id=concept.tenant_id,
            scope=concept.scope.value,
            team_id=concept.team_id,
            project_id=concept.project_id,
            agent_id=concept.agent_id,
            period=concept.period.value,
            limit_tokens=concept.limit_tokens,
            limit_cost_cents=concept.limit_cost_cents,
            currency=concept.currency,
            policy_id=pid,
            created_at=now,
        )
    )
    return BudgetDefinition(
        budget_id=bid,
        tenant_id=concept.tenant_id,
        scope=concept.scope,
        team_id=concept.team_id,
        project_id=concept.project_id,
        agent_id=concept.agent_id,
        period=concept.period,
        limit_tokens=concept.limit_tokens,
        limit_cost_cents=concept.limit_cost_cents,
        currency=concept.currency,
        policy_id=pid,
    )


async def raise_budget_cost_cap(
    session: AsyncSession, *, budget_id: str, new_limit_cost_cents: int
) -> None:
    """Update a budget's cost cap (tenant-scoped UPDATE; the budget-raise path).

    The next evaluation that sees spend back under the new cap publishes a refreshed cap
    at a bumped version (un-enforce). Does NOT commit (caller owns the txn). RLS confines
    the UPDATE to the caller's tenant on both the visible row and the post-image.
    """
    await session.execute(
        update(budget_definitions)
        .where(budget_definitions.c.budget_id == budget_id)
        .values(limit_cost_cents=new_limit_cost_cents)
    )


async def get_budget(session: AsyncSession, *, budget_id: str) -> BudgetDefinition | None:
    """Look up one budget by id (RLS confines the read to the caller's tenant).

    Returns ``None`` when the id doesn't exist OR belongs to another tenant — the two
    cases are indistinguishable to the caller by design (no cross-tenant existence leak).
    """
    stmt = select(budget_definitions).where(budget_definitions.c.budget_id == budget_id)
    row = (await session.execute(stmt)).first()
    return None if row is None else _row_to_definition(row)


async def list_budgets(session: AsyncSession, *, limit: int = 100) -> list[BudgetDefinition]:
    """List the caller's tenant's budgets (RLS-confined), oldest first.

    ``limit`` is clamped to ``[1, MAX_LIST_LIMIT]`` (mirrors D-007's list-response cap —
    a deliberate resource limit, not a business rule).
    """
    stmt = (
        select(budget_definitions)
        .order_by(budget_definitions.c.created_at)
        .limit(max(1, min(limit, MAX_LIST_LIMIT)))
    )
    rows = (await session.execute(stmt)).all()
    return [_row_to_definition(r) for r in rows]


async def budgets_for_event(
    session: AsyncSession,
    *,
    team_id: str,
    project_id: str,
    agent_id: str,
) -> list[BudgetDefinition]:
    """Budgets whose scope the affected usage event touches (RLS confines to the tenant).

    A tenant-scope budget always matches; a team/project/agent-scope budget matches only
    when its id equals the event's. Tenant isolation is structural (RLS): an event for
    tenant A can never load tenant B's budgets (vector 8).
    """
    t = budget_definitions.c
    stmt = select(budget_definitions).where(
        or_(
            t.scope == BudgetScope.TENANT.value,
            and_(t.scope == BudgetScope.TEAM.value, t.team_id == team_id),
            and_(t.scope == BudgetScope.PROJECT.value, t.project_id == project_id),
            and_(t.scope == BudgetScope.AGENT.value, t.agent_id == agent_id),
        )
    )
    rows = (await session.execute(stmt)).all()
    return [_row_to_definition(r) for r in rows]
