"""Request-time policy enforcement evaluators (ADR-0009 §4, §6, §10).

Pure decision logic + the DB loaders the F-006 router calls. Reads run on the
caller's session (a tenant session at request time, RLS-scoped). Keeping this
logic here — out of selection.py / cost.py — means the F-006 files get only
minimal call-site insertions (R7).

MODEL policies use the Sentinel-ID wildcard convention (Decision A): a policy
matches when its tenant_id equals the request's and each sub-tenant id equals the
request's OR the wildcard token (WILDCARD_UUID for team/project, WILDCARD_AGENT
for agent). DENY is absolute; among matching allow-lists the highest-specificity
one applies. BUDGET policies do NOT use wildcards — their own `scope` field
selects which ids are significant; "used" is summed over persisted usage events
in the current period (a client-side estimate, not an authoritative bill).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import DateTime, and_, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.policy_repository import PolicyRepository
from policy.constants import WILDCARD_AGENT, WILDCARD_UUID
from policy.variants import BudgetLimitPolicy, ModelAllowlistPolicy, ModelDenylistPolicy


@dataclass(frozen=True, slots=True)
class RequestScope:
    """The four request IDs the enforcement layer matches policies against."""

    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str


def scope_from_context(tenant_context) -> RequestScope:
    """Build a RequestScope from a gateway TenantContext (server-resolved IDs)."""
    return RequestScope(
        tenant_id=tenant_context.tenant_id,
        team_id=tenant_context.team_id,
        project_id=tenant_context.project_id,
        agent_id=tenant_context.agent_id,
    )


# --------------------------------------------------------------------------- #
# Model-policy decision types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ModelAllow:
    policy_id: str | None = None  # the allow-list that permitted it, if any matched


@dataclass(frozen=True, slots=True)
class ModelDeny:
    policy_id: str
    reason: str  # "model_denied" | "model_not_in_allowlist"


ModelDecision = ModelAllow | ModelDeny


@dataclass(frozen=True, slots=True)
class BudgetOk:
    pass


@dataclass(frozen=True, slots=True)
class BudgetExceeded:
    policy_id: str
    reason: str  # "budget_tokens_exceeded" | "budget_cost_exceeded"


BudgetDecision = BudgetOk | BudgetExceeded


# --------------------------------------------------------------------------- #
# Pure matching helpers
# --------------------------------------------------------------------------- #
def model_matches_scope(
    view: ModelAllowlistPolicy | ModelDenylistPolicy, scope: RequestScope
) -> bool:
    """Wildcard-aware match for a MODEL policy (tenant exact; sub-ids exact-or-wildcard)."""
    return (
        view.tenant_id == scope.tenant_id
        and view.team_id in (scope.team_id, WILDCARD_UUID)
        and view.project_id in (scope.project_id, WILDCARD_UUID)
        and view.agent_id in (scope.agent_id, WILDCARD_AGENT)
    )


def model_specificity(view: ModelAllowlistPolicy | ModelDenylistPolicy) -> int:
    """Number of non-wildcard sub-tenant ids (0-3); higher = more specific."""
    return (
        int(view.team_id != WILDCARD_UUID)
        + int(view.project_id != WILDCARD_UUID)
        + int(view.agent_id != WILDCARD_AGENT)
    )


def budget_matches_scope(view: BudgetLimitPolicy, scope: RequestScope) -> bool:
    """Match a BUDGET policy by its own `scope` field (no wildcard convention)."""
    if view.tenant_id != scope.tenant_id:
        return False
    if view.scope in ("team", "project", "agent") and view.team_id != scope.team_id:
        return False
    if view.scope in ("project", "agent") and view.project_id != scope.project_id:
        return False
    if view.scope == "agent" and view.agent_id != scope.agent_id:
        return False
    return True


def resolve_model_decision(
    allow_views: list[ModelAllowlistPolicy],
    deny_views: list[ModelDenylistPolicy],
    model_id: str,
) -> ModelDecision:
    """Pure resolution: deny absolute, else highest-specificity allow-list wins.

    Inputs are the allow/deny views that ALREADY matched the request scope. No
    matching allow-list => not allow-constrained (ModelAllow). Tie-break among
    equal-specificity allow-lists: higher policy_version, then policy_id.
    """
    for deny in deny_views:
        if deny.is_denied(model_id):
            return ModelDeny(policy_id=deny.policy_id, reason="model_denied")

    if not allow_views:
        return ModelAllow()

    chosen = max(
        allow_views,
        key=lambda v: (model_specificity(v), v.policy_version, v.policy_id),
    )
    if chosen.is_allowed(model_id):
        return ModelAllow(policy_id=chosen.policy_id)
    return ModelDeny(policy_id=chosen.policy_id, reason="model_not_in_allowlist")


def allowlist_active(view: ModelAllowlistPolicy, now: datetime) -> bool:
    """An allow-list applies only until its optional effective_until expiry (contract).

    No effective_until => no expiry. An unparseable expiry is treated as inactive
    (the allow-list stops constraining) rather than silently enforcing a stale,
    unverifiable window; intake schema validation makes a malformed stored value
    near-impossible. Deny-lists carry no expiry — a deny is permanent until replaced.
    """
    if view.effective_until is None:
        return True
    try:
        until = datetime.fromisoformat(view.effective_until.replace("Z", "+00:00"))
    except ValueError:
        return False
    return until > now


def period_start(period: str, now: datetime) -> datetime:
    """UTC bucket start for a budget period (date_trunc semantics, in Python)."""
    now = now.astimezone(UTC)
    if period == "hourly":
        return now.replace(minute=0, second=0, microsecond=0)
    if period == "daily":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)  # monthly


# --------------------------------------------------------------------------- #
# DB-backed evaluators
# --------------------------------------------------------------------------- #
async def budget_period_used(
    session: AsyncSession,
    scope: RequestScope,
    budget: BudgetLimitPolicy,
    *,
    now: datetime | None = None,
) -> tuple[int, float]:
    """Sum (tokens, cost) over persisted usage events in the current period bucket."""
    start = period_start(budget.period, now or datetime.now(UTC))
    conds = [
        EventsAuditLog.event_type == "usage",
        EventsAuditLog.tenant_id == scope.tenant_id,
    ]
    if budget.scope in ("team", "project", "agent"):
        conds.append(EventsAuditLog.team_id == scope.team_id)
    if budget.scope in ("project", "agent"):
        conds.append(EventsAuditLog.project_id == scope.project_id)
    if budget.scope == "agent":
        conds.append(EventsAuditLog.agent_id == scope.agent_id)
    # event_timestamp is a String(64) RFC3339-UTC value (always written with a 'Z'
    # by build_usage_event / build_policy_event). Postgres parses it via the
    # timestamptz cast. A malformed/naive value would be misbucketed, but the
    # emitter is the sole writer and always emits canonical RFC3339-UTC.
    conds.append(cast(EventsAuditLog.event_timestamp, DateTime(timezone=True)) >= start)

    stmt = select(
        func.coalesce(func.sum(EventsAuditLog.tokens_in + EventsAuditLog.tokens_out), 0),
        func.coalesce(func.sum(EventsAuditLog.cost_estimate_cents), 0),
    ).where(and_(*conds))
    row = (await session.execute(stmt)).one()
    return int(row[0] or 0), float(row[1] or 0.0)


async def evaluate_model_policies(
    session: AsyncSession, scope: RequestScope, model_id: str, *, now: datetime | None = None
) -> ModelDecision:
    """Read active model allow/deny policies for the scope and resolve a decision.

    Allow-lists past their optional effective_until expiry are excluded (contract);
    deny-lists never expire. effective_from is filtered in SQL; effective_until lives
    in the policy_payload, so it is filtered here on the parsed view.
    """
    now = now or datetime.now(UTC)
    repo = PolicyRepository(session)
    deny_rows = await repo.get_active_policies_for_scope(scope.tenant_id, "model_denylist")
    allow_rows = await repo.get_active_policies_for_scope(scope.tenant_id, "model_allowlist")
    deny_views = [
        v
        for v in (ModelDenylistPolicy(**json.loads(r.policy_payload)) for r in deny_rows)
        if model_matches_scope(v, scope)
    ]
    allow_views = [
        v
        for v in (ModelAllowlistPolicy(**json.loads(r.policy_payload)) for r in allow_rows)
        if model_matches_scope(v, scope) and allowlist_active(v, now)
    ]
    return resolve_model_decision(allow_views, deny_views, model_id)


async def load_active_budgets(
    session: AsyncSession, scope: RequestScope, *, now: datetime | None = None
) -> list[tuple[BudgetLimitPolicy, int, float]]:
    """Matched budget views with their current period-used (tokens, cost) baselines.

    Used at request entry to seed the stream-time ceiling check (StreamRouteResult).
    """
    repo = PolicyRepository(session)
    rows = await repo.get_active_policies_for_scope(scope.tenant_id, "budget_limit")
    out: list[tuple[BudgetLimitPolicy, int, float]] = []
    for row in rows:
        budget = BudgetLimitPolicy(**json.loads(row.policy_payload))
        if not budget_matches_scope(budget, scope):
            continue
        used_tokens, used_cost = await budget_period_used(session, scope, budget, now=now)
        out.append((budget, used_tokens, used_cost))
    return out


def evaluate_budget_against(
    budgets: list[tuple[BudgetLimitPolicy, int, float]],
    est_tokens: int,
    est_cost: float,
) -> BudgetDecision:
    """Pure: given matched budgets + baselines, check an additional (tokens, cost)."""
    for budget, used_tokens, used_cost in budgets:
        if (
            budget.max_tokens_per_period is not None
            and used_tokens + est_tokens > budget.max_tokens_per_period
        ):
            return BudgetExceeded(policy_id=budget.policy_id, reason="budget_tokens_exceeded")
        if (
            budget.max_cost_cents_per_period is not None
            and used_cost + est_cost > budget.max_cost_cents_per_period
        ):
            return BudgetExceeded(policy_id=budget.policy_id, reason="budget_cost_exceeded")
    return BudgetOk()


async def evaluate_budget_pre_request(
    session: AsyncSession,
    scope: RequestScope,
    est_tokens: int,
    est_cost: float,
    *,
    now: datetime | None = None,
) -> BudgetDecision:
    """Read active budgets for the scope and check the pre-request estimate."""
    budgets = await load_active_budgets(session, scope, now=now)
    return evaluate_budget_against(budgets, est_tokens, est_cost)
