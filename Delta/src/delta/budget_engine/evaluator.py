"""Budget evaluation orchestration (ADR-0005 §3.2-§3.6).

Fires after a usage debit commits (the D-004 ingest hook), for ONLY the scope(s) the
event touches. It is a post-commit SIDE EFFECT: it runs in its own tenant transaction and
NEVER alters the ingest response — a successful debit always returns 200 regardless of what
evaluation does (the ledger is the authority; enforcement is downstream).

Fail posture (Fork 4, vectors 11+12):
  * a transient ledger-read error NEVER publishes an enforcement (never wrongly cut off an
    under-budget tenant on a blip) — it is logged and the next event re-evaluates;
  * a non-transient error is logged LOUD and never swallowed into a fail-open;
  * a publish failure is handled by the drainer (decision durable in the outbox).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..ingest.errors import is_transient
from ..persistence.database import get_tenant_session
from .config import EngineSettings
from .decision import is_over_cost_cap, soft_warning_band
from .definitions import BudgetDefinition, budgets_for_event
from .drainer import drain_tenant
from .emit import build_policy_payload
from .outbox import enqueue_decision
from .periods import period_bucket_label, period_end, period_start
from .spend import scope_spend_cents
from .state import (
    get_or_create_state,
    try_bump_warned_pct,
    try_transition_to_enforced,
    try_transition_to_under,
)
from .warnings import emit_budget_warning

logger = logging.getLogger("delta.budget_engine.evaluator")


async def evaluate_after_post(record, settings: EngineSettings) -> None:
    """Evaluate the budgets the just-posted usage event touches. Never raises.

    ``record`` is the D-004 ``UsageRecord`` (carries tenant/team/project/agent). ``settings``
    is resolved once at app startup (fail-loud) and passed in; when the engine is disabled
    this is an immediate no-op.
    """
    if not settings.enabled:
        return
    tenant_id = record.tenant_id
    try:
        await _evaluate(record, settings)
    except Exception as exc:  # noqa: BLE001 — classify, never raise into the ingest path
        if is_transient(exc):
            logger.warning(
                "delta.budget eval transient failure — NO enforcement published (under-budget "
                "tenants are never cut off on a blip; next event re-evaluates) tenant=%s err=%r",
                tenant_id,
                exc,
            )
        else:
            logger.error(
                "delta.budget eval FAILED (non-transient) — NO enforcement published (NOT "
                "fail-open); a persistent failure is a monitored incident tenant=%s err=%r",
                tenant_id,
                exc,
            )


async def _evaluate(record, settings: EngineSettings) -> None:
    now = datetime.now(timezone.utc)
    tenant_id = record.tenant_id
    async with get_tenant_session(tenant_id) as session:
        budgets = await budgets_for_event(
            session,
            team_id=record.team_id,
            project_id=record.project_id,
            agent_id=record.agent_id,
        )
        for budget in budgets:
            await _evaluate_budget(session, budget, settings, now)
        await session.commit()

    # Best-effort inline publish (sub-second latency) AND the event-driven retry sweep:
    # drain on EVERY event so a previously-failed publish for this tenant is retried (its
    # own backoff is respected by claim_due). The decision is already durable in the outbox,
    # so a publish failure never loses it. Cheap when there is nothing due (one indexed scan).
    await drain_tenant(tenant_id, settings, now)


async def _evaluate_budget(
    session, budget: BudgetDefinition, settings: EngineSettings, now: datetime
) -> bool:
    """Evaluate one budget; enqueue a decision if an edge was crossed. Returns True if so."""
    pstart = period_start(budget.period, now)
    pend = period_end(budget.period, now)
    bucket = period_bucket_label(budget.period, now)
    spend = await scope_spend_cents(
        session,
        scope=budget.scope,
        tenant_id=budget.tenant_id,
        team_id=budget.team_id,
        project_id=budget.project_id,
        agent_id=budget.agent_id,
        currency=budget.currency,
        period_start=pstart,
        period_end=pend,
    )
    state = await get_or_create_state(
        session,
        tenant_id=budget.tenant_id,
        budget_id=budget.budget_id,
        period_bucket=bucket,
        now=now,
    )
    over = is_over_cost_cap(spend, budget)

    # under -> over: enforce (publish the cap) exactly once via the conditional transition.
    if over and state.state == "under":
        version = await try_transition_to_enforced(
            session,
            tenant_id=budget.tenant_id,
            budget_id=budget.budget_id,
            period_bucket=bucket,
            now=now,
        )
        if version is None:
            return False  # a concurrent append already enforced — exactly one publish
        await _enqueue(session, budget, version, "enforce", now)
        logger.info(
            "delta.budget ENFORCE decided policy_id=%s version=%d scope=%s tenant=%s "
            "spend_cents=%d cap_cents=%s",
            budget.policy_id,
            version,
            budget.scope.value,
            budget.tenant_id,
            spend,
            budget.limit_cost_cents,
        )
        return True

    # over -> under: budget raised above spend — refresh the cap (un-enforce) at a new version.
    if (not over) and state.state == "enforced":
        version = await try_transition_to_under(
            session,
            tenant_id=budget.tenant_id,
            budget_id=budget.budget_id,
            period_bucket=bucket,
            now=now,
        )
        if version is None:
            return False
        await _enqueue(session, budget, version, "refresh", now)
        logger.info(
            "delta.budget REFRESH (un-enforce) decided policy_id=%s version=%d scope=%s "
            "tenant=%s spend_cents=%d cap_cents=%s",
            budget.policy_id,
            version,
            budget.scope.value,
            budget.tenant_id,
            spend,
            budget.limit_cost_cents,
        )
        return True

    # Still under the cap: advisory warning only (CONFIRM B) — never enforcement.
    band = soft_warning_band(spend, budget, settings.soft_warning_pcts)
    if band is not None and await try_bump_warned_pct(
        session,
        tenant_id=budget.tenant_id,
        budget_id=budget.budget_id,
        period_bucket=bucket,
        pct=band,
        now=now,
    ):
        emit_budget_warning(budget=budget, spend_cents=spend, pct=band)
    return False


async def _enqueue(
    session, budget: BudgetDefinition, version: int, transition: str, now: datetime
) -> None:
    payload = build_policy_payload(budget, policy_version=version, effective_from=now)
    await enqueue_decision(
        session,
        tenant_id=budget.tenant_id,
        budget_id=budget.budget_id,
        policy_id=budget.policy_id,
        policy_version=version,
        transition=transition,
        policy_payload=payload,
        now=now,
    )
