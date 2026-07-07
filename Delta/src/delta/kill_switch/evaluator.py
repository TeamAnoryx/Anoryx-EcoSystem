"""Kill-switch evaluation orchestration (ADR-0006 §3.2-§3.4).

Fires from the SAME D-004 ingest post-commit hook as the D-005 budget engine, for the
single scope the just-posted event touches. A pure post-commit side effect: it runs in
its own tenant transaction and NEVER alters the ingest response. Unlike D-005 there is no
ledger SUM — the check is O(1): an allow-list presence lookup plus an integer comparison
against the single event's own cost, already in hand. This is what makes the kill-switch
faster than the budget-threshold loop.

Fail posture (ADR-0006 §3.7, mirrors ADR-0005 §3.5):
  * a transient detection-read error NEVER publishes a kill (never wrongly cut off an
    authorized agent on a blip) — logged, the next event re-evaluates;
  * a non-transient error is logged LOUD and never swallowed into a fail-open;
  * a publish failure is handled by the drainer (decision durable in the outbox).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..ingest.errors import is_transient
from ..persistence.database import get_tenant_session
from .authorizations import is_authorized, is_tenant_gated
from .config import KillSwitchSettings
from .drainer import drain_tenant
from .emit import build_kill_payload
from .outbox import enqueue_decision
from .state import get_or_create_state, try_transition_to_killed
from .triggers import detect_reason

logger = logging.getLogger("delta.kill_switch.evaluator")


async def evaluate_kill_switch(record, settings: KillSwitchSettings) -> None:
    """Evaluate the scope the just-posted usage event touches. Never raises.

    ``record`` is the D-004 ``UsageRecord``. ``settings`` is resolved once at app startup
    (fail-loud) and passed in; when the kill-switch is disabled this is an immediate no-op.
    """
    if not settings.enabled:
        return
    tenant_id = record.tenant_id
    try:
        await _evaluate(record, settings)
    except Exception as exc:  # noqa: BLE001 — classify, never raise into the ingest path
        if is_transient(exc):
            logger.warning(
                "delta.kill_switch eval transient failure — NO kill published (an "
                "authorized/normal agent is never cut off on a blip; next event "
                "re-evaluates) tenant=%s err=%r",
                tenant_id,
                exc,
            )
        else:
            logger.error(
                "delta.kill_switch eval FAILED (non-transient) — NO kill published (NOT "
                "fail-open); a persistent failure is a monitored incident tenant=%s err=%r",
                tenant_id,
                exc,
            )


async def _evaluate(record, settings: KillSwitchSettings) -> None:
    now = datetime.now(timezone.utc)
    tenant_id = record.tenant_id
    async with get_tenant_session(tenant_id) as session:
        gated = await is_tenant_gated(session, tenant_id)
        authorized = gated and await is_authorized(session, tenant_id, record.agent_id)
        reason = detect_reason(
            gated=gated,
            authorized=authorized,
            cost_cents=record.cost_estimate_cents,
            max_single_tx_cost_cents=settings.max_single_tx_cost_cents,
        )
        if reason is not None:
            await _kill(session, record, reason, settings, now)
        await session.commit()

    # Best-effort inline publish (sub-second latency) AND the event-driven retry sweep,
    # same shape as the D-005 budget engine.
    await drain_tenant(tenant_id, settings, now)


async def _kill(session, record, reason: str, settings: KillSwitchSettings, now: datetime) -> None:
    state = await get_or_create_state(
        session,
        tenant_id=record.tenant_id,
        team_id=record.team_id,
        project_id=record.project_id,
        agent_id=record.agent_id,
        now=now,
    )
    if state.state != "clear":
        return  # already killed (or a concurrent evaluator is about to kill it)
    version = await try_transition_to_killed(
        session, tenant_id=record.tenant_id, kill_id=state.kill_id, reason=reason, now=now
    )
    if version is None:
        return  # a concurrent offending event already killed it — exactly one publish
    payload = build_kill_payload(
        tenant_id=record.tenant_id,
        team_id=record.team_id,
        project_id=record.project_id,
        agent_id=record.agent_id,
        policy_id=state.policy_id,
        policy_version=version,
        effective_from=now,
    )
    await enqueue_decision(
        session,
        tenant_id=record.tenant_id,
        kill_id=state.kill_id,
        policy_id=state.policy_id,
        policy_version=version,
        transition="kill",
        policy_payload=payload,
        now=now,
    )
    logger.warning(
        "delta.kill_switch KILL decided reason=%s policy_id=%s version=%d tenant=%s "
        "team=%s project=%s agent=%s cost_cents=%d",
        reason,
        state.policy_id,
        version,
        record.tenant_id,
        record.team_id,
        record.project_id,
        record.agent_id,
        record.cost_estimate_cents,
    )
