"""Automation-rule evaluation + execution engine — evaluate_and_execute (O-011, ADR-0011).

Scheduled via FastAPI `BackgroundTasks` from the ingest router immediately after a
successful ACCEPTED persist (mirrors exactly how `distribution/router.py` schedules
`drive_distribution`). Loads this tenant's ENABLED rules for the event's `event_type`,
matches each with the pure `automation.matcher.rule_matches` function, and for every match
triggers exactly ONE closed, pre-existing, already-audited action: `redistribute_policy`
re-drives an O-004 distribution via the EXISTING `distribution.engine.drive_distribution`
— this module never duplicates that fan-out logic.

HARD INVARIANT (state explicitly, non-removable): `evaluate_and_execute` must NEVER
itself cause a new event to be ingested or a new automation evaluation to be scheduled —
no chaining, no recursion. `drive_distribution` only performs outbound HTTP + its own
target/audit bookkeeping; it does not call back into `ingest` or `automation` in any way,
so this invariant holds STRUCTURALLY (there is no code path from this module back to
`ingest.router` or `automation.engine`), not merely by convention or by omission.

EXCEPTION DISCIPLINE (mirrors distribution/engine.py's ADR-0026 narrow-catch precedent):
  * Loading this tenant's enabled rules (the one query BEFORE the per-rule loop) is caught
    narrowly for the SAME `_DB_CONNECTIVITY_ERRORS` family distribution/engine.py defines —
    a transient DB blip there means zero rules are evaluated for this event (logged as a
    warning), never an uncaught crash of the background task. A genuine logic defect
    (anything outside that narrow family) still propagates rather than being silently
    swallowed.
  * EACH matched rule's execute+audit attempt runs inside its OWN isolated try/except
    boundary in the per-rule loop — one rule's unexpected failure can never prevent the
    REMAINING matched rules for this same event from being evaluated (a prior version of
    this engine let one rule's unhandled exception abort the whole loop; fixed as a
    code-reviewer follow-up).
  * A genuine per-rule execution failure (`drive_distribution` raising — which per its own
    docstring only happens for an unexpected logic defect, never an ordinary per-target
    delivery failure) is caught INSIDE `_execute_rule`, recorded as a `failed` audit link,
    and logged at `logger.error` with rule_id/tenant_id/event_id (NEVER the payload) — it
    must never propagate back into FastAPI's BackgroundTasks machinery (the request
    already returned 202; there is nothing left to fail visibly to the caller).
  * The audit-append call itself is wrapped in the SAME narrow DB-connectivity exception
    family already defined in distribution/engine.py (`_DB_CONNECTIVITY_ERRORS`) so a
    transient DB blip recording the audit link does not crash the background task.
  * The UNIQUE(rule_id, triggering_event_id) IntegrityError on that same insert is the
    idempotency dedup gate — caught narrowly and treated as "already executed, skip", a
    normal outcome, never an error.
  * Any OTHER unexpected exception escaping `_execute_rule` (e.g. a logic defect in the
    audit-append path, outside the two narrow catches above) is caught by the per-rule
    loop's own boundary in `evaluate_and_execute`: logged at `logger.error`
    (rule_id/tenant_id/event_id only, never payload content), followed by a best-effort
    attempt to still record a `failed` automation_executions row
    (`error_reason="unexpected_error"`) so Fork I's "every matched execution appends one
    link" claim holds even on this path — then evaluation continues to the next rule
    regardless of whether that best-effort record succeeded.
"""

from __future__ import annotations

import logging
from typing import Any

import sqlalchemy.exc
from sqlalchemy.exc import IntegrityError

from orchestrator.automation.matcher import rule_matches
from orchestrator.config import AutomationSettings, DistributionSettings
from orchestrator.distribution.engine import drive_distribution
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_automation_audit_link,
    list_enabled_automation_rules,
)

logger = logging.getLogger(__name__)

# DB-connectivity errors that must not crash the background task (mirrors
# distribution/engine.py's _DB_CONNECTIVITY_ERRORS verbatim): caught NARROWLY around the
# audit-append call only. A logic defect (InvalidRequestError / ProgrammingError) is
# deliberately excluded so it raises/logs rather than being silently swallowed.
_DB_CONNECTIVITY_ERRORS = (
    sqlalchemy.exc.OperationalError,
    sqlalchemy.exc.InterfaceError,
    sqlalchemy.exc.TimeoutError,
    OSError,
)

# v1 supports exactly ONE action type. A rule's action_type is validated closed to this
# set at rule-creation time (422), so reaching an unknown value here would indicate a
# logic defect elsewhere — handled defensively (never silently no-op'd) rather than
# assumed unreachable.
_REDISTRIBUTE_POLICY = "redistribute_policy"


async def evaluate_and_execute(
    *,
    tenant_id: str,
    event_id: str,
    event_type: str,
    source_product: str,
    payload: dict[str, Any],
    automation_settings: AutomationSettings,
    distribution_settings: DistributionSettings,
) -> None:
    """Evaluate this tenant's automation rules against ONE just-accepted ingest event.

    No-op immediately when the master switch (`automation_settings.enabled`) is off — the
    engine ships OFF by default (ADR-0011). This runs as a FastAPI BackgroundTask AFTER the
    ingest request already returned 202, so there is no HTTP response left to fail: this
    mirrors `distribution.engine.drive_distribution`'s honesty about its own exception
    discipline rather than overclaiming "never raises" — an ORDINARY failure mode (a DB
    connectivity blip loading rules, or one matched rule's execution/audit attempt failing
    unexpectedly) is caught, logged, and best-effort recorded rather than propagated or
    allowed to abort evaluation of the other matched rules for this event; only a genuine
    logic defect outside those narrow, named catches still propagates.
    """
    if not automation_settings.enabled:
        return

    try:
        async with get_tenant_session(tenant_id) as session:
            rules = await list_enabled_automation_rules(
                session, tenant_id=tenant_id, event_type=event_type
            )
    except _DB_CONNECTIVITY_ERRORS:
        # Mirrors distribution/engine.py's narrow-catch precedent: a transient DB blip
        # loading this tenant's rules means zero rules are evaluated for THIS event (never
        # a crashed background task). A genuine logic defect (outside this narrow family)
        # is deliberately excluded so it still raises/logs rather than being swallowed.
        logger.warning(
            "automation rule lookup hit a DB connectivity error; no rules evaluated for "
            "this event",
            extra={"tenant_id": tenant_id, "event_id": event_id},
        )
        return

    for rule in rules:
        if not rule_matches(
            rule, event_type=event_type, source_product=source_product, payload=payload
        ):
            continue
        rule_id = rule.get("id")
        try:
            await _execute_rule(
                rule,
                tenant_id=tenant_id,
                event_id=event_id,
                distribution_settings=distribution_settings,
            )
        except Exception:  # noqa: BLE001 - deliberately broad: one rule's unexpected
            # failure (anything escaping _execute_rule's own narrow IntegrityError /
            # _DB_CONNECTIVITY_ERRORS catches) must NEVER prevent the REMAINING matched
            # rules for this same event from being evaluated. Logged narrowly (never
            # payload content), then a best-effort `failed` audit row is attempted so
            # Fork I's "every matched execution appends one link" still holds here.
            logger.error(
                "automation rule execution raised an unexpected, unhandled error",
                extra={"rule_id": rule_id, "tenant_id": tenant_id, "event_id": event_id},
            )
            await _record_unexpected_failure(
                rule_id=rule_id,
                tenant_id=tenant_id,
                event_id=event_id,
                action_type=rule.get("action_type"),
            )


async def _execute_rule(
    rule: dict[str, Any],
    *,
    tenant_id: str,
    event_id: str,
    distribution_settings: DistributionSettings,
) -> None:
    """Execute exactly ONE matched rule's action, then append exactly ONE audit link.

    Only reached for a rule that genuinely matched — a non-matching rule never gets here
    and so never produces an automation_executions row (there is nothing tamper-evident
    to say about a rule that did not fire).
    """
    rule_id = rule["id"]
    action_type = rule["action_type"]
    disposition = "executed"
    error_reason: str | None = None

    if action_type == _REDISTRIBUTE_POLICY:
        distribution_id = (rule.get("action_config") or {}).get("distribution_id")
        try:
            await drive_distribution(distribution_id, tenant_id, settings=distribution_settings)
        except Exception:  # noqa: BLE001 - must be logged, never silently swallowed, and
            # must NEVER propagate into FastAPI's BackgroundTasks machinery (the request
            # already returned 202 — there is no caller left to see this fail).
            disposition = "failed"
            error_reason = "redistribute_policy_error"
            logger.error(
                "automation rule execution raised an unexpected error",
                extra={"rule_id": rule_id, "tenant_id": tenant_id, "event_id": event_id},
            )
    else:
        # Structurally unreachable (action_type is validated closed to _REDISTRIBUTE_POLICY
        # at rule-creation time, and the DB CHECK constraint enforces the same set) — but
        # an unknown action_type is recorded as a genuine failure, never silently skipped.
        disposition = "failed"
        error_reason = "unknown_action_type"

    try:
        async with get_privileged_session() as psession:
            async with psession.begin():
                await append_automation_audit_link(
                    psession,
                    rule_id=rule_id,
                    tenant_id=tenant_id,
                    triggering_event_id=event_id,
                    action_type=action_type,
                    disposition=disposition,
                    error_reason=error_reason,
                )
    except IntegrityError:
        # UNIQUE(rule_id, triggering_event_id) — this event's automation evaluation for
        # this rule was already executed (a retried/duplicate background-task schedule).
        # A normal, expected skip — never an error.
        pass
    except _DB_CONNECTIVITY_ERRORS:
        logger.warning(
            "automation execution audit-append hit a DB connectivity error",
            extra={"rule_id": rule_id, "tenant_id": tenant_id, "event_id": event_id},
        )


async def _record_unexpected_failure(
    *,
    rule_id: str | None,
    tenant_id: str,
    event_id: str,
    action_type: str | None,
) -> None:
    """Best-effort record ONE `failed` automation_executions row for a rule whose
    execute+audit attempt raised an exception `_execute_rule` itself did not already
    handle (i.e. something outside its own narrow IntegrityError/_DB_CONNECTIVITY_ERRORS
    catches). This is the LAST line of defense for Fork I's "every matched execution
    appends one link" claim on that rare path — it must NEVER itself raise back into the
    per-rule loop in `evaluate_and_execute`, even on a DB-connectivity error, a duplicate
    (already-recorded) row, or any other unexpected failure while trying to record the
    failure. A missing rule_id (should not happen — it is the table's primary key) is a
    no-op: there is nothing to key the audit row on.
    """
    if rule_id is None:
        return
    try:
        async with get_privileged_session() as psession:
            async with psession.begin():
                await append_automation_audit_link(
                    psession,
                    rule_id=rule_id,
                    tenant_id=tenant_id,
                    triggering_event_id=event_id,
                    action_type=action_type or _REDISTRIBUTE_POLICY,
                    disposition="failed",
                    error_reason="unexpected_error",
                )
    except IntegrityError:
        # UNIQUE(rule_id, triggering_event_id) — an executions row for this (rule, event)
        # already exists (e.g. _execute_rule's own audit-append actually succeeded before
        # some LATER, unrelated step raised). Nothing further to record — a normal skip.
        pass
    except Exception:  # noqa: BLE001 - deliberately broad: THIS is the last line of
        # defense: it must never itself raise back into the per-rule loop, no matter what
        # fails while attempting to record the failure (DB connectivity, or anything else).
        logger.error(
            "automation rule best-effort failure-audit append itself failed",
            extra={"rule_id": rule_id, "tenant_id": tenant_id, "event_id": event_id},
        )
