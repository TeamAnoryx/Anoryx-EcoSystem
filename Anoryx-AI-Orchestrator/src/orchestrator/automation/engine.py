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
  * A genuine per-rule execution failure (`drive_distribution` raising — which per its own
    docstring only happens for an unexpected logic defect, never an ordinary per-target
    delivery failure) is caught, recorded as a `failed` audit link, and logged at
    `logger.error` with rule_id/tenant_id/event_id (NEVER the payload) — it must never
    propagate back into FastAPI's BackgroundTasks machinery (the request already returned
    202; there is nothing left to fail visibly to the caller).
  * The audit-append call itself is wrapped in the SAME narrow DB-connectivity exception
    family already defined in distribution/engine.py (`_DB_CONNECTIVITY_ERRORS`) so a
    transient DB blip recording the audit link does not crash the background task.
  * The UNIQUE(rule_id, triggering_event_id) IntegrityError on that same insert is the
    idempotency dedup gate — caught narrowly and treated as "already executed, skip", a
    normal outcome, never an error.
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
    engine ships OFF by default (ADR-0011). Never raises: this runs as a FastAPI
    BackgroundTask AFTER the ingest request already returned 202, so there is no HTTP
    response left to fail; every foreseeable failure mode is caught and logged internally
    (never the payload) rather than propagated.
    """
    if not automation_settings.enabled:
        return

    async with get_tenant_session(tenant_id) as session:
        rules = await list_enabled_automation_rules(
            session, tenant_id=tenant_id, event_type=event_type
        )

    for rule in rules:
        if not rule_matches(
            rule, event_type=event_type, source_product=source_product, payload=payload
        ):
            continue
        await _execute_rule(
            rule,
            tenant_id=tenant_id,
            event_id=event_id,
            distribution_settings=distribution_settings,
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
