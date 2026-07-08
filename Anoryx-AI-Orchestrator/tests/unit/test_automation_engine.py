"""Unit tests for `evaluate_and_execute`'s per-rule isolation + narrow DB-connectivity
catch (O-011 code-reviewer follow-up, item 2). No real DB — `get_tenant_session` /
`get_privileged_session` and the repo-layer calls imported by name into
`automation.engine` are monkeypatched at the module boundary, mirroring
test_automation_router.py's pattern. The full, non-stubbed matched-execution path is
already proven by tests/integration/test_automation_e2e.py; this file is scoped to the
loop-isolation + narrow-catch orchestration logic added by this follow-up.
"""

from __future__ import annotations

import contextlib

import sqlalchemy.exc
from sqlalchemy.exc import IntegrityError

from orchestrator.automation import engine as automation_engine
from orchestrator.config import AutomationSettings, DistributionSettings

_TENANT = "tenant-1"
_EVENT_TYPE = "policy_decision_deny"


def _automation_settings(**overrides) -> AutomationSettings:
    base = {"enabled": True, "max_rules_per_tenant": 20}
    base.update(overrides)
    return AutomationSettings(**base)


def _distribution_settings(**overrides) -> DistributionSettings:
    base = {
        "service_token": None,
        "sentinel_admin_token": "admin-token",
        "targets": {},
        "intake_path": "/admin/policies/intake",
        "max_attempts": 1,
        "backoff_seconds": 0.0,
        "http_timeout_seconds": 1.0,
    }
    base.update(overrides)
    return DistributionSettings(**base)


def _rule(rule_id: str, *, distribution_id: str = "dist-a") -> dict:
    return {
        "id": rule_id,
        "tenant_id": _TENANT,
        "trigger_event_type": _EVENT_TYPE,
        "trigger_source_product": None,
        "trigger_conditions": {},
        "action_type": "redistribute_policy",
        "action_config": {"distribution_id": distribution_id},
    }


def _patch_tenant_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield object()

    monkeypatch.setattr(automation_engine, "get_tenant_session", _fake)


def _patch_rules(monkeypatch, rules=None, *, raise_exc: Exception | None = None):
    async def _list_enabled_automation_rules(_session, *, tenant_id, event_type):
        if raise_exc is not None:
            raise raise_exc
        return rules or []

    monkeypatch.setattr(
        automation_engine, "list_enabled_automation_rules", _list_enabled_automation_rules
    )


# --------------------------------------------------------------------------- #
# Master switch off — no-op regardless of what the rule lookup would have done.
# --------------------------------------------------------------------------- #


async def test_master_switch_off_never_reaches_the_db(monkeypatch):
    async def _boom(*_args, **_kwargs):
        raise AssertionError("must not be called when the master switch is off")

    monkeypatch.setattr(automation_engine, "get_tenant_session", _boom)
    monkeypatch.setattr(automation_engine, "list_enabled_automation_rules", _boom)

    await automation_engine.evaluate_and_execute(
        tenant_id=_TENANT,
        event_id="evt-1",
        event_type=_EVENT_TYPE,
        source_product="sentinel",
        payload={},
        automation_settings=_automation_settings(enabled=False),
        distribution_settings=_distribution_settings(),
    )


# --------------------------------------------------------------------------- #
# Item 2a — a DB-connectivity blip loading rules never crashes the background task.
# --------------------------------------------------------------------------- #


async def test_db_connectivity_error_loading_rules_is_caught_not_raised(monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_rules(monkeypatch, raise_exc=sqlalchemy.exc.OperationalError("x", {}, Exception("x")))

    execute_calls: list[str] = []

    async def _execute_rule(rule, **_kwargs):
        execute_calls.append(rule["id"])

    monkeypatch.setattr(automation_engine, "_execute_rule", _execute_rule)

    # Must not raise.
    await automation_engine.evaluate_and_execute(
        tenant_id=_TENANT,
        event_id="evt-1",
        event_type=_EVENT_TYPE,
        source_product="sentinel",
        payload={},
        automation_settings=_automation_settings(),
        distribution_settings=_distribution_settings(),
    )
    assert execute_calls == []  # never reached the per-rule loop


async def test_non_connectivity_error_loading_rules_still_propagates(monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_rules(monkeypatch, raise_exc=sqlalchemy.exc.ProgrammingError("x", {}, Exception("x")))

    try:
        await automation_engine.evaluate_and_execute(
            tenant_id=_TENANT,
            event_id="evt-1",
            event_type=_EVENT_TYPE,
            source_product="sentinel",
            payload={},
            automation_settings=_automation_settings(),
            distribution_settings=_distribution_settings(),
        )
        raised = False
    except sqlalchemy.exc.ProgrammingError:
        raised = True
    assert raised  # a genuine logic defect is NOT silently swallowed


# --------------------------------------------------------------------------- #
# Item 2b — one matched rule's unexpected failure never aborts the remaining rules.
# --------------------------------------------------------------------------- #


async def test_one_rule_unexpected_failure_does_not_abort_remaining_rules(monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_rules(monkeypatch, rules=[_rule("rule-1"), _rule("rule-2")])

    executed: list[str] = []

    async def _execute_rule(rule, **_kwargs):
        executed.append(rule["id"])
        if rule["id"] == "rule-1":
            raise RuntimeError("an unexpected logic defect, not IntegrityError/connectivity")

    recorded_failures: list[str] = []

    async def _record_unexpected_failure(*, rule_id, tenant_id, event_id, action_type):
        recorded_failures.append(rule_id)

    monkeypatch.setattr(automation_engine, "_execute_rule", _execute_rule)
    monkeypatch.setattr(automation_engine, "_record_unexpected_failure", _record_unexpected_failure)

    await automation_engine.evaluate_and_execute(
        tenant_id=_TENANT,
        event_id="evt-1",
        event_type=_EVENT_TYPE,
        source_product="sentinel",
        payload={},
        automation_settings=_automation_settings(),
        distribution_settings=_distribution_settings(),
    )

    # BOTH rules were evaluated — rule-1's unhandled failure never aborted the loop.
    assert executed == ["rule-1", "rule-2"]
    # A best-effort failure record was attempted for the rule that raised, and ONLY that
    # one (rule-2 succeeded, so no failure record is attempted for it).
    assert recorded_failures == ["rule-1"]


async def test_non_matching_rule_never_calls_execute_rule(monkeypatch):
    _patch_tenant_session(monkeypatch)
    non_matching = _rule("rule-1")
    non_matching["trigger_event_type"] = "some_other_event_type"
    _patch_rules(monkeypatch, rules=[non_matching])

    async def _boom(*_args, **_kwargs):
        raise AssertionError("must not execute a non-matching rule")

    monkeypatch.setattr(automation_engine, "_execute_rule", _boom)

    await automation_engine.evaluate_and_execute(
        tenant_id=_TENANT,
        event_id="evt-1",
        event_type=_EVENT_TYPE,
        source_product="sentinel",
        payload={},
        automation_settings=_automation_settings(),
        distribution_settings=_distribution_settings(),
    )


# --------------------------------------------------------------------------- #
# _record_unexpected_failure — the last line of defense never raises itself.
# --------------------------------------------------------------------------- #


class _FakePrivilegedSession:
    @contextlib.asynccontextmanager
    async def begin(self):
        yield None


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield _FakePrivilegedSession()

    monkeypatch.setattr(automation_engine, "get_privileged_session", _fake)


async def test_record_unexpected_failure_writes_a_failed_row(monkeypatch):
    _patch_privileged_session(monkeypatch)
    appended = []

    async def _append_automation_audit_link(_session, **kwargs):
        appended.append(kwargs)

    monkeypatch.setattr(
        automation_engine, "append_automation_audit_link", _append_automation_audit_link
    )

    await automation_engine._record_unexpected_failure(
        rule_id="rule-1", tenant_id=_TENANT, event_id="evt-1", action_type="redistribute_policy"
    )
    assert len(appended) == 1
    assert appended[0]["disposition"] == "failed"
    assert appended[0]["error_reason"] == "unexpected_error"
    assert appended[0]["rule_id"] == "rule-1"


async def test_record_unexpected_failure_swallows_integrity_error(monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _append_automation_audit_link(_session, **_kwargs):
        raise IntegrityError("insert", {}, Exception("duplicate"))

    monkeypatch.setattr(
        automation_engine, "append_automation_audit_link", _append_automation_audit_link
    )

    # Must not raise.
    await automation_engine._record_unexpected_failure(
        rule_id="rule-1", tenant_id=_TENANT, event_id="evt-1", action_type="redistribute_policy"
    )


async def test_record_unexpected_failure_swallows_any_other_error(monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _append_automation_audit_link(_session, **_kwargs):
        raise sqlalchemy.exc.OperationalError("x", {}, Exception("x"))

    monkeypatch.setattr(
        automation_engine, "append_automation_audit_link", _append_automation_audit_link
    )

    # Must not raise — this IS the last line of defense.
    await automation_engine._record_unexpected_failure(
        rule_id="rule-1", tenant_id=_TENANT, event_id="evt-1", action_type="redistribute_policy"
    )


async def test_record_unexpected_failure_is_a_noop_without_a_rule_id(monkeypatch):
    async def _boom():
        raise AssertionError("must not open a privileged session without a rule_id")

    monkeypatch.setattr(automation_engine, "get_privileged_session", _boom)

    await automation_engine._record_unexpected_failure(
        rule_id=None, tenant_id=_TENANT, event_id="evt-1", action_type="redistribute_policy"
    )
