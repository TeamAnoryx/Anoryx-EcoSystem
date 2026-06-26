"""D-002 reason-for-being: a BudgetPolicy WITH advisory warnings emits a hard-cap
``budget_limit`` record that is byte-valid against the UNMODIFIED LOCKED Sentinel
``policy.schema.json`` — and the warnings NEVER leak into the signed record.

This re-uses the same Draft 2020-12 idiom + lock-marker assertion as the D-001
``test_budget_variant_roundtrip.py`` so it validates against the frozen v1
contract, not a copy.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_policy import BudgetPolicy, BudgetWarningTier, WarningAction

_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_SIG = "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc"
_EFF = datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc)

# Keys that belong ONLY to the Delta-side advisory layer; none may appear in the
# emitted signed record (the locked variant is additionalProperties:false anyway,
# but we assert the drop directly, not just rely on the schema biting).
_ADVISORY_KEYS = frozenset({"warnings", "threshold_percent", "threshold_cost_cents", "action"})


def _locked_policy_schema_path() -> Path:
    override = os.environ.get("SENTINEL_POLICY_SCHEMA_PATH")
    if override:
        return Path(override)
    # Delta/tests -> Delta -> <repo root> -> Anoryx-Sentinel/contracts/policy.schema.json
    return (
        Path(__file__).resolve().parents[2] / "Anoryx-Sentinel" / "contracts" / "policy.schema.json"
    )


@pytest.fixture(scope="module")
def locked_validator() -> Draft202012Validator:
    path = _locked_policy_schema_path()
    assert path.exists(), f"LOCKED Sentinel policy schema not found at {path}"
    raw = path.read_text(encoding="utf-8")
    schema = json.loads(raw)
    # Confirm we validate against the frozen v1 contract (assert the lock marker on
    # the raw text — the schema has multiple `$comment` keys, json keeps the last).
    assert schema["$id"] == "sentinel:policy:v1"
    assert "LOCKED at F-008" in raw
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _cap(**over) -> BudgetConcept:
    base = dict(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500_000,
    )
    base.update(over)
    return BudgetConcept(**base)


def _policy(cap: BudgetConcept, warnings=()) -> BudgetPolicy:
    return BudgetPolicy(
        cap=cap, policy_id=_POLICY, policy_version=1, effective_from=_EFF, warnings=warnings
    )


def test_policy_with_warnings_emits_valid_budget_limit(locked_validator):
    policy = _policy(
        _cap(),
        warnings=(
            BudgetWarningTier(threshold_percent=80, action=WarningAction.NOTIFY),
            BudgetWarningTier(threshold_percent=95, action=WarningAction.PAGE),
        ),
    )
    record = policy.to_policy_payload(signature=_SIG)
    errors = sorted(locked_validator.iter_errors(record), key=lambda e: list(e.path))
    assert errors == [], [e.message for e in errors]


def test_emitted_record_has_no_advisory_keys(locked_validator):
    policy = _policy(
        _cap(),
        warnings=(BudgetWarningTier(threshold_cost_cents=400_000, action=WarningAction.ALERT),),
    )
    record = policy.to_policy_payload(signature=_SIG)
    assert _ADVISORY_KEYS.isdisjoint(record.keys())
    # And the record still validates (the drop did not corrupt the cap).
    assert locked_validator.is_valid(record)


def test_emitted_record_is_a_budget_limit(locked_validator):
    record = _policy(_cap()).to_policy_payload(signature=_SIG)
    assert record["policy_type"] == "budget_limit"
    assert locked_validator.is_valid(record)


def test_integer_cents_satisfies_wire_number_field(locked_validator):
    record = _policy(_cap(limit_cost_cents=12_345)).to_policy_payload(signature=_SIG)
    assert isinstance(record["max_cost_cents_per_period"], int)
    assert locked_validator.is_valid(record)


@pytest.mark.parametrize("scope", ["tenant", "team", "project", "agent"])
def test_all_scopes_resolve_one_to_one(locked_validator, scope):
    record = _policy(_cap(scope=BudgetScope(scope))).to_policy_payload(signature=_SIG)
    assert record["scope"] == scope
    # the four identity fields are carried verbatim (cross-check; F-008 resolves
    # the authoritative scope from the signature server-side).
    assert record["tenant_id"] == _T
    assert record["team_id"] == _TEAM
    assert record["project_id"] == _PROJ
    assert record["agent_id"] == "gateway-core"
    assert locked_validator.is_valid(record)


def test_non_utc_effective_from_normalizes_to_z(locked_validator):
    # Awareness is required at construction; UTC normalization happens at emit.
    # +05:00 at 05:00 local -> 00:00:00Z on the wire.
    eff = datetime(2026, 6, 26, 5, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    record = BudgetPolicy(
        cap=_cap(), policy_id=_POLICY, policy_version=1, effective_from=eff
    ).to_policy_payload(signature=_SIG)
    assert record["effective_from"] == "2026-06-26T00:00:00Z"
    assert locked_validator.is_valid(record)


def test_bad_signature_rejected_before_emit():
    # The emit path reuses D-001's envelope guard: a non-JWS signature never emits.
    with pytest.raises(ValueError, match="signature"):
        _policy(_cap()).to_policy_payload(signature="not-a-jws")


def test_validator_actually_bites(locked_validator):
    # Negative control: drop required `scope` -> the locked schema must reject,
    # proving the validator exercises the real contract (not a no-op).
    record = _policy(_cap()).to_policy_payload(signature=_SIG)
    del record["scope"]
    assert not locked_validator.is_valid(record)
