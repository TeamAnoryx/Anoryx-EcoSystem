"""CONFIRM / vector 8: a Delta BudgetConcept serializes into the LOCKED Sentinel
BudgetLimitPolicy with NO schema change.

This validates a Delta-emitted ``budget_limit`` record against
``Anoryx-Sentinel/contracts/policy.schema.json`` (frozen at F-008 a9e2344) using the
same jsonschema Draft 2020-12 idiom the contract mandates. If this passes, D-002 can
emit budgets without the locked schema moving.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from delta.attribution import budget_concept_to_policy_payload
from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope

_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_SIG = "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc"
_EFF = datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc)


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
    # Sanity: confirm we are validating against the frozen v1 contract, not a copy.
    # The schema has multiple `$comment` keys (json keeps the last), so assert the
    # lock marker against the raw file text, not the parsed dict.
    assert schema["$id"] == "sentinel:policy:v1"
    assert "LOCKED at F-008" in raw
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _concept(**over) -> BudgetConcept:
    base = dict(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500000,
    )
    base.update(over)
    return BudgetConcept(**base)


def _payload(concept: BudgetConcept) -> dict:
    return budget_concept_to_policy_payload(
        concept, policy_id=_POLICY, policy_version=1, effective_from=_EFF, signature=_SIG
    )


def test_cost_only_budget_validates_against_locked_schema(locked_validator):
    record = _payload(_concept(limit_tokens=None, limit_cost_cents=500000))
    errors = sorted(locked_validator.iter_errors(record), key=lambda e: list(e.path))
    assert errors == [], [e.message for e in errors]


def test_tokens_only_budget_validates(locked_validator):
    record = _payload(_concept(limit_tokens=1000, limit_cost_cents=None))
    assert locked_validator.is_valid(record)


def test_both_limits_budget_validates(locked_validator):
    record = _payload(_concept(limit_tokens=1000, limit_cost_cents=500000))
    assert locked_validator.is_valid(record)


def test_integer_cents_satisfies_wire_number_field(locked_validator):
    # The seam: wire max_cost_cents_per_period is a JSON `number`; Delta emits an int.
    record = _payload(_concept(limit_cost_cents=12345))
    assert isinstance(record["max_cost_cents_per_period"], int)
    assert locked_validator.is_valid(record)


@pytest.mark.parametrize("scope", ["tenant", "team", "project", "agent"])
def test_all_scopes_validate(locked_validator, scope):
    record = _payload(_concept(scope=BudgetScope(scope)))
    assert locked_validator.is_valid(record)


def test_validator_actually_bites(locked_validator):
    # Negative control: a record missing required `scope` must fail, proving the
    # validator is really exercising the locked schema (not a no-op).
    record = _payload(_concept())
    del record["scope"]
    assert not locked_validator.is_valid(record)
