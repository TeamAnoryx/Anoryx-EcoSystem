"""The published policy is byte-valid against the UNMODIFIED locked schema (ADR-0005 §4).

Loads the real Sentinel ``policy.schema.json`` (asserting the lock marker) and validates the
``build_policy_payload`` output — the central D-005 artifact. ``policy_type`` stays
``budget_limit`` (no new type, CRIT-2) and no advisory key leaks into the signed record
(CONFIRM B).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from delta.budget import BudgetPeriod, BudgetScope
from delta.budget_engine.definitions import BudgetDefinition
from delta.budget_engine.emit import build_policy_payload

_LOCKED_SCHEMA = (
    Path(__file__).resolve().parents[3] / "Anoryx-Sentinel" / "contracts" / "policy.schema.json"
)
_ADVISORY_KEYS = frozenset({"warnings", "threshold_percent", "threshold_cost_cents", "action"})


@pytest.fixture(scope="module")
def locked_validator() -> Draft202012Validator:
    raw = _LOCKED_SCHEMA.read_text(encoding="utf-8")
    schema = json.loads(raw)
    assert schema["$id"] == "sentinel:policy:v1"
    assert "LOCKED at F-008" in raw
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _budget(
    *,
    scope: BudgetScope = BudgetScope.TEAM,
    period: BudgetPeriod = BudgetPeriod.DAILY,
    limit_cost_cents: int | None = 500_000,
    limit_tokens: int | None = None,
) -> BudgetDefinition:
    return BudgetDefinition(
        budget_id="b0000000-0000-4000-8000-000000000000",
        tenant_id="11111111-1111-4111-8111-111111111111",
        scope=scope,
        team_id="22222222-2222-4222-8222-222222222222",
        project_id="33333333-3333-4333-8333-333333333333",
        agent_id="gateway-core",
        period=period,
        limit_tokens=limit_tokens,
        limit_cost_cents=limit_cost_cents,
        currency="USD",
        policy_id="44444444-4444-4444-8444-444444444444",
    )


def test_built_cost_cap_payload_is_byte_valid(locked_validator):
    payload = build_policy_payload(
        _budget(), policy_version=3, effective_from=datetime(2026, 7, 1, tzinfo=timezone.utc)
    )
    errors = sorted(locked_validator.iter_errors(payload), key=lambda e: list(e.path))
    assert errors == [], [e.message for e in errors]
    assert payload["policy_type"] == "budget_limit"
    assert payload["max_cost_cents_per_period"] == 500_000
    assert payload["scope"] == "team"
    assert payload["period"] == "daily"
    assert payload["effective_from"].endswith("Z")


@pytest.mark.parametrize("scope", list(BudgetScope))
@pytest.mark.parametrize("period", list(BudgetPeriod))
def test_all_scope_period_combos_byte_valid(locked_validator, scope, period):
    payload = build_policy_payload(
        _budget(scope=scope, period=period),
        policy_version=1,
        effective_from=datetime(2026, 7, 1, tzinfo=timezone.utc),
    )
    assert locked_validator.is_valid(payload), list(locked_validator.iter_errors(payload))


def test_token_only_cap_byte_valid(locked_validator):
    payload = build_policy_payload(
        _budget(limit_cost_cents=None, limit_tokens=1_000_000),
        policy_version=1,
        effective_from=datetime(2026, 7, 1, tzinfo=timezone.utc),
    )
    assert locked_validator.is_valid(payload), list(locked_validator.iter_errors(payload))
    assert payload["max_tokens_per_period"] == 1_000_000


def test_no_advisory_key_in_published_payload(locked_validator):
    payload = build_policy_payload(
        _budget(), policy_version=1, effective_from=datetime(2026, 7, 1, tzinfo=timezone.utc)
    )
    assert _ADVISORY_KEYS.isdisjoint(payload.keys())


def test_locked_schema_is_byte_untouched():
    """D-005 must not edit the locked schema (CRIT-2 / the lock)."""
    raw = _LOCKED_SCHEMA.read_text(encoding="utf-8")
    assert '"$id": "sentinel:policy:v1"' in raw
    assert "LOCKED at F-008 commit a9e2344" in raw
