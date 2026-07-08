"""Kill/clear payloads are byte-valid against the UNMODIFIED locked
``policy.schema.json`` (ADR-0006 §3.5, vector 8) — no schema change, no new policy_type,
same D-002 emit vehicle D-005 already proved valid.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from delta.kill_switch.emit import build_clear_payload, build_kill_payload
from delta.money import MAX_BUDGET_COST_CENTS, MAX_BUDGET_TOKENS

_TENANT = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_NOW = datetime(2026, 7, 7, 0, 0, 0, tzinfo=timezone.utc)


def _locked_policy_schema_path() -> Path:
    override = os.environ.get("SENTINEL_POLICY_SCHEMA_PATH")
    if override:
        return Path(override)
    return (
        Path(__file__).resolve().parents[3] / "Anoryx-Sentinel" / "contracts" / "policy.schema.json"
    )


@pytest.fixture(scope="module")
def locked_validator() -> Draft202012Validator:
    path = _locked_policy_schema_path()
    assert path.exists(), f"LOCKED Sentinel policy schema not found at {path}"
    raw = path.read_text(encoding="utf-8")
    schema = json.loads(raw)
    assert schema["$id"] == "sentinel:policy:v1"
    assert "LOCKED at F-008" in raw
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def test_kill_payload_is_valid_zero_cap_budget_limit(locked_validator):
    record = build_kill_payload(
        tenant_id=_TENANT,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="rogue-agent",
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_NOW,
    )
    errors = sorted(locked_validator.iter_errors(record), key=lambda e: list(e.path))
    assert errors == [], [e.message for e in errors]
    assert record["policy_type"] == "budget_limit"
    assert record["scope"] == "agent"
    assert record["max_tokens_per_period"] == 0
    assert record["max_cost_cents_per_period"] == 0


def test_clear_payload_is_valid_max_cap_budget_limit(locked_validator):
    record = build_clear_payload(
        tenant_id=_TENANT,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="rogue-agent",
        policy_id=_POLICY,
        policy_version=2,
        effective_from=_NOW,
    )
    errors = sorted(locked_validator.iter_errors(record), key=lambda e: list(e.path))
    assert errors == [], [e.message for e in errors]
    assert record["max_tokens_per_period"] == MAX_BUDGET_TOKENS
    assert record["max_cost_cents_per_period"] == MAX_BUDGET_COST_CENTS


def test_kill_and_clear_share_policy_id_different_version(locked_validator):
    kill = build_kill_payload(
        tenant_id=_TENANT,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="rogue-agent",
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_NOW,
    )
    clear = build_clear_payload(
        tenant_id=_TENANT,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="rogue-agent",
        policy_id=_POLICY,
        policy_version=2,
        effective_from=_NOW,
    )
    assert kill["policy_id"] == clear["policy_id"] == _POLICY
    assert clear["policy_version"] > kill["policy_version"]
