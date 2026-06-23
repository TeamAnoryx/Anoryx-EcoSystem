"""Unit tests for data_lock.rules (F-017 — bounded, fail-closed rule parsing)."""

from __future__ import annotations

import pytest

from data_lock import rules
from data_lock.rules import DataLockRuleError, parse_rules


def test_disabled_payload_not_armed() -> None:
    armed, parsed = parse_rules({"enabled": False, "rules": [{"x": 1}]})
    assert armed is False
    assert parsed == []


def test_missing_enabled_not_armed() -> None:
    armed, parsed = parse_rules({})
    assert armed is False
    assert parsed == []


def test_valid_payload_parses() -> None:
    armed, parsed = parse_rules(
        {
            "enabled": True,
            "rules": [
                {
                    "field_path": "result.ssn",
                    "condition": {"type": "time", "unlock_at": "2030-01-01T00:00:00Z"},
                },
                {
                    "field_path": "result.salary",
                    "condition": {"type": "permission", "allow": {"team_id": ["team-hr"]}},
                },
            ],
        }
    )
    assert armed is True
    assert len(parsed) == 2
    assert parsed[0].raw_path == "result.ssn"
    assert parsed[0].tokens == ("result", "ssn")


@pytest.mark.parametrize(
    "payload",
    [
        "not-a-dict",
        {"enabled": True},  # rules missing
        {"enabled": True, "rules": "x"},  # rules not a list
        {"enabled": True, "rules": [{"field_path": 123, "condition": {}}]},  # bad path type
        {
            "enabled": True,
            "rules": [
                {
                    "field_path": "a..b",
                    "condition": {"type": "time", "unlock_at": "2030-01-01T00:00:00Z"},
                }
            ],
        },  # bad path
        {
            "enabled": True,
            "rules": [{"field_path": "a.b", "condition": {"type": "approval"}}],
        },  # deferred condition
        {"enabled": True, "rules": [{"field_path": "a.b"}]},  # condition missing
    ],
)
def test_malformed_payload_fails_closed(payload) -> None:
    """Any malformed rule raises — never a silent drop (a dropped rule = leak)."""
    with pytest.raises(DataLockRuleError):
        parse_rules(payload)


def test_too_many_rules_rejected(monkeypatch) -> None:
    monkeypatch.setattr(rules, "MAX_RULES", 2)
    payload = {
        "enabled": True,
        "rules": [
            {
                "field_path": f"a.f{i}",
                "condition": {"type": "time", "unlock_at": "2030-01-01T00:00:00Z"},
            }
            for i in range(3)
        ],
    }
    with pytest.raises(DataLockRuleError):
        parse_rules(payload)
