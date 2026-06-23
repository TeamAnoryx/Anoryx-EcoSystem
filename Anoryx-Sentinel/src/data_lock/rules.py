"""Data-lock rule parsing (F-017, ADR-0020 §6/§7).

Parses a tenant's ``data_lock`` policy payload into a bounded list of typed rules.

Payload shape (ADR-0020 §6)::

    {"enabled": true,
     "rules": [
        {"field_path": "result.ssn",    "condition": {"type": "time", "unlock_at": "..."}},
        {"field_path": "result.salary", "condition": {"type": "permission",
            "allow": {"project_id": ["proj-finance"], "team_id": ["team-hr"]}}}
     ]}

FAIL-CLOSED parsing: a payload with ANY malformed rule raises
``DataLockRuleError`` — rules are never silently dropped (a dropped rule = a
leaked field).  The config layer converts this raise into the whole-response
fail-closed block (ADR-0020 §4 tier 2).  ``enabled: false`` / missing → not
armed (cheap pass; the tenant did not opt in).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from data_lock.conditions import ConditionError, LockCondition, parse_condition
from data_lock.selector import SelectorError, parse_path

# Max rules per data_lock policy (R7).
MAX_RULES = 100


class DataLockRuleError(ValueError):
    """Raised when the rule payload is malformed/over-cap (fail-closed signal)."""


@dataclass(frozen=True)
class DataLockRule:
    """One parsed lock rule: a bounded path + a typed condition."""

    raw_path: str
    tokens: tuple[str, ...]
    condition: LockCondition


def parse_rules(payload: Any) -> tuple[bool, list[DataLockRule]]:
    """Parse a data_lock policy payload into ``(armed, rules)``.

    ``armed`` is False when the payload disables the feature (``enabled`` falsey)
    — a cheap pass, not an error.  When armed, every rule is validated; any bad
    rule raises ``DataLockRuleError`` (fail-closed — no silent drop).
    """
    if not isinstance(payload, dict):
        raise DataLockRuleError("data_lock payload must be an object")

    if not bool(payload.get("enabled", False)):
        return False, []

    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise DataLockRuleError("data_lock 'rules' must be a list when enabled")
    if len(raw_rules) > MAX_RULES:
        raise DataLockRuleError(f"data_lock 'rules' exceeds {MAX_RULES} entries")

    rules: list[DataLockRule] = []
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise DataLockRuleError(f"rule[{i}] must be an object")
        field_path = raw.get("field_path")
        if not isinstance(field_path, str):
            raise DataLockRuleError(f"rule[{i}].field_path must be a string")
        try:
            tokens = parse_path(field_path)
            condition = parse_condition(raw.get("condition"))
        except (SelectorError, ConditionError) as exc:
            # Wrap into one fail-closed type so the config layer catches a single
            # exception class and blocks the whole response.
            raise DataLockRuleError(f"rule[{i}] invalid: {exc}") from exc
        rules.append(DataLockRule(raw_path=field_path, tokens=tokens, condition=condition))

    return True, rules
