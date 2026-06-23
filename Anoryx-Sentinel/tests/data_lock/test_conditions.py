"""Unit tests for data_lock.conditions (F-017 vectors 2, 3, 7).

Server-authoritative condition evaluation: TIME uses the server clock only,
PERMISSION matches the server-resolved identity only. No caller-supplied value
participates at this layer (the function signature has no such parameter).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from data_lock.conditions import (
    ConditionError,
    PermissionCondition,
    TimeCondition,
    evaluate,
    parse_condition,
)

_IDS = {"team_id": "team-a", "project_id": "proj-a", "agent_id": "agent-a"}


# --- parse_condition -------------------------------------------------------


def test_parse_time_condition_ok() -> None:
    cond = parse_condition({"type": "time", "unlock_at": "2030-01-01T00:00:00Z"})
    assert isinstance(cond, TimeCondition)
    assert cond.unlock_at.tzinfo is not None


def test_parse_permission_condition_ok() -> None:
    cond = parse_condition({"type": "permission", "allow": {"team_id": ["team-a", "team-b"]}})
    assert isinstance(cond, PermissionCondition)
    assert ("team_id", "team-a") in cond.allow_pairs


@pytest.mark.parametrize(
    "raw",
    [
        {"type": "approval", "approver": "x"},  # deferred (Fork 4) → unsupported
        {"type": "unknown"},
        {"type": "time"},  # missing unlock_at
        {"type": "time", "unlock_at": "2030-01-01T00:00:00"},  # naive (no tz) → rejected
        {"type": "time", "unlock_at": "not-a-date"},
        {"type": "permission"},  # missing allow
        {"type": "permission", "allow": {}},  # empty allow
        {
            "type": "permission",
            "allow": {"role": ["admin"]},
        },  # invalid attr (no RBAC on data plane)
        {"type": "permission", "allow": {"team_id": []}},  # empty value list
        {"type": "permission", "allow": {"team_id": [""]}},  # empty value
        "not-an-object",
    ],
)
def test_parse_condition_rejects_malformed(raw) -> None:
    with pytest.raises(ConditionError):
        parse_condition(raw)


# --- evaluate: TIME (vectors 3, 7) ----------------------------------------


def test_time_past_releases() -> None:
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    cond = parse_condition({"type": "time", "unlock_at": past})
    assert evaluate(cond, **_IDS) is True  # condition met → release


def test_time_future_withholds() -> None:
    future = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    cond = parse_condition({"type": "time", "unlock_at": future})
    assert evaluate(cond, **_IDS) is False  # not yet → withhold


def test_time_uses_server_clock_not_caller_input() -> None:
    """Vector 3: evaluate takes no caller time; only the server clock decides."""
    import inspect

    params = set(inspect.signature(evaluate).parameters)
    # The only inputs are the condition + the three server-resolved identity IDs.
    assert params == {"condition", "team_id", "project_id", "agent_id"}


# --- evaluate: PERMISSION (vector 2) --------------------------------------


def test_permission_match_releases() -> None:
    cond = parse_condition({"type": "permission", "allow": {"project_id": ["proj-a"]}})
    assert evaluate(cond, **_IDS) is True


def test_permission_no_match_withholds() -> None:
    cond = parse_condition({"type": "permission", "allow": {"project_id": ["proj-OTHER"]}})
    assert evaluate(cond, **_IDS) is False


def test_permission_or_across_attributes() -> None:
    # Allows by team OR project; caller matches team only → release.
    cond = parse_condition(
        {"type": "permission", "allow": {"team_id": ["team-a"], "project_id": ["proj-OTHER"]}}
    )
    assert evaluate(cond, **_IDS) is True


def test_permission_caller_cannot_satisfy_with_other_identity() -> None:
    """Vector 2 (unit level): only the passed server-resolved IDs are matched;
    a value the caller might try to inject elsewhere is irrelevant here."""
    cond = parse_condition({"type": "permission", "allow": {"agent_id": ["privileged-agent"]}})
    # Caller's real agent_id is 'agent-a' → withhold, regardless of any body claim.
    assert evaluate(cond, **_IDS) is False
