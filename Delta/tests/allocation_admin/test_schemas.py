"""D-007 pure schema validation — no DB.

Covers the log-injection guard (control characters in free-text actor/note fields)
added after the independent security review (docs/audit/d-007-security-audit.md
finding #2) and the pagination clamp helper (finding #1).
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from delta.allocation_admin.schemas import AllocationCreateRequest, ApprovalDecisionRequest
from delta.allocation_admin.store import MAX_LIST_LIMIT, _clamp_limit
from delta.budget import BudgetPeriod, BudgetScope


def _valid_create_kwargs(**over: object) -> dict:
    fields: dict = {
        "tenant_id": str(uuid.uuid4()),
        "total_minor_units": 1000,
        "currency": "USD",
        "period": BudgetPeriod.DAILY,
        "targets": [
            {
                "scope": BudgetScope.TEAM,
                "team_id": str(uuid.uuid4()),
                "project_id": str(uuid.uuid4()),
                "agent_id": "gateway-core",
                "amount_minor_units": 1000,
            }
        ],
        "requested_by": "operator-1",
    }
    fields.update(over)
    return fields


def test_requested_by_rejects_embedded_newline() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        AllocationCreateRequest(**_valid_create_kwargs(requested_by="admin\nFORGED LINE"))


def test_actor_rejects_control_character() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        ApprovalDecisionRequest(
            tenant_id=str(uuid.uuid4()), action="approve", actor="op\x1b[31mred"
        )


def test_note_rejects_control_character() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        ApprovalDecisionRequest(
            tenant_id=str(uuid.uuid4()),
            action="approve",
            actor="operator-1",
            note="fine\r\ninjected",
        )


def test_ordinary_actor_and_note_accepted() -> None:
    decision = ApprovalDecisionRequest(
        tenant_id=str(uuid.uuid4()),
        action="approve",
        actor="Jane Doe",
        note="approved after review, within Q3 budget",
    )
    assert decision.actor == "Jane Doe"


def test_clamp_limit_bounds_to_max() -> None:
    assert _clamp_limit(MAX_LIST_LIMIT + 10_000) == MAX_LIST_LIMIT


def test_clamp_limit_bounds_below_one() -> None:
    assert _clamp_limit(0) == 1
    assert _clamp_limit(-5) == 1
