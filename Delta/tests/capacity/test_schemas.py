"""Pure Pydantic validation tests for D-016 capacity schemas — no DB, no I/O."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.capacity.schemas import (
    MAX_CAPACITY_POINTS,
    TaskTeamAssignRequest,
    TeamCapacityUpdateRequest,
    TeamCreateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_TASK = "22222222-2222-4222-8222-222222222222"
_TEAM = "33333333-3333-4333-8333-333333333333"


def test_team_create_accepts_valid_request() -> None:
    req = TeamCreateRequest(tenant_id=_TENANT, name="Platform Squad", capacity_points_per_sprint=20)
    assert req.capacity_points_per_sprint == 20


def test_team_create_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        TeamCreateRequest(tenant_id=_TENANT, name="Squad\n1", capacity_points_per_sprint=20)


def test_team_create_rejects_negative_capacity() -> None:
    with pytest.raises(ValidationError):
        TeamCreateRequest(tenant_id=_TENANT, name="Squad", capacity_points_per_sprint=-1)


def test_team_create_rejects_capacity_above_max() -> None:
    with pytest.raises(ValidationError):
        TeamCreateRequest(
            tenant_id=_TENANT, name="Squad", capacity_points_per_sprint=MAX_CAPACITY_POINTS + 1
        )


def test_team_create_accepts_zero_capacity() -> None:
    req = TeamCreateRequest(tenant_id=_TENANT, name="Squad", capacity_points_per_sprint=0)
    assert req.capacity_points_per_sprint == 0


def test_team_create_rejects_float_capacity() -> None:
    with pytest.raises(ValidationError):
        TeamCreateRequest(tenant_id=_TENANT, name="Squad", capacity_points_per_sprint=20.0)


def test_team_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TeamCreateRequest(
            tenant_id=_TENANT, name="Squad", capacity_points_per_sprint=20, unexpected="field"
        )


def test_team_capacity_update_rejects_float() -> None:
    with pytest.raises(ValidationError):
        TeamCapacityUpdateRequest(tenant_id=_TENANT, capacity_points_per_sprint=15.5)


def test_task_team_assign_accepts_null_team_id_as_unassignment() -> None:
    req = TaskTeamAssignRequest(tenant_id=_TENANT, team_id=None)
    assert req.team_id is None


def test_task_team_assign_accepts_team_id() -> None:
    req = TaskTeamAssignRequest(tenant_id=_TENANT, team_id=_TEAM)
    assert req.team_id == _TEAM


def test_task_team_assign_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TaskTeamAssignRequest(tenant_id=_TENANT, team_id=_TEAM, unexpected="field")
