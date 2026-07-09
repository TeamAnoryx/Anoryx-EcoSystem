"""Pure Pydantic validation tests for D-015 PM schemas — no DB, no I/O."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.pm.schemas import (
    MAX_STORY_POINTS,
    SprintCreateRequest,
    SprintStatusUpdateRequest,
    TaskCreateRequest,
    TaskDependencyCreateRequest,
    TaskStatusUpdateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_PROJECT = "22222222-2222-4222-8222-222222222222"
_TASK_A = "33333333-3333-4333-8333-333333333333"
_TASK_B = "44444444-4444-4444-8444-444444444444"
_AWARE_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_AWARE_END = _AWARE_START + timedelta(days=14)


def test_sprint_create_accepts_valid_request() -> None:
    req = SprintCreateRequest(
        tenant_id=_TENANT,
        project_id=_PROJECT,
        name="Sprint 1",
        start_date=_AWARE_START,
        end_date=_AWARE_END,
    )
    assert req.name == "Sprint 1"


def test_sprint_create_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        SprintCreateRequest(
            tenant_id=_TENANT,
            project_id=_PROJECT,
            name="Sprint\n1",
            start_date=_AWARE_START,
            end_date=_AWARE_END,
        )


def test_sprint_create_rejects_naive_start_date() -> None:
    with pytest.raises(ValidationError):
        SprintCreateRequest(
            tenant_id=_TENANT,
            project_id=_PROJECT,
            name="Sprint 1",
            start_date=datetime(2026, 7, 1),  # naive
            end_date=_AWARE_END,
        )


def test_sprint_create_rejects_naive_end_date() -> None:
    with pytest.raises(ValidationError):
        SprintCreateRequest(
            tenant_id=_TENANT,
            project_id=_PROJECT,
            name="Sprint 1",
            start_date=_AWARE_START,
            end_date=datetime(2026, 7, 14),  # naive
        )


def test_sprint_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SprintCreateRequest(
            tenant_id=_TENANT,
            project_id=_PROJECT,
            name="Sprint 1",
            start_date=_AWARE_START,
            end_date=_AWARE_END,
            unexpected="field",
        )


def test_sprint_status_update_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        SprintStatusUpdateRequest(tenant_id=_TENANT, status="cancelled")


def test_task_create_accepts_minimal_valid_request() -> None:
    req = TaskCreateRequest(tenant_id=_TENANT, project_id=_PROJECT, title="Build the widget")
    assert req.story_points is None
    assert req.sprint_id is None


def test_task_create_rejects_control_chars_in_title() -> None:
    with pytest.raises(ValidationError):
        TaskCreateRequest(tenant_id=_TENANT, project_id=_PROJECT, title="Build\x00widget")


def test_task_create_rejects_control_chars_in_assignee() -> None:
    with pytest.raises(ValidationError):
        TaskCreateRequest(
            tenant_id=_TENANT, project_id=_PROJECT, title="Build widget", assignee="Jane\rDoe"
        )


def test_task_create_rejects_negative_story_points() -> None:
    with pytest.raises(ValidationError):
        TaskCreateRequest(
            tenant_id=_TENANT, project_id=_PROJECT, title="Build widget", story_points=-1
        )


def test_task_create_rejects_story_points_above_max() -> None:
    with pytest.raises(ValidationError):
        TaskCreateRequest(
            tenant_id=_TENANT,
            project_id=_PROJECT,
            title="Build widget",
            story_points=MAX_STORY_POINTS + 1,
        )


def test_task_create_rejects_float_story_points() -> None:
    with pytest.raises(ValidationError):
        TaskCreateRequest(
            tenant_id=_TENANT, project_id=_PROJECT, title="Build widget", story_points=3.0
        )


def test_task_status_update_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        TaskStatusUpdateRequest(tenant_id=_TENANT, status="archived")


def test_task_dependency_create_accepts_distinct_tasks() -> None:
    req = TaskDependencyCreateRequest(
        tenant_id=_TENANT, blocking_task_id=_TASK_A, blocked_task_id=_TASK_B
    )
    assert req.blocking_task_id == _TASK_A


def test_task_dependency_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TaskDependencyCreateRequest(
            tenant_id=_TENANT,
            blocking_task_id=_TASK_A,
            blocked_task_id=_TASK_B,
            unexpected="field",
        )
