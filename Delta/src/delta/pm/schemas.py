"""Project-management API request/response DTOs (D-015, ADR-0015).

A deliberately bounded vertical slice: sprints, tasks, a dependency graph, a
sprint-velocity aggregate, and a deterministic blocking-fan-out bottleneck heuristic —
not the roadmap's literal "real-time... execution-bottleneck prediction" (no push
updates, no trained/validated ML; see ADR-0015 §3).

Mirrors D-013's `crm.schemas`/D-014's `erp.schemas` conventions throughout:
`extra="forbid"`, bounded free text with control-character rejection,
`require_aware_utc` timestamps, `reject_non_integer` on every count/points field.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import ProjectId, SprintId, TaskDependencyId, TaskId, TenantId
from ..money import reject_non_integer, require_aware_utc

SprintStatus = Literal["planned", "active", "completed"]
TaskStatus = Literal["todo", "in_progress", "done", "blocked"]

_NAME_MAX_LENGTH = 256
_ASSIGNEE_MAX_LENGTH = 128
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# A task's story-point count is bounded — no real sprint carries an unbounded number
# of points on one task (mirrors D-013/D-014's own bounded-integer-field discipline).
MAX_STORY_POINTS = 1000

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# The bottleneck report and the cycle-freedom check both need a bound on how many
# dependency edges are considered per request — a real project's dependency graph is
# small; this guards against a pathologically large one turning either into an
# unbounded scan (ADR-0015 §4).
MAX_DEPENDENCY_EDGES_CONSIDERED = 2000


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class SprintCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    project_id: ProjectId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    start_date: datetime
    end_date: datetime

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("start_date")
    @classmethod
    def _start_date_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "start_date")

    @field_validator("end_date")
    @classmethod
    def _end_date_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "end_date")


class SprintStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    status: SprintStatus


class SprintView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sprint_id: SprintId
    tenant_id: TenantId
    project_id: ProjectId
    name: str
    start_date: datetime
    end_date: datetime
    status: SprintStatus
    created_at: datetime
    updated_at: datetime


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    project_id: ProjectId
    sprint_id: SprintId | None = None
    title: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    story_points: int | None = Field(default=None, ge=0, le=MAX_STORY_POINTS)
    assignee: str | None = Field(default=None, max_length=_ASSIGNEE_MAX_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "title")

    @field_validator("assignee")
    @classmethod
    def _assignee_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "assignee")

    @field_validator("story_points", mode="before")
    @classmethod
    def _story_points_strict_integer(cls, value: object) -> object:
        return value if value is None else reject_non_integer(value, "story_points")


class TaskStatusUpdateRequest(BaseModel):
    """Task status is NOT forward-only (unlike D-013's deal stages / D-014's asset
    lifecycle) — a task can be reopened. `completed_at` is stamped/cleared alongside
    the transition to/from 'done' (ADR-0015 Fork 2)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    status: TaskStatus


class TaskView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    tenant_id: TenantId
    project_id: ProjectId
    sprint_id: SprintId | None
    title: str
    status: TaskStatus
    story_points: int | None
    assignee: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class TaskDependencyCreateRequest(BaseModel):
    """`blocking_task_id` must complete before `blocked_task_id` can proceed. Rejected
    if it would create a cycle (ADR-0015 Fork 3) or reference the same task twice."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    blocking_task_id: TaskId
    blocked_task_id: TaskId


class TaskDependencyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dependency_id: TaskDependencyId
    tenant_id: TenantId
    blocking_task_id: TaskId
    blocked_task_id: TaskId
    created_at: datetime


class SprintVelocityRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sprint_id: SprintId
    sprint_name: str
    status: SprintStatus
    completed_story_points: int
    completed_task_count: int
    total_task_count: int


class VelocityReportView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: ProjectId
    sprints: list[SprintVelocityRow]


class BottleneckRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    title: str
    status: TaskStatus
    blocking_count: int


class BottleneckReportView(BaseModel):
    """A fixed blocking-fan-out ranking, not a trained/validated statistical or ML
    prediction model — same honesty-boundary discipline as D-011/D-012/D-013's own
    `method` literals."""

    model_config = ConfigDict(extra="forbid")

    project_id: ProjectId
    bottlenecks: list[BottleneckRow]
    method: Literal["blocking_fanout_v1"] = "blocking_fanout_v1"
