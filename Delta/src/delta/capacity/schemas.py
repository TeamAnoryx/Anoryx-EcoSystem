"""Team-capacity API request/response DTOs (D-016, ADR-0016).

A deliberately bounded vertical slice: teams with an operator-declared per-sprint
story-point capacity, task-to-team assignment, a deterministic utilization report, and
an advisory (never automatic) rebalancing suggestion — not the roadmap's literal
"squad performance... automated resource allocation... real-time utilization to
prevent burnout" (no individual-level capacity/PTO data exists anywhere in Delta, no
burnout/wellbeing signal, no automatic task reassignment, no real-time push; see
ADR-0016 §3).

Mirrors D-015's `pm.schemas` conventions throughout: `extra="forbid"`, bounded free
text with control-character rejection, `reject_non_integer` on the capacity field.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import ProjectId, SprintId, TaskId, TeamId, TenantId
from ..money import reject_non_integer

_NAME_MAX_LENGTH = 256
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# A team's declared capacity is bounded — no real squad carries an unbounded
# story-point budget per sprint (mirrors D-015's own MAX_STORY_POINTS discipline).
MAX_CAPACITY_POINTS = 10_000

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class TeamCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    capacity_points_per_sprint: int = Field(ge=0, le=MAX_CAPACITY_POINTS)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("capacity_points_per_sprint", mode="before")
    @classmethod
    def _capacity_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "capacity_points_per_sprint")


class TeamCapacityUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    capacity_points_per_sprint: int = Field(ge=0, le=MAX_CAPACITY_POINTS)

    @field_validator("capacity_points_per_sprint", mode="before")
    @classmethod
    def _capacity_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "capacity_points_per_sprint")


class TeamView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team_id: TeamId
    tenant_id: TenantId
    name: str
    capacity_points_per_sprint: int
    created_at: datetime
    updated_at: datetime


class TaskTeamAssignRequest(BaseModel):
    """`team_id: null` unassigns the task from any team (it stops counting toward
    any team's utilization)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    team_id: TeamId | None = None


class TaskAssignmentView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    tenant_id: TenantId
    team_id: TeamId | None


class TaskCapacityView(BaseModel):
    """A task's capacity-relevant fields for one sprint — `delta.pm`'s own
    `TaskView` does not expose `team_id`, so the capacity UI reads through this
    endpoint instead of `/v1/admin/pm/tasks` whenever it needs to show or change a
    task's current team assignment."""

    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    title: str
    status: str
    story_points: int | None
    team_id: TeamId | None


class UtilizationRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team_id: TeamId
    team_name: str
    capacity_points_per_sprint: int
    total_assigned_points: int
    remaining_points: int
    # `None` when capacity is 0 and there is remaining (unbounded-ratio) work — an
    # honest "undefined", never a silently-wrong number (e.g. divide-by-zero to inf).
    utilization_ratio: float | None


class UtilizationReportView(BaseModel):
    """A deterministic ratio (`remaining assigned story points / declared team
    capacity`), not a trained/validated statistical or ML prediction — same
    honesty-boundary discipline as D-011/D-012/D-013/D-015's own `method` literals.
    Does NOT measure burnout, wellbeing, or individual workload — Delta has no such
    data (ADR-0016 §3)."""

    model_config = ConfigDict(extra="forbid")

    project_id: ProjectId
    sprint_id: SprintId
    teams: list[UtilizationRow]
    method: Literal["capacity_ratio_v1"] = "capacity_ratio_v1"


class RebalanceSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    title: str
    story_points: int
    from_team_id: TeamId
    from_team_name: str
    to_team_id: TeamId
    to_team_name: str


class RebalanceReportView(BaseModel):
    """A deterministic greedy suggestion (move the largest not-done tasks from
    over-capacity teams to under-capacity teams until balanced or exhausted) — purely
    advisory. Nothing is moved automatically; an operator applies a suggestion
    explicitly via `POST /v1/admin/capacity/tasks/{task_id}/team`. Not a trained/
    validated ML optimization (ADR-0016 §3)."""

    model_config = ConfigDict(extra="forbid")

    project_id: ProjectId
    sprint_id: SprintId
    suggestions: list[RebalanceSuggestion]
    method: Literal["greedy_rebalance_v1"] = "greedy_rebalance_v1"
