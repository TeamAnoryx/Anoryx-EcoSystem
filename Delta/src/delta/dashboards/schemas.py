"""Dashboard API request/response DTOs (D-008)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..identifiers import AgentId, ProjectId, TeamId, TenantId
from ..money import require_aware_utc

GroupDimension = Literal["team_id", "project_id", "agent_id"]
BucketGranularity = Literal["hour", "day"]

# Bound the window so an operator cannot request an unbounded full-history scan
# (mirrors the D-007 list-pagination guard — a deliberate resource limit, not a
# business rule). 400 days covers a year-plus daily view; a longer horizon needs
# server-side rollups this task does not build (see ADR-0008 honesty boundary).
_MAX_WINDOW_DAYS = 400
_MAX_WINDOW = timedelta(days=_MAX_WINDOW_DAYS)


class DashboardQuery(BaseModel):
    """Shared window + scope parameters ("client/team-set parameters")."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    start: datetime
    end: datetime
    team_id: TeamId | None = None
    project_id: ProjectId | None = None
    agent_id: AgentId | None = None

    @model_validator(mode="after")
    def _validate_window(self) -> "DashboardQuery":
        require_aware_utc(self.start, "start")
        require_aware_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError("end must be strictly after start")
        # Compare the exact timedelta, not .days (which truncates — a window of
        # 400 days + 23h59m has .days == 400 and would silently pass a .days
        # comparison; independent security review finding #2).
        if (self.end - self.start) > _MAX_WINDOW:
            raise ValueError(f"window exceeds the {_MAX_WINDOW_DAYS}-day maximum")
        return self


class SpendSummaryView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_cost_cents: int
    request_count: int
    cost_per_request_cents: float | None
    burn_rate_cents_per_hour: float


class TimeSeriesPointView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bucket_start: datetime
    cost_cents: int
    request_count: int


class GroupSpendView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_key: str
    cost_cents: int
    request_count: int


class TopSpendersQuery(DashboardQuery):
    group_by: GroupDimension
    limit: int = Field(default=10, ge=1, le=100)

    @model_validator(mode="after")
    def _group_by_not_the_active_scope_filter(self) -> "TopSpendersQuery":
        # Grouping by a dimension that is ALSO pinned as a scope filter is a
        # no-op request (every group would be the single pinned value) — reject
        # it explicitly rather than silently returning a one-row "ranking".
        pinned = {
            "team_id": self.team_id,
            "project_id": self.project_id,
            "agent_id": self.agent_id,
        }
        if pinned.get(self.group_by) is not None:
            raise ValueError(f"cannot group_by={self.group_by} while it is also a scope filter")
        return self


class TimeSeriesQuery(DashboardQuery):
    bucket: BucketGranularity = "day"
