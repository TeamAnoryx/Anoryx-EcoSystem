"""Chargeback/showback + anomaly-detection API DTOs (D-012)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..identifiers import AgentId, ProjectId, TeamId, TenantId
from ..money import require_aware_utc

GroupDimension = Literal["team_id", "project_id", "agent_id"]

# Bound the window so an operator cannot request an unbounded full-history scan
# (mirrors D-008's ADR-0008 window guard — a deliberate resource limit, not a
# business rule).
_MAX_WINDOW_DAYS = 400
_MAX_WINDOW = timedelta(days=_MAX_WINDOW_DAYS)

_DEFAULT_BASELINE_PERIODS = 7
_MAX_BASELINE_PERIODS = 90


class _GroupedWindowQuery(BaseModel):
    """Shared window + group-by + scope parameters (mirrors D-008's DashboardQuery /
    TopSpendersQuery split)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    start: datetime
    end: datetime
    group_by: GroupDimension
    team_id: TeamId | None = None
    project_id: ProjectId | None = None
    agent_id: AgentId | None = None

    @model_validator(mode="after")
    def _validate_window(self) -> "_GroupedWindowQuery":
        require_aware_utc(self.start, "start")
        require_aware_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError("end must be strictly after start")
        # Compare the exact timedelta, not .days (which truncates — D-008's own
        # independent security review finding #2).
        if (self.end - self.start) > _MAX_WINDOW:
            raise ValueError(f"window exceeds the {_MAX_WINDOW_DAYS}-day maximum")
        return self

    @model_validator(mode="after")
    def _group_by_not_the_active_scope_filter(self) -> "_GroupedWindowQuery":
        # Grouping by a dimension that is ALSO pinned as a scope filter is a no-op
        # request (every group would be the single pinned value) — reject it
        # explicitly, mirrors D-008's TopSpendersQuery.
        pinned = {
            "team_id": self.team_id,
            "project_id": self.project_id,
            "agent_id": self.agent_id,
        }
        if pinned.get(self.group_by) is not None:
            raise ValueError(f"cannot group_by={self.group_by} while it is also a scope filter")
        return self


class ChargebackQuery(_GroupedWindowQuery):
    pass


class ChargebackRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_key: str
    cost_cents: int
    request_count: int
    # 0.0-100.0, of total_cost_cents below; 0.0 when total_cost_cents is 0.
    share_pct: float


class ChargebackReportView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_cost_cents: int
    rows: list[ChargebackRow]


class AnomalyQuery(_GroupedWindowQuery):
    # How many equal-length windows immediately preceding [start, end) to average as
    # the baseline. Bounded — a large value means a large window scanned twice over
    # (mirrors D-008's own window-size resource guard).
    baseline_periods: int = Field(default=_DEFAULT_BASELINE_PERIODS, ge=1, le=_MAX_BASELINE_PERIODS)

    @model_validator(mode="after")
    def _bounded_baseline_span(self) -> "AnomalyQuery":
        # baseline_periods alone isn't enough of a bound: a large window combined with
        # a large baseline_periods multiplies out to an unbounded total scan (e.g. a
        # 400-day window x 90 baseline_periods = ~98 years). Cap the TOTAL baseline
        # span the same way the window itself is capped.
        duration = self.end - self.start
        if duration * self.baseline_periods > _MAX_WINDOW:
            raise ValueError(
                f"baseline_periods x window duration exceeds the {_MAX_WINDOW_DAYS}-day "
                "maximum total baseline span"
            )
        return self

    def baseline_window(self) -> tuple[datetime, datetime]:
        """``[baseline_start, start)`` — ``baseline_periods`` windows, each the same
        duration as ``[start, end)``, immediately preceding the current window."""
        duration = self.end - self.start
        baseline_start = self.start - duration * self.baseline_periods
        return baseline_start, self.start


class AnomalyRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_key: str
    current_spend_cents: int
    baseline_avg_cents: float
    ratio: float | None
    code: Literal["SPEND_SPIKE", "NEW_SPENDER"]
    severity: Literal["info", "warning"]


class AnomalyReportView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_periods: int
    baseline_start: datetime
    baseline_end: datetime
    anomalies: list[AnomalyRow]
    # Explicit, honest method tag — a fixed-multiple trailing-average comparison, not a
    # trained/validated statistical or ML model (ADR-0012 honesty boundary). A future
    # different method gets a NEW literal, never a silent redefinition of this one.
    method: Literal["trailing_average_ratio_v1"] = "trailing_average_ratio_v1"
