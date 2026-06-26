"""Usage records and time windows (Fork 3: Delta RECORDS Sentinel's cost).

``UsageRecord`` mirrors ``events.schema.json`` ``UsageEvent``: it carries the four
stable IDs, the model name, token counts, and the **recorded** cost estimate (cents
as an integer), plus the join keys back to the originating event. Delta computes no
cost of its own. The integer cost comes from the wire ``number`` via
:meth:`delta.money.Money.from_wire_cents` (half-even quantization at ingest).

``cost_estimate_cents`` is a *client-side cost estimate*, never an authoritative bill.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator, model_validator

from .identifiers import AgentId, EventId, ProjectId, RequestId, TeamId, TenantId
from .money import (
    DEFAULT_CURRENCY,
    MAX_USAGE_COST_CENTS,
    MAX_USAGE_TOKENS,
    Currency,
    bounded_count,
    require_aware_utc,
)

_MODEL_MAX_LENGTH = 256
ModelName = Annotated[str, StringConstraints(min_length=1, max_length=_MODEL_MAX_LENGTH)]


class WindowGranularity(StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    MONTHLY = "monthly"


class TimeWindow(BaseModel):
    """A half-open ``[start, end)`` window for burn-rate derivation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start: datetime
    end: datetime
    granularity: WindowGranularity

    @field_validator("start", "end")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "window bound")

    @model_validator(mode="after")
    def _ordered(self) -> "TimeWindow":
        if self.end <= self.start:
            raise ValueError("time window end must be strictly after start")
        return self

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()


class UsageRecord(BaseModel):
    """A per-request token/cost record mirroring a Sentinel ``usage`` event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId
    model: ModelName
    tokens_in: int
    tokens_out: int
    cost_estimate_cents: int
    currency: Currency = DEFAULT_CURRENCY
    request_id: RequestId
    event_id: EventId
    event_timestamp: datetime

    @field_validator("tokens_in", "tokens_out", mode="before")
    @classmethod
    def _tokens(cls, value: object) -> int:
        return bounded_count(value, "tokens", MAX_USAGE_TOKENS)

    @field_validator("cost_estimate_cents", mode="before")
    @classmethod
    def _cost(cls, value: object) -> int:
        # Integer cents only (vector 1). A fractional wire estimate must be
        # quantized via Money.from_wire_cents BEFORE constructing a UsageRecord.
        return bounded_count(value, "cost_estimate_cents", MAX_USAGE_COST_CENTS)

    @field_validator("event_timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "event_timestamp")
