"""Admin API request/response DTOs (D-007).

Wire-facing shapes. Requests are converted to the shared D-001 domain types
(``delta.allocation.Allocation``) before persistence so the "targets reconcile to
total" invariant (vector 4) is enforced by construction, not re-implemented here.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..budget import BudgetPeriod, BudgetScope
from ..identifiers import AgentId, AllocationId, ProjectId, TeamId, TenantId
from ..money import DEFAULT_CURRENCY, Currency

AllocationStatus = Literal["requested", "approved", "rejected"]
ApprovalAction = Literal["approve", "reject"]

# Bounded free-text fields (storage-bloat guard — mirrors the request_id length
# discipline in delta.identifiers). Unlike RequestId's narrow slug pattern, actor
# names and notes are genuinely free text (e.g. "Jane Doe"), so length is bounded
# here and control characters are rejected separately (log-injection guard: a
# forged newline could impersonate a second change-history/audit-log line in any
# downstream renderer — see docs/audit/d-007-security-audit.md finding #2).
_ACTOR_MAX_LENGTH = 128
_NOTE_MAX_LENGTH = 1024
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class AllocationTargetIn(BaseModel):
    """One proposed distribution target, carrying the scope Sentinel/D-005 needs.

    ``BudgetScope.TENANT`` targets ignore ``team_id``/``project_id``/``agent_id``
    (they must still be supplied — the API asks the caller for the same four-id
    shape ``BudgetConcept`` requires — but only the scope-relevant id is used to
    derive the target's ``scope_ref``; see :func:`.service.target_scope_ref`).
    """

    model_config = ConfigDict(extra="forbid")

    scope: BudgetScope
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId
    amount_minor_units: int = Field(ge=0)


class AllocationCreateRequest(BaseModel):
    """Propose a new allocation (status starts ``requested`` — never auto-applied)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    total_minor_units: int = Field(ge=0)
    currency: Currency = DEFAULT_CURRENCY
    period: BudgetPeriod
    targets: list[AllocationTargetIn] = Field(min_length=1, max_length=1024)
    requested_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("requested_by")
    @classmethod
    def _requested_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "requested_by")


class AllocationTargetView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: BudgetScope
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId
    amount_minor_units: int
    budget_id: str | None  # set once the target is materialized on approval


class AllocationView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allocation_id: AllocationId
    tenant_id: TenantId
    total_minor_units: int
    currency: Currency
    period: BudgetPeriod
    status: AllocationStatus
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    targets: list[AllocationTargetView]


class ApprovalDecisionRequest(BaseModel):
    """Approve or reject a ``requested`` allocation. Idempotent per allocation."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    action: ApprovalAction
    actor: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)

    @field_validator("actor")
    @classmethod
    def _actor_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "actor")

    @field_validator("note")
    @classmethod
    def _note_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "note")


class ChangeHistoryEntryView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    history_id: str
    tenant_id: TenantId
    entity_type: str
    entity_id: str
    action: str
    actor: str
    note: str | None
    created_at: datetime
