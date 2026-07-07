"""Admin API request/response DTOs (D-007).

Wire-facing shapes. Requests are converted to the shared D-001 domain types
(``delta.allocation.Allocation``) before persistence so the "targets reconcile to
total" invariant (vector 4) is enforced by construction, not re-implemented here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..budget import BudgetPeriod, BudgetScope
from ..identifiers import AgentId, AllocationId, ProjectId, TeamId, TenantId
from ..money import DEFAULT_CURRENCY, Currency

AllocationStatus = Literal["requested", "approved", "rejected"]
ApprovalAction = Literal["approve", "reject"]

# Bounded free-text fields (log-injection / storage-bloat guard — mirrors the request_id
# charset discipline in delta.identifiers rather than accepting unbounded strings).
_ACTOR_MAX_LENGTH = 128
_NOTE_MAX_LENGTH = 1024


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
