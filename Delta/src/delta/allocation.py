"""Allocations — a total distributed across targets, reconciled by construction.

An ``Allocation`` cannot be constructed unless its targets share its currency and
sum exactly to its total (vector 4). The same rule is exposed as a standalone
check in :mod:`delta.reconciliation` for callers holding raw data.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .budget import BudgetPeriod
from .identifiers import AllocationId, TenantId
from .money import Money
from .reconciliation import reconcile_allocation

_SCOPE_REF_MAX_LENGTH = 64
# Intentionally a bounded opaque string: a target may be a team_id / project_id
# (UUID) OR an agent_id (slug), so no single id format fits. D-003 is responsible
# for validating scope_ref against the Sentinel ID registry when it persists rows.
ScopeRef = Annotated[str, StringConstraints(min_length=1, max_length=_SCOPE_REF_MAX_LENGTH)]


class AllocationTarget(BaseModel):
    """One distribution target: an opaque scope reference + the amount allocated to it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_ref: ScopeRef  # opaque team/project/agent id; D-003 validates vs the ID registry
    amount: Money


class Allocation(BaseModel):
    """A tenant-scoped total distributed across targets; reconciled by construction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allocation_id: AllocationId
    tenant_id: TenantId
    total: Money
    # Immutable tuple: a reconciled allocation cannot be desynced by .append() (H-1).
    targets: tuple[AllocationTarget, ...] = Field(min_length=1, max_length=1024)
    period: BudgetPeriod

    @model_validator(mode="after")
    def _reconciled(self) -> "Allocation":
        errors = reconcile_allocation(self.total, [t.amount for t in self.targets])
        if errors:
            raise ValueError("; ".join(errors))
        return self
