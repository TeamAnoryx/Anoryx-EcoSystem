"""ModelInventoryRepository — data access for the F-019 model inventory (ADR-0022 §5.2).

The per-tenant model/fine-tune registry + its approval state machine. Reads run on a
tenant RLS session at request time (enforcement) and on a per-target tenant session
for operator endpoints; the table's RLS tenant_isolation policy is the primary
boundary and the explicit `tenant_id` predicate here is the second lock (the F-003b
defense-in-depth pattern).

TRANSACTION CONTRACT: none of these methods commit. The caller owns the transaction
so a state transition and its audit append commit ATOMICALLY (ADR-0022 §7.4 — no
state change without a committed audit row). `transition()` mutates the row in the
session; the operator endpoint wraps transition + emit in one `session.begin()`.

STATE MACHINE (minimal, ADR-0022 D2): adopt creates `pending`; an operator moves
pending→approved, pending→denied, approved→denied, denied→approved. Any other edge
(or a transition on an absent model) is rejected. There is no path back to `pending`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.model_inventory import INVENTORY_STATES, MODEL_TYPES, ModelInventory

# Unknown-model sentinel returned by get_state for an absent row → DENY at enforcement.
UNKNOWN_STATE = "unknown"

# Allowed state transitions (ADR-0022 §5.2). No edge leads back to 'pending'.
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"approved", "denied"}),
    "approved": frozenset({"denied"}),
    "denied": frozenset({"approved"}),
}


class ModelInventoryNotFoundError(Exception):
    """Raised when a transition targets a model_id with no inventory row."""


class InvalidModelTransitionError(Exception):
    """Raised when a requested state transition is not a permitted edge."""


class ModelInventoryRepository:
    """Data access + state-machine guard for the per-tenant model inventory."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_for_tenant(
        self, tenant_id: str, *, limit: int = 200, offset: int = 0
    ) -> list[ModelInventory]:
        """A page of inventory rows for a tenant (RLS-scoped; explicit predicate = 2nd lock).

        Pagination is pushed into SQL (LIMIT/OFFSET) so an operator read never does a
        full-table fetch for a large inventory (code-review MED fix; mirrors
        PolicyRepository.list_for_tenant).
        """
        stmt = (
            select(ModelInventory)
            .where(ModelInventory.tenant_id == tenant_id)
            .order_by(ModelInventory.model_id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_row(self, tenant_id: str, model_id: str) -> ModelInventory | None:
        """Fetch a single inventory row, or None if absent."""
        stmt = select(ModelInventory).where(
            ModelInventory.tenant_id == tenant_id,
            ModelInventory.model_id == model_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_state(self, tenant_id: str, model_id: str) -> str:
        """Current state for a model, or UNKNOWN_STATE if no row exists.

        UNKNOWN_STATE is deliberately distinct from the three real states so the
        enforcement layer denies an absent model (default-deny) without conflating
        it with an explicit 'denied' decision.
        """
        row = await self.get_row(tenant_id, model_id)
        return row.state if row is not None else UNKNOWN_STATE

    async def adopt(
        self, tenant_id: str, model_id: str, model_type: str = "base"
    ) -> tuple[ModelInventory, bool]:
        """Register a model as `pending` if not already present (idempotent).

        Returns (row, created): created=True ONLY when this call inserted a new row,
        False when the model already existed. Callers gate the model_adopted audit
        event on `created` so a re-adoption never logs a false "newly registered"
        (code-review MED fix — the prior pre-adopt get_row check had a TOCTOU window).
        Adoption never resets an already-decided model back to pending (that would
        silently undo an operator denial). model_type is validated up front.
        """
        if model_type not in MODEL_TYPES:
            raise ValueError(f"invalid model_type: {model_type!r}")

        existing = await self.get_row(tenant_id, model_id)
        if existing is not None:
            return existing, False

        row = ModelInventory(
            inventory_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            model_id=model_id,
            model_type=model_type,
            state="pending",
        )
        self._session.add(row)
        await self._session.flush()
        return row, True

    async def transition(
        self,
        tenant_id: str,
        model_id: str,
        new_state: str,
        operator_id: str | None,
        now: datetime,
    ) -> ModelInventory:
        """Move an existing model to a new state via a permitted edge.

        Does NOT commit — the caller wraps this and the audit append in one
        transaction (atomicity, ADR-0022 §7.4). Raises ModelInventoryNotFoundError if
        the model has no row, InvalidModelTransitionError if the edge is not allowed.
        `operator_id` is the authenticated operator's actor_id (admin_users.id) or
        None for break-glass; it is recorded as the decider of this transition.
        """
        if new_state not in INVENTORY_STATES:
            raise ValueError(f"invalid target state: {new_state!r}")

        row = await self.get_row(tenant_id, model_id)
        if row is None:
            raise ModelInventoryNotFoundError(
                f"no inventory row for tenant {tenant_id!r} model {model_id!r}"
            )

        if new_state == row.state:
            # Idempotent no-op edge would still need an audited reason; treat an
            # explicit same-state request as invalid so callers handle it deliberately.
            raise InvalidModelTransitionError(f"model {model_id!r} is already {row.state!r}")
        if new_state not in _VALID_TRANSITIONS.get(row.state, frozenset()):
            raise InvalidModelTransitionError(
                f"illegal transition {row.state!r} -> {new_state!r} for model {model_id!r}"
            )

        row.state = new_state
        row.approved_by = operator_id
        row.approved_at = now
        row.updated_at = now
        await self._session.flush()
        return row

    async def set_retirement(
        self,
        tenant_id: str,
        model_id: str,
        retire_at: datetime,
        now: datetime,
    ) -> ModelInventory:
        """Schedule retirement of an APPROVED model (sets retire_at). No commit.

        F-021 (ADR-0024). Retirement is a grace deadline on an active approval, NOT a
        state transition — `state` stays 'approved' and `approved_by`/`approved_at`
        (the approval decider) are untouched; the retiring operator is recorded in the
        audit event, not on the row. Only an 'approved' model can be retired: a model
        that is pending/denied/absent is rejected (ModelInventoryNotFoundError /
        InvalidModelTransitionError) so an operator can never "retire" something that
        was never usable, and every emitted event corresponds to a real change. The
        caller wraps this and the audit append in one transaction (ADR-0022 §7.4).
        """
        row = await self.get_row(tenant_id, model_id)
        if row is None:
            raise ModelInventoryNotFoundError(
                f"no inventory row for tenant {tenant_id!r} model {model_id!r}"
            )
        if row.state != "approved":
            raise InvalidModelTransitionError(
                f"cannot retire model {model_id!r} in state {row.state!r}; "
                "only an 'approved' model can be scheduled for retirement"
            )
        row.retire_at = retire_at
        row.updated_at = now
        await self._session.flush()
        return row

    async def clear_retirement(
        self,
        tenant_id: str,
        model_id: str,
        now: datetime,
    ) -> ModelInventory:
        """Cancel a scheduled retirement (clears retire_at). No commit.

        F-021 (ADR-0024). Rejects a model with no scheduled retirement (retire_at IS
        NULL) so an un-retire always corresponds to a real change — no empty audit
        event. Does not alter `state` or the approval decider.
        """
        row = await self.get_row(tenant_id, model_id)
        if row is None:
            raise ModelInventoryNotFoundError(
                f"no inventory row for tenant {tenant_id!r} model {model_id!r}"
            )
        if row.retire_at is None:
            raise InvalidModelTransitionError(
                f"model {model_id!r} has no scheduled retirement to cancel"
            )
        row.retire_at = None
        row.updated_at = now
        await self._session.flush()
        return row
