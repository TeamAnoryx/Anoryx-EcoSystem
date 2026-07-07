"""Delta budget allocation admin surface (D-007).

Turns the internal-only ``budget_engine.definitions.create_budget`` seam (D-005) into
an authenticated, auditable admin workflow: an operator proposes an *allocation* — a
tenant's total distributed across scope targets (``delta.allocation.Allocation``) — a
second decision (approve/reject) either materializes each target as a real
``BudgetDefinition`` or discards it, and every state transition is appended to a plain
change-history log.

Honesty boundary: the change-history log here is append-only but NOT hash-chained.
The tamper-evident, hash-chained audit trail for Delta's financial workflows is a
separate, later task (D-009) that applies the Sentinel F-003 pattern; this log is its
un-hash-chained precursor, not a substitute for it.
"""

from __future__ import annotations
