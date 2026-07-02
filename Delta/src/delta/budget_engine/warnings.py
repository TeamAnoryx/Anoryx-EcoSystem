"""Advisory soft-threshold warnings (CONFIRM B, ADR-0005 §3.6, vector 10).

Delta-side advisory only. A warning is an ALERT (a structured log line) emitted when
cumulative spend crosses a soft threshold (e.g. 80%, 95%) of the hard cap while still
UNDER it. It shares NO code path with enforcement: this module never writes the publish
outbox, never flips enforcement state, and never blocks anything. A soft warning can never
become a hard block. The cost is a client-side estimate (honest language).
"""

from __future__ import annotations

import logging

from .definitions import BudgetDefinition

logger = logging.getLogger("delta.budget_engine.warnings")


def emit_budget_warning(*, budget: BudgetDefinition, spend_cents: int, pct: int) -> None:
    """Emit an advisory warning alert. NEVER enforces (CONFIRM B)."""
    logger.warning(
        "delta.budget advisory: soft threshold crossed — policy_id=%s scope=%s tenant=%s "
        "team=%s project=%s agent=%s period=%s threshold_pct=%d "
        "spend_cents=%d cap_cents=%s (client-side cost estimate; advisory only, no block)",
        budget.policy_id,
        budget.scope.value,
        budget.tenant_id,
        budget.team_id,
        budget.project_id,
        budget.agent_id,
        budget.period.value,
        pct,
        spend_cents,
        budget.limit_cost_cents,
    )
