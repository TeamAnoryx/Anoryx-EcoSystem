"""Pure spend-vs-cap decision logic (ADR-0005 §3.3, vectors 3+4).

No I/O, no float. The ledger is a COST ledger, so Delta's authoritative enforcement
signal is the cost cap (``limit_cost_cents``). A token cap, if also set, is carried in the
published ``budget_limit`` and enforced by F-008 against its own token counter once the
policy is live; Delta does not derive token spend from the cost ledger (stated honestly in
the ADR). ``is_over_cap`` is a strict integer ``>`` — the cap is the maximum allowed, so
spend == cap is still within budget and spend > cap is over (matching F-008's own
``used + est > cap`` strict check).
"""

from __future__ import annotations

from .definitions import BudgetDefinition


def is_over_cost_cap(spend_cents: int, budget: BudgetDefinition) -> bool:
    """True iff cumulative cost has strictly exceeded the budget's cost cap (integer)."""
    cap = budget.limit_cost_cents
    return cap is not None and spend_cents > cap


def soft_warning_band(
    spend_cents: int, budget: BudgetDefinition, pcts: tuple[int, ...]
) -> int | None:
    """The highest soft-threshold percentage crossed, while spend does not exceed the cap.

    Returns ``None`` when there is no cost cap, when spend is below the lowest threshold, or
    when spend STRICTLY EXCEEDS the cap (enforcement territory, owned by ``is_over_cost_cap``
    which is also strict ``>``). At spend == cap (within budget, not over) it returns the
    highest crossed band. Integer arithmetic only: ``spend * 100 >= pct * cap``.
    """
    cap = budget.limit_cost_cents
    if cap is None or cap <= 0:
        return None
    if spend_cents > cap:  # over the cap — enforcement territory, not a warning
        return None
    crossed = [p for p in pcts if 0 < p < 100 and spend_cents * 100 >= p * cap]
    return max(crossed) if crossed else None
