"""Deterministic, threshold-based advisory recommendations (D-011, ADR-0011 §2 fork 2).

Extends the D-005 soft-warning-threshold pattern (``budget_engine.decision``/``warnings``)
from "already crossed" to "projected to cross" and "where to look to cut cost." Every
recommendation here is advisory only — it shares no code path with enforcement (mirrors
``warnings.py``'s own invariant) and never writes to the outbox or enforcement state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from ..budget_engine import decision
from ..budget_engine.definitions import BudgetDefinition
from ..dashboards.store import GroupSpendRow
from .projection import Projection

Severity = Literal["info", "warning", "critical"]

# Same soft-threshold percentages the budget engine itself warns at (ADR-0005 §3.6) —
# reusing the constant keeps the "already crossed" language consistent across both
# advisory surfaces rather than drifting to a different threshold here.
_SOFT_WARNING_PCTS = (80, 95)

# A single group (team/project/agent, depending on the budget's own scope) accounting
# for more than this share of spend is called out as a concentration worth reviewing.
_CONCENTRATION_SHARE_PCT = 50


@dataclass(frozen=True)
class Recommendation:
    code: str
    severity: Severity
    message: str


def build_recommendations(
    *,
    budget: BudgetDefinition,
    projection: Projection,
    top_spender: GroupSpendRow | None,
    exhaustion_at: datetime | None,
) -> list[Recommendation]:
    """``exhaustion_at`` is the caller's own precomputed :func:`.projection.exhaustion_at`
    result (computed once in the service layer and reused here, rather than recomputed) —
    ``None`` whenever a projected crossing isn't applicable (see that function's docstring)."""
    if projection.insufficient_data:
        return [
            Recommendation(
                code="INSUFFICIENT_DATA",
                severity="info",
                message=(
                    "Less than an hour has elapsed in the current period — not enough "
                    "data yet for a burn-rate forecast."
                ),
            )
        ]

    cap = budget.limit_cost_cents
    if cap is None:
        return [
            Recommendation(
                code="NO_COST_CAP",
                severity="info",
                message=(
                    "This budget has no cost cap set — spend is tracked but no "
                    "exceedance forecast applies."
                ),
            )
        ]

    recs: list[Recommendation] = []

    if decision.is_over_cost_cap(projection.current_period_spend_cents, budget):
        recs.append(
            Recommendation(
                code="ALREADY_OVER_CAP",
                severity="critical",
                message=(
                    f"Current period spend (${projection.current_period_spend_cents / 100:,.2f}) "
                    f"has already exceeded the cap (${cap / 100:,.2f}); budget-engine "
                    "enforcement should already be blocking further spend in this scope."
                ),
            )
        )
    else:
        band = decision.soft_warning_band(
            projection.current_period_spend_cents, budget, _SOFT_WARNING_PCTS
        )
        if band is not None:
            recs.append(
                Recommendation(
                    code="SOFT_THRESHOLD_CROSSED",
                    severity="warning",
                    message=f"Current spend has crossed {band}% of the cap.",
                )
            )

        if (
            projection.projected_period_end_spend_cents is not None
            and projection.projected_period_end_spend_cents > cap
        ):
            rate_dollars = projection.burn_rate_cents_per_hour / 100
            if exhaustion_at is not None:
                recs.append(
                    Recommendation(
                        code="PROJECTED_TO_EXCEED",
                        severity="warning",
                        message=(
                            f"At the current burn rate (~${rate_dollars:,.2f}/hr), this "
                            f"budget is projected to exceed its cap around "
                            f"{exhaustion_at.isoformat()}, before the period ends on "
                            f"{projection.period_end.isoformat()}."
                        ),
                    )
                )
            else:
                recs.append(
                    Recommendation(
                        code="PROJECTED_TO_EXCEED",
                        severity="info",
                        message=(
                            f"At the current burn rate (~${rate_dollars:,.2f}/hr), "
                            "projected period-end spend exceeds the cap, but not clearly "
                            "before the period itself ends."
                        ),
                    )
                )

    if projection.trend_direction == "rising":
        recs.append(
            Recommendation(
                code="RISING_TREND",
                severity="info",
                message=(
                    "Burn rate has increased in the second half of the elapsed period "
                    "compared to the first half."
                ),
            )
        )

    if top_spender is not None and projection.current_period_spend_cents > 0:
        # top_spender.cost_cents (dashboards.store.top_spenders) sums GROSS
        # debit-direction rows; current_period_spend_cents (budget_engine.spend.
        # scope_spend_cents) is the NET expense balance (debit-minus-credit,
        # expense-type only). The two use different accounting bases, so when a
        # reversal exists in the period this ratio is an approximation and can
        # nominally exceed 100% — clamped for display and worded as approximate,
        # never a claim of enforcement-grade precision (independent security review).
        share_pct = min(100.0, top_spender.cost_cents * 100 / projection.current_period_spend_cents)
        if share_pct > _CONCENTRATION_SHARE_PCT:
            recs.append(
                Recommendation(
                    code="SPEND_CONCENTRATION",
                    severity="info",
                    message=(
                        f"{top_spender.group_key} accounts for approximately "
                        f"{share_pct:.0f}% of this budget's spend — consider "
                        "reviewing its usage."
                    ),
                )
            )

    return recs
