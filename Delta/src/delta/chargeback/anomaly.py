"""Pure trailing-average anomaly detection (D-012, ADR-0012 §2 fork 1). No I/O.

Deliberately NOT a z-score / standard-deviation model or ML classifier — the same
"simpler is more honest" reasoning D-011's current-rate projection used (ADR-0011 fork
1): with only a handful of historical baseline periods, a fitted statistical model is
unstable and its assumptions (a large-enough sample, a roughly normal distribution)
don't hold for a group that may only have a few active days of history. Instead: compare
the CURRENT window's spend for a group against that SAME group's own trailing average
over N equal-length baseline windows immediately preceding it, and flag when the ratio
clears a fixed multiple — the same threshold-based (not statistical) shape D-011's
`PROJECTED_TO_EXCEED`/`SOFT_THRESHOLD_CROSSED` already use. Also distinct from D-006's
kill-switch `anomalous_single_tx` trigger (`kill_switch/triggers.py`), which is a fixed
absolute ceiling on ONE transaction with no history/period at all — a different shape of
"anomaly" (single-event outlier vs. spend-pattern-over-time), not reused here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AnomalyCode = Literal["SPEND_SPIKE", "NEW_SPENDER"]

# Current spend must exceed the trailing baseline average by at least this factor to be
# flagged — a fixed multiple, not a statistical confidence interval (honesty boundary).
DEFAULT_SPIKE_RATIO_THRESHOLD = 3.0

# Below this floor, a "spike" is noise, not a signal (e.g. $0.01 -> $0.05 is technically
# a 5x ratio but not operationally meaningful).
DEFAULT_MIN_FLOOR_CENTS = 1000  # $10


@dataclass(frozen=True)
class AnomalyResult:
    group_key: str
    current_spend_cents: int
    baseline_avg_cents: float
    ratio: float | None  # None when baseline_avg_cents == 0 (NEW_SPENDER)
    code: AnomalyCode
    severity: Literal["info", "warning"]


def detect_anomalies(
    *,
    current_by_group: dict[str, int],
    baseline_total_by_group: dict[str, int],
    baseline_periods: int,
    ratio_threshold: float = DEFAULT_SPIKE_RATIO_THRESHOLD,
    min_floor_cents: int = DEFAULT_MIN_FLOOR_CENTS,
) -> list[AnomalyResult]:
    """Flag groups whose CURRENT spend is an outlier vs. their own trailing baseline
    average. ``baseline_total_by_group`` is the SUM across all ``baseline_periods``
    windows (divided by ``baseline_periods`` here, not by the caller); a group absent
    from that dict is treated as a zero baseline (never spent before -> ``NEW_SPENDER``
    if it clears the floor now). Only groups present in ``current_by_group`` are ever
    evaluated — a group that stopped spending entirely has nothing to charge back or
    flag; this is about cost OVERRUNS, not underspend, mirroring D-011's own
    increase-only recommendation focus. Results are sorted by current spend, descending
    (biggest dollar impact first).
    """
    if baseline_periods < 1:
        raise ValueError("baseline_periods must be >= 1")

    results: list[AnomalyResult] = []
    for group_key, current_cents in current_by_group.items():
        if current_cents < min_floor_cents:
            continue
        baseline_total = baseline_total_by_group.get(group_key, 0)
        baseline_avg = baseline_total / baseline_periods
        if baseline_avg <= 0:
            results.append(
                AnomalyResult(
                    group_key=group_key,
                    current_spend_cents=current_cents,
                    baseline_avg_cents=0.0,
                    ratio=None,
                    code="NEW_SPENDER",
                    severity="info",
                )
            )
            continue
        ratio = current_cents / baseline_avg
        if ratio >= ratio_threshold:
            results.append(
                AnomalyResult(
                    group_key=group_key,
                    current_spend_cents=current_cents,
                    baseline_avg_cents=baseline_avg,
                    ratio=ratio,
                    code="SPEND_SPIKE",
                    severity="warning",
                )
            )

    results.sort(key=lambda r: r.current_spend_cents, reverse=True)
    return results
