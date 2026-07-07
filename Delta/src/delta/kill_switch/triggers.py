"""Pure kill-switch trigger logic (ADR-0006 §3.1). No I/O, no float.

Two independent, orthogonal signals — either alone is sufficient to trigger a kill:

* **unauthorized agent** — the tenant has opted in to an agent allow-list (``gated``)
  and the transacting agent is not on it.
* **anomalous single transaction** — the transaction's own cost, in isolation, exceeds
  a configured absolute ceiling. No accumulation, no period: this is what makes the
  kill-switch faster than the D-005 budget-threshold loop.

Both are opt-in / inert by default (ADR-0006 §2 fork 2): an ungated tenant, or an unset
ceiling, means that trigger never fires — the kill-switch imposes no new restriction on a
tenant that has not configured it.
"""

from __future__ import annotations

UNAUTHORIZED_AGENT = "unauthorized_agent"
ANOMALOUS_SINGLE_TX = "anomalous_single_tx"


def unauthorized_reason(*, gated: bool, authorized: bool) -> str | None:
    """``UNAUTHORIZED_AGENT`` iff the tenant is gated and the agent is not authorized."""
    if gated and not authorized:
        return UNAUTHORIZED_AGENT
    return None


def anomalous_reason(*, cost_cents: int, max_single_tx_cost_cents: int | None) -> str | None:
    """``ANOMALOUS_SINGLE_TX`` iff a ceiling is configured and this transaction exceeds it.

    Strict ``>`` (a transaction exactly at the ceiling is not anomalous), matching the
    D-005 cap-comparison convention (``decision.is_over_cost_cap``).
    """
    if max_single_tx_cost_cents is not None and cost_cents > max_single_tx_cost_cents:
        return ANOMALOUS_SINGLE_TX
    return None


def detect_reason(
    *,
    gated: bool,
    authorized: bool,
    cost_cents: int,
    max_single_tx_cost_cents: int | None,
) -> str | None:
    """The first triggered reason (unauthorized checked before anomalous), or None."""
    reason = unauthorized_reason(gated=gated, authorized=authorized)
    if reason is not None:
        return reason
    return anomalous_reason(
        cost_cents=cost_cents, max_single_tx_cost_cents=max_single_tx_cost_cents
    )
