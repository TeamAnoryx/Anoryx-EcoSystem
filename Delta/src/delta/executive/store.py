"""Executive dashboard persistence (D-020, ADR-0020).

Only the D-013 CRM pipeline rollup lives here: D-008's spend summary and D-011's
per-budget forecasts are reused via their own SERVICE functions (not re-queried at
the table level) — see ``service.py``'s module docstring for why that's the correct
reuse boundary here, unlike D-018/D-019's "query the shared table directly" precedent.

Reads the shared ``clients``/``deals`` tables directly rather than importing
``crm.store`` — mirrors D-018/D-019's own precedent for a read with no existing
counterpart in the owning package's store module (there is no tenant-wide
"sum every open deal" aggregate in ``crm.store`` today).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import clients, deals

_TERMINAL_STAGES = ("won", "lost")


@dataclass(frozen=True)
class PipelineSummary:
    client_count: int
    open_deal_count: int
    open_pipeline_value_minor_units: int


async def get_pipeline_summary(session: AsyncSession, *, currency: str) -> PipelineSummary:
    """Counts + summed value of every non-terminal ('lead'/'qualified'/'proposal'/
    'negotiation') deal, scoped to one reporting currency (D-001's no-FX rule — mirrors
    every other Delta rollup's single-currency discipline). `open_deal_count` and
    `open_pipeline_value_minor_units` describe the SAME deal set: a deal in a
    different explicit currency is excluded from both (not counted-but-unsummed,
    which would pair a count spanning every currency with a value scoped to one —
    security audit finding, ADR-0020 §2 Fork 8). A deal with a NULL value/currency
    (an unqualified early-stage lead, per D-013's own pairing discipline) still
    contributes to `open_deal_count` but not to the summed value.
    """
    client_count_stmt = select(func.count()).select_from(clients)
    client_count = (await session.execute(client_count_stmt)).scalar_one()

    open_deal_count_stmt = select(func.count()).where(
        deals.c.stage.notin_(_TERMINAL_STAGES),
        or_(deals.c.currency.is_(None), deals.c.currency == currency),
    )
    open_deal_count = (await session.execute(open_deal_count_stmt)).scalar_one()

    value_stmt = select(func.coalesce(func.sum(deals.c.value_minor_units), 0)).where(
        deals.c.stage.notin_(_TERMINAL_STAGES), deals.c.currency == currency
    )
    open_pipeline_value = (await session.execute(value_stmt)).scalar_one()

    return PipelineSummary(
        client_count=client_count,
        open_deal_count=open_deal_count,
        open_pipeline_value_minor_units=open_pipeline_value,
    )
