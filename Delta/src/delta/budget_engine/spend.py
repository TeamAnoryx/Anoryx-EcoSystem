"""Authoritative cumulative-spend derivation from the D-003 ledger (ADR-0005 §3.1).

Spend is a PURE aggregate over the append-only ledger on the caller's tenant-scoped (RLS)
session — never a stored running total, so it cannot desync from the ledger or be forged.

Spend is the NET balance of the tenant's EXPENSE account(s) over the period window:
``SUM(debit) - SUM(credit)`` restricted to ``accounts.type = 'expense'``. This is correct
under REVERSALS: D-004 posts a usage cost as a DEBIT to the expense account (+cost), and a
D-003 reversal posts a CREDIT to the same expense account (-cost), so a reversed usage nets
to zero. Summing raw debits across ALL accounts would double-count the reversal's contra-
account (LIABILITY) DEBIT and report 2x cost — a FALSE-ENFORCEMENT bug (the wrong
direction). The contra/clearing legs are excluded by the ``type = 'expense'`` filter.

Everything is integer cents (``amount_minor_units`` is ``BIGINT``) — there is NO float
anywhere in the spend-vs-cap path, because a float boundary error would flip the
enforcement decision (vector 4).

The window is the WHOLE current period ``[period_start, period_end)`` (the next boundary),
not ``[period_start, now)`` — so a usage event timestamped slightly in the future relative
to the eval clock (clock skew) but within the current period is still counted, closing the
enforcement gap the ``now`` upper bound would otherwise leave (review MED).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..budget import BudgetScope
from ..persistence.models import accounts, ledger_entries


async def scope_spend_cents(
    session: AsyncSession,
    *,
    scope: BudgetScope,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    currency: str,
    period_start: datetime,
    period_end: datetime,
) -> int:
    """Net expense balance (integer cents) for the scope over ``[period_start, period_end)``.

    Tenant isolation is enforced by RLS on the tenant-scoped session (both ledger_entries
    and accounts are RLS-scoped); the explicit ``tenant_id`` predicate is defence-in-depth.
    The scope selects the additional id filter on the ledger entry:

      * ``tenant``  — all of the tenant's expense activity (no sub-id filter);
      * ``team``    — entries with ``team_id`` == the budget's team;
      * ``project`` — entries with ``project_id`` == the budget's project;
      * ``agent``   — entries with ``agent_id`` == the budget's agent.
    """
    le = ledger_entries.c
    conds = [
        le.tenant_id == tenant_id,
        accounts.c.type == "expense",  # cost legs only — excludes the contra/clearing legs
        accounts.c.currency == currency,  # never aggregate minor units across currencies
        le.timestamp >= period_start,
        le.timestamp < period_end,  # half-open [period_start, period_end)
    ]
    if scope is BudgetScope.TEAM:
        conds.append(le.team_id == team_id)
    elif scope is BudgetScope.PROJECT:
        conds.append(le.project_id == project_id)
    elif scope is BudgetScope.AGENT:
        conds.append(le.agent_id == agent_id)
    # BudgetScope.TENANT: no sub-id filter — the whole tenant's expense activity.

    # Net debit-minus-credit so a reversal (credit on the expense account) cancels its
    # original debit. Integer cents throughout.
    signed = case(
        (le.direction == "debit", le.amount_minor_units),
        else_=-le.amount_minor_units,
    )
    stmt = (
        select(func.coalesce(func.sum(signed), 0))
        .select_from(ledger_entries.join(accounts, le.account_id == accounts.c.account_id))
        .where(and_(*conds))
    )
    total = (await session.execute(stmt)).scalar_one()
    return int(total)
