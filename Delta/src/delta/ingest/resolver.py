"""Event -> account resolution (ADR-0004 Fork 1a, threat vectors 1 + 7).

The two canonical accounts a usage event posts against are derived DETERMINISTICALLY
from the validated ``tenant_id`` (+ currency), never taken from the event payload:

    expense_account_id = uuid5(NS, f"{tenant_id}:{currency}:expense")
    contra_account_id  = uuid5(NS, f"{tenant_id}:{currency}:spend_clearing")

Because the ids are a pure function of the tenant and a fixed role string, a
malicious payload cannot name an arbitrary or cross-tenant account (vector 7). The
accounts are get-or-created (INSERT ... ON CONFLICT DO NOTHING) within the CALLER's
tenant session so the composite same-tenant FK on ``ledger_entries`` is satisfied in
the same transaction that posts the entries (no orphan accounts on failure).

Accounts are keyed per (tenant, currency) so each account is single-currency by
construction — Delta is single-currency / no-FX (D-001 Fork 4), and this keeps the
D-003 balance reads (which sum minor units per account) currency-coherent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..accounts import AccountType
from ..persistence.models import accounts as accounts_table

# Fixed namespace for deterministic account ids. A version-5 UUID over this namespace
# yields a canonical dashed UUID, matching the strict AccountId pattern.
DELTA_ACCOUNT_NAMESPACE = uuid.UUID("d0e1f2a3-0004-4000-8000-000000000004")

# The two roles in the minimal chart of accounts for AI spend.
_EXPENSE_ROLE = "expense"
_CONTRA_ROLE = "spend_clearing"

# X-005 revenue posting roles. DELIBERATELY DISTINCT role strings from the usage
# expense/contra roles above: because the account id hashes (tenant, currency, role), a
# different role yields a different deterministic account id, so a revenue account can
# NEVER collide with a usage account for the same (tenant, currency).
_REVENUE_RECEIVABLE_ROLE = "subscription_receivable"
_REVENUE_ACCOUNT_ROLE = "subscription_revenue"


@dataclass(frozen=True)
class ResolvedAccounts:
    """The two same-tenant accounts a usage event's two-leg transaction posts to."""

    expense_account_id: str
    contra_account_id: str


@dataclass(frozen=True)
class ResolvedRevenueAccounts:
    """The two same-tenant accounts an X-005 subscription_granted's two-leg txn posts to."""

    receivable_account_id: str
    revenue_account_id: str


def _account_id(tenant_id: str, currency: str, role: str) -> str:
    """Deterministic, same-tenant account id. Pure function of (tenant, currency, role)."""
    return str(uuid.uuid5(DELTA_ACCOUNT_NAMESPACE, f"{tenant_id}:{currency}:{role}"))


def resolve_account_ids(tenant_id: str, currency: str) -> ResolvedAccounts:
    """Compute the deterministic (expense, contra) account ids — no DB access."""
    return ResolvedAccounts(
        expense_account_id=_account_id(tenant_id, currency, _EXPENSE_ROLE),
        contra_account_id=_account_id(tenant_id, currency, _CONTRA_ROLE),
    )


async def _ensure_account(
    session: AsyncSession,
    *,
    account_id: str,
    tenant_id: str,
    account_type: AccountType,
    currency: str,
    name: str,
) -> None:
    """Get-or-create one account in the caller's tenant session (no commit).

    INSERT ... ON CONFLICT (account_id) DO NOTHING is idempotent and race-safe: a
    concurrent first-event for the same tenant resolves to one winner, the loser
    no-ops. RLS WITH CHECK requires the session GUC == tenant_id (set by
    get_tenant_session), so an account can only be created in its own tenant.
    """
    stmt = (
        pg_insert(accounts_table)
        .values(
            account_id=account_id,
            tenant_id=tenant_id,
            type=account_type.value,
            currency=currency,
            name=name,
        )
        .on_conflict_do_nothing(index_elements=["account_id"])
    )
    await session.execute(stmt)


async def ensure_accounts(session: AsyncSession, tenant_id: str, currency: str) -> ResolvedAccounts:
    """Ensure both canonical accounts exist in the caller's tenant session.

    Runs in the CALLER's transaction (no commit) so the composite same-tenant FK on
    ledger_entries is satisfied atomically when the posting commits. Returns the
    resolved account ids.
    """
    resolved = resolve_account_ids(tenant_id, currency)
    await _ensure_account(
        session,
        account_id=resolved.expense_account_id,
        tenant_id=tenant_id,
        account_type=AccountType.EXPENSE,
        currency=currency,
        name=f"AI Spend Expense ({currency})",
    )
    await _ensure_account(
        session,
        account_id=resolved.contra_account_id,
        tenant_id=tenant_id,
        # Spend accrued/owed against budget — a liability-style clearing account the
        # budget/settlement layer (D-005+) reconciles. DEBIT expense, CREDIT this.
        account_type=AccountType.LIABILITY,
        currency=currency,
        name=f"AI Spend Clearing ({currency})",
    )
    return resolved


def resolve_revenue_account_ids(tenant_id: str, currency: str) -> ResolvedRevenueAccounts:
    """Compute the deterministic (receivable, revenue) account ids — no DB access."""
    return ResolvedRevenueAccounts(
        receivable_account_id=_account_id(tenant_id, currency, _REVENUE_RECEIVABLE_ROLE),
        revenue_account_id=_account_id(tenant_id, currency, _REVENUE_ACCOUNT_ROLE),
    )


async def ensure_revenue_accounts(
    session: AsyncSession, tenant_id: str, currency: str
) -> ResolvedRevenueAccounts:
    """Ensure both X-005 revenue accounts exist in the caller's tenant session (no commit).

    Same get-or-create (INSERT ... ON CONFLICT DO NOTHING), same caller-transaction
    discipline as :func:`ensure_accounts`, so the composite same-tenant FK on
    ledger_entries is satisfied atomically when the posting commits. The two accounts are:

      * receivable — ``AccountType.ASSET`` (an amount owed to / collected by the tenant),
      * revenue    — ``AccountType.REVENUE`` (recognized subscription income).

    A subscription_granted DEBITs the receivable (increasing the asset) and CREDITs the
    revenue account (increasing revenue), netting to zero (balanced by construction).
    """
    resolved = resolve_revenue_account_ids(tenant_id, currency)
    await _ensure_account(
        session,
        account_id=resolved.receivable_account_id,
        tenant_id=tenant_id,
        account_type=AccountType.ASSET,
        currency=currency,
        name=f"Subscription Receivable ({currency})",
    )
    await _ensure_account(
        session,
        account_id=resolved.revenue_account_id,
        tenant_id=tenant_id,
        account_type=AccountType.REVENUE,
        currency=currency,
        name=f"Subscription Revenue ({currency})",
    )
    return resolved
