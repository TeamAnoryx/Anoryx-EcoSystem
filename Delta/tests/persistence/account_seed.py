"""Test helper (D-004): seed accounts so the new same-tenant FK is satisfiable.

D-004 adds a composite ``(tenant_id, account_id)`` FK from ``ledger_entries`` to
``accounts`` (ADR-0004 Fork 1a, closing D-003's deferred HIGH#2). Every posted entry
now requires its account to exist first. D-003's persistence tests predate the FK and
posted against accounts that were never created, so they seed accounts here before
posting — the documented Fork 1a cost. Importable (not a fixture) so both ``conftest``
and the test helpers can use it.
"""

from __future__ import annotations

import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from delta.persistence.models import accounts

# Deterministic namespace for test account ids (distinct from production resolver NS).
_TEST_ACCOUNT_NS = uuid.UUID("d0e1f2a3-0004-4000-8000-0000000000aa")


def builder_account_id(tenant_id: str, label: str) -> str:
    """A deterministic, same-tenant account id for a given (tenant, label)."""
    return str(uuid.uuid5(_TEST_ACCOUNT_NS, f"{tenant_id}:{label}"))


async def ensure_accounts(
    session: AsyncSession, tenant_id: str, *account_ids: str, currency: str = "USD"
) -> None:
    """Get-or-create the given accounts in the caller's tenant session (no commit).

    ON CONFLICT DO NOTHING — idempotent and safe to call repeatedly. Runs in the
    caller's transaction so the FK is satisfied atomically when the posting commits.
    """
    for account_id in account_ids:
        await session.execute(
            pg_insert(accounts)
            .values(
                account_id=account_id,
                tenant_id=tenant_id,
                type="asset",
                currency=currency,
                name="test account",
            )
            .on_conflict_do_nothing(index_elements=["account_id"])
        )
