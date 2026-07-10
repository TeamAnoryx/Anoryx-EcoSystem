"""F-031 real-DB checks — migrations-at-head + audit-chain-integrity.

Requires DATABASE_URL (skips at collection if absent), matching the other
real-DB test modules' convention.
"""

from __future__ import annotations

import os

import pytest

from preflight.checks import check_audit_chain_integrity, check_migrations_at_head
from preflight.result import STATUS_PASS

if not os.environ.get("DATABASE_URL"):
    pytest.skip("DATABASE_URL not set", allow_module_level=True)


@pytest.mark.asyncio
async def test_migrations_at_head_passes_on_migrated_db():
    # The CI/test DB is migrated to head, so this must PASS and report the head.
    result = await check_migrations_at_head()
    assert result.status == STATUS_PASS, result.detail
    assert result.evidence["db_revision"] == result.evidence["script_head"]


@pytest.mark.asyncio
async def test_audit_chain_integrity_passes_on_untampered_db():
    # A freshly-migrated DB has an intact (possibly empty-then-appended) chain.
    result = await check_audit_chain_integrity()
    assert result.status == STATUS_PASS, result.detail
    assert "rows_checked" in result.evidence
