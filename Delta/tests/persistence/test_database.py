"""database.py — fail-closed tenant guard + the real get_tenant_session path."""

from __future__ import annotations

import os
import re
import uuid

import pytest
from account_seed import ensure_accounts, builder_account_id
from sqlalchemy import func, select, text

from delta.persistence.database import (
    TenantContextRequiredError,
    get_privileged_session,
    get_tenant_session,
    reset_engines,
)
from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import ledger_entries


async def test_delta_app_authenticates_on_fresh_db():
    """Vector 3 — the F-010 failure mode: delta_app must AUTHENTICATE after the
    migration + entrypoint/conftest password provisioning. A passwordless role (the
    migration-0006 defect) would fail SCRAM here.
    """
    app_url = os.environ.get("APP_DATABASE_URL", "")
    m = re.match(r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", app_url)
    assert m, "APP_DATABASE_URL must be set for the persistence suite"
    import asyncpg

    conn = await asyncpg.connect(
        user=m.group(1),
        password=m.group(2),
        host=m.group(3),
        port=int(m.group(4)),
        database=m.group(5),
    )
    try:
        assert await conn.fetchval("SELECT 1") == 1
    finally:
        await conn.close()


async def test_get_tenant_session_fail_closed_on_empty():
    with pytest.raises(TenantContextRequiredError):
        async with get_tenant_session("") as _s:
            pass
    with pytest.raises(TenantContextRequiredError):
        async with get_tenant_session("   ") as _s:
            pass


async def test_get_tenant_session_scopes_to_tenant(make_balanced_txn):
    """The production session factory sets the GUC and RLS scopes reads to it."""
    reset_engines()  # bind module engines to this test's event loop
    try:
        tid = str(uuid.uuid4())
        async with get_tenant_session(tid) as s:
            # Production path (not the conftest opener) — seed the builder accounts so
            # the same-tenant FK is satisfied in the same posting transaction.
            await ensure_accounts(
                s, tid, builder_account_id(tid, "debit"), builder_account_id(tid, "credit")
            )
            await append_transaction(s, make_balanced_txn(tenant_id=tid))

        # A fresh tenant session sees only this tenant's rows.
        async with get_tenant_session(tid) as s:
            count = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
        assert count == 2

        # Another tenant sees none of them.
        other = str(uuid.uuid4())
        async with get_tenant_session(other) as s:
            count = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
        assert count == 0
    finally:
        reset_engines()


async def test_privileged_session_reads():
    """get_privileged_session opens the owner connection (no tenant GUC)."""
    reset_engines()
    try:
        async with get_privileged_session() as s:
            assert await s.scalar(text("SELECT 1")) == 1
    finally:
        reset_engines()


async def test_missing_database_url_raises(monkeypatch):
    reset_engines()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        async with get_privileged_session() as _s:
            pass
    reset_engines()


async def test_missing_app_database_url_raises(monkeypatch):
    reset_engines()
    monkeypatch.delenv("APP_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        async with get_tenant_session("some-tenant") as _s:
            pass
    reset_engines()
