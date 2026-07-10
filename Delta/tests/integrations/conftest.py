"""Fixtures for the D-019 ERP/procurement/cloud-cost sync DB suite. Mirrors
``tests/invoicing/conftest.py`` exactly (same db_required/ensure_schema_at_head/
provision_app_role/_truncate/_reset_delta_engines/admin_token/app/client/auth_headers
shape).

D-019 depends on D-014 (vendors/purchase_orders) and D-018 (invoices) for its
reconciliation targets — ``delta.erp.store`` and ``delta.invoicing.service`` are
called directly (then committed) to seed prerequisite rows, mirroring
``tests/invoicing/conftest.py``'s identical cross-package seeding precedent.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

_DELTA_ROOT = Path(__file__).resolve().parents[2]  # .../Delta
_DEFAULT_TEST_TOKEN = "test-admin-token-do-not-use-in-prod"  # noqa: S105


def _asyncpg(url: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _parse(url: str) -> dict:
    m = re.match(r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)
    if not m:
        pytest.fail("could not parse a postgres URL (user:pw@host:port/db expected)")
    return {
        "user": m.group(1),
        "password": m.group(2),
        "host": m.group(3),
        "port": int(m.group(4)),
        "database": m.group(5),
    }


def _db_env_present() -> bool:
    return bool(os.environ.get("DATABASE_URL") and os.environ.get("APP_DATABASE_URL"))


db_required = pytest.mark.skipif(
    not _db_env_present(), reason="DATABASE_URL/APP_DATABASE_URL unset (no live Postgres)"
)


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    if not os.environ.get("DATABASE_URL"):
        return
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_DELTA_ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")


async def _provision_delta_app(db_url: str, app_url: str) -> None:
    import base64
    import hashlib
    import hmac as _hmac

    app_pw = _parse(app_url)["password"]
    d = _parse(db_url)
    import asyncpg

    conn = await asyncpg.connect(
        user=d["user"],
        password=d["password"],
        host=d["host"],
        port=d["port"],
        database=d["database"],
    )
    try:
        salt = os.urandom(16)
        iters = 4096
        salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
        ck = _hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        sk = _hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        verifier = (
            f"SCRAM-SHA-256${iters}"
            f":{base64.b64encode(salt).decode()}"
            f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
            f":{base64.b64encode(sk).decode()}"
        )
        await conn.execute(f"ALTER ROLE delta_app WITH LOGIN PASSWORD '{verifier}'")
        verify = await asyncpg.connect(
            user="delta_app",
            password=app_pw,
            host=d["host"],
            port=d["port"],
            database=d["database"],
        )
        await verify.close()
    finally:
        await conn.close()


@pytest_asyncio.fixture(autouse=True)
async def provision_app_role(ensure_schema_at_head: None) -> None:
    if os.environ.get("DELTA_PROVISION_APP_ROLE", "").lower() not in ("1", "true", "yes", "on"):
        return
    if not _db_env_present():
        return
    await _provision_delta_app(os.environ["DATABASE_URL"], os.environ["APP_DATABASE_URL"])


@pytest_asyncio.fixture(autouse=True)
async def _truncate(provision_app_role: None) -> AsyncIterator[None]:
    if not _db_env_present():
        yield
        return
    engine = create_async_engine(_asyncpg(os.environ["DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE delta.sync_line_items, delta.sync_runs, delta.external_systems, "
                    "delta.invoice_payments, delta.invoices, "
                    "delta.purchase_orders, delta.assets, delta.vendors CASCADE"
                )
            )
    finally:
        await engine.dispose()
    yield


@pytest.fixture(autouse=True)
def _reset_delta_engines() -> Iterator[None]:
    from delta.persistence import database as _db

    _db.reset_engines()
    yield
    _db.reset_engines()


@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- admin app/client
@pytest.fixture(scope="session", autouse=True)
def admin_token() -> str:
    raw = os.environ.get("DELTA_ADMIN_TOKEN")
    if not raw:
        raw = _DEFAULT_TEST_TOKEN
        os.environ["DELTA_ADMIN_TOKEN"] = raw
    return raw


@pytest.fixture
def app(admin_token: str):
    from delta.allocation_admin.app import create_app

    return create_app()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://delta") as c:
        yield c


@pytest.fixture
def auth_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


# ------------------------------------------------------------------- domain seeding


async def seed_approved_po(
    session, *, tenant_id: str, amount_minor_units: int = 100_000, currency: str = "USD"
) -> tuple[str, str]:
    """Create a vendor + an 'approved' purchase order for it. Returns (vendor_id, po_id).
    Uses ``delta.erp.store`` directly, mirrors ``tests/invoicing/conftest.py``'s
    identical helper.
    """
    from delta.erp import store as erp_store

    now = datetime.now(timezone.utc)
    vendor = await erp_store.create_vendor(
        session, tenant_id=tenant_id, name="Acme Supplies", contact_email=None, now=now
    )
    po = await erp_store.create_purchase_order(
        session,
        tenant_id=tenant_id,
        vendor_id=vendor.vendor_id,
        asset_id=None,
        description="Q1 services",
        amount_minor_units=amount_minor_units,
        currency=currency,
        requested_by="buyer@example.com",
        now=now,
    )
    decided = await erp_store.try_decide_purchase_order(
        session, po_id=po.po_id, new_status="approved", decided_by="approver@example.com", now=now
    )
    assert decided
    await session.commit()
    return vendor.vendor_id, po.po_id


async def seed_approved_invoice(
    *,
    tenant_id: str,
    vendor_id: str,
    po_id: str,
    amount_minor_units: int = 40_000,
    currency: str = "USD",
) -> str:
    """Submit and approve an invoice against an already-approved PO. Returns invoice_id.
    Uses ``delta.invoicing.service`` directly (the real write path). Takes no session —
    `create_invoice`/`decide_invoice` each commit internally, so this opens its OWN
    two `get_tenant_session` blocks rather than accepting a caller's session, avoiding
    the D-013-era "session reused across two commits" RLS bug (a commit clears the
    transaction-local tenant GUC; a second write/read on the same session then sees
    zero rows under RLS instead of an error)."""
    from delta.persistence.database import get_tenant_session

    async with get_tenant_session(tenant_id) as session:
        from delta.invoicing.schemas import InvoiceCreateRequest
        from delta.invoicing.service import create_invoice

        invoice = await create_invoice(
            session,
            InvoiceCreateRequest(
                tenant_id=tenant_id,
                vendor_id=vendor_id,
                po_id=po_id,
                invoice_number=f"INV-{uuid.uuid4().hex[:8]}",
                description="Q1 services",
                amount_minor_units=amount_minor_units,
                currency=currency,
                submitted_by="ap@example.com",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        from delta.invoicing.schemas import InvoiceDecisionRequest
        from delta.invoicing.service import decide_invoice

        await decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            decision=InvoiceDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="lead@example.com"
            ),
        )
    return invoice.invoice_id
