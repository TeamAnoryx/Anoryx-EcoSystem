"""Non-stubbed cross-product seam: real Orchestrator inbound -> real Delta ingest (D-004).

PATH USED (the preferred one): this drives the REAL Orchestrator inbound. A Sentinel-style
usage envelope is HMAC-signed and POSTed to the real Orchestrator app's
``POST /v1/ingest/events`` (the O-003 receiver + pipeline), which durably persists an
``ingest_events`` row + a ``forward_outbox`` forward-INTENT row (status='pending') in the
Orchestrator DB. Then the REAL dispatcher (``orchestrator.dispatch.dispatcher.dispatch_pending``)
drains that outbox: it signs each payload with the Orchestrator->Delta HMAC and POSTs it to
the REAL Delta ingest app (bound via an ASGI client). Nothing on the path is stubbed.

Proven end to end:
  * a usage event accepted by the Orchestrator becomes exactly ONE balanced debit in the
    Delta ledger for that tenant, and the forward_outbox row flips 'pending' -> 'forwarded';
  * re-delivering the same event (Orchestrator dedup) + re-draining is idempotent — Delta
    still holds exactly ONE debit, no duplicate.

GUARDED: skips unless BOTH product DBs are configured (APP_DATABASE_URL for Delta,
ORCH_APP_DATABASE_URL for the Orchestrator). The Delta schema/role come from the ingest
conftest autouse harness; the Orchestrator schema/role are provisioned here (idempotent).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

pytestmark = pytest.mark.skipif(
    not (os.environ.get("APP_DATABASE_URL") and os.environ.get("ORCH_APP_DATABASE_URL")),
    reason="needs both Delta (APP_DATABASE_URL) and Orchestrator (ORCH_APP_DATABASE_URL) DBs",
)

# Make `import orchestrator` work without installing it (mirror the seam wiring contract).
_REPO_ROOT = Path(__file__).resolve().parents[3]  # .../worktrees/d-004
_ORCH_SRC = _REPO_ROOT / "Anoryx-AI-Orchestrator" / "src"
_ORCH_ROOT = _ORCH_SRC.parent
if str(_ORCH_SRC) not in sys.path:
    sys.path.insert(0, str(_ORCH_SRC))

# Windows: the default ProactorEventLoop races asyncpg socket teardown; the selector loop
# tears down cleanly (matches the Orchestrator integration conftest).
if sys.platform == "win32":
    with contextlib.suppress(Exception):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

_ORCH_TEST_SECRET = "seam-orch-inbound-secret"  # noqa: S105 - test-only fake
_DELTA_URL = "http://delta/v1/ingest/usage"


# --------------------------------------------------------------------------- pg helpers
def _pg_parts(url: str):
    return re.match(r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


def _sync_dsn(url: str) -> str:
    return re.sub(r"^postgresql\+\w+://", "postgresql://", url)


def _orch_upgrade_head() -> subprocess.CompletedProcess:
    """Run `alembic upgrade head` for the Orchestrator (literal argv — no dynamic input)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_ORCH_SRC)
    return subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_ORCH_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _provision_orch_app() -> None:
    """ALTER ROLE orchestrator_app with a SCRAM verifier (idempotent, opt-in)."""
    if os.environ.get("ORCH_PROVISION_APP_ROLE") != "1":
        return
    app_url = os.environ.get("ORCH_APP_DATABASE_URL", "")
    m = re.match(r"postgresql(?:\+\w+)?://[^:]+:([^@]+)@", app_url)
    if not m:
        return
    import psycopg

    app_pw = m.group(1)
    salt = os.urandom(16)
    iters = 4096
    salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
    ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    verifier = (
        f"SCRAM-SHA-256${iters}"
        f":{base64.b64encode(salt).decode()}"
        f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
        f":{base64.b64encode(sk).decode()}"
    )
    with psycopg.connect(_sync_dsn(os.environ["ORCH_DATABASE_URL"]), autocommit=True) as conn:
        conn.execute(f"ALTER ROLE orchestrator_app WITH PASSWORD '{verifier}'")  # noqa: S608


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module", autouse=True)
def _orchestrator_ready() -> None:
    """Bring the Orchestrator DB to head + provision its app role (idempotent)."""
    os.environ.setdefault("ORCH_INGEST_HMAC_SECRET", _ORCH_TEST_SECRET)
    os.environ.setdefault("ORCH_DB_NULLPOOL", "1")  # robust under per-function loops
    os.environ.setdefault("ORCH_DB_SSL", "disable")  # local/CI Postgres has TLS off
    result = _orch_upgrade_head()
    if result.returncode != 0:
        pytest.fail(f"orchestrator alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")
    _provision_orch_app()


@pytest_asyncio.fixture(autouse=True)
async def _reset_orch_engines():
    """Reset the Orchestrator engine singletons around each test (current-loop binding)."""
    from orchestrator.persistence import database as odb

    await odb.reset_engines()
    yield
    await odb.reset_engines()


# --------------------------------------------------------------------------- signing + envelope
def _orch_sign(body: bytes, secret: bytes, ts: int | None = None) -> dict[str, str]:
    """Sentinel->Orchestrator inbound HMAC headers (X-Sentinel-*), over f'{ts}.'+body."""
    stamp = int(time.time()) if ts is None else int(ts)
    signed = f"{stamp}.".encode("utf-8") + body
    digest = hmac.new(secret, signed, hashlib.sha256).hexdigest()
    return {
        "X-Sentinel-Signature": f"sha256={digest}",
        "X-Sentinel-Timestamp": str(stamp),
        "Content-Type": "application/json",
    }


def _usage_envelope(payload: dict) -> dict:
    """Wrap a UsageEvent payload in a contract-valid O-002 envelope.

    The three consumer invariants hold by construction: event_type == payload.event_type,
    idempotency_key == payload.event_id, source_product == 'sentinel'.
    """
    return {
        "schema_version": 1,
        "envelope_id": str(uuid.uuid4()),
        "event_type": "usage",
        "source_product": "sentinel",
        "occurred_at": "2026-06-26T12:00:01Z",
        "idempotency_key": payload["event_id"],
        "sequence": 1024,
        "correlation_id": payload["request_id"],
        "payload": payload,
    }


async def _post_to_orchestrator(envelope: dict) -> httpx.Response:
    from orchestrator.app import create_app as orch_create_app

    orch_app = orch_create_app()
    body = json.dumps(envelope).encode("utf-8")
    headers = _orch_sign(body, os.environ["ORCH_INGEST_HMAC_SECRET"].encode("utf-8"))
    transport = httpx.ASGITransport(app=orch_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orchestrator") as oc:
        return await oc.post("/v1/ingest/events", content=body, headers=headers)


async def _orch_outbox_status(idempotency_key: str) -> str | None:
    import asyncpg

    m = _pg_parts(os.environ["ORCH_DATABASE_URL"])
    conn = await asyncpg.connect(
        user=m.group(1),
        password=m.group(2),
        host=m.group(3),
        port=int(m.group(4)),
        database=m.group(5),
        ssl=False,
    )
    try:
        return await conn.fetchval(
            "SELECT status FROM forward_outbox WHERE idempotency_key = $1", idempotency_key
        )
    finally:
        await conn.close()


# --------------------------------------------------------------------------- the seam test
async def test_real_orchestrator_to_delta_seam(client, usage_event, tenant_id, read_tenant_ledger):
    from orchestrator.dispatch.dispatcher import dispatch_pending

    payload = usage_event(tenant_id, cost=1234)
    envelope = _usage_envelope(payload)
    key = envelope["idempotency_key"]

    # 1. REAL Orchestrator inbound: persists ingest_events + a 'pending' forward_outbox row.
    accepted = await _post_to_orchestrator(envelope)
    assert accepted.status_code == 202, accepted.text
    assert await _orch_outbox_status(key) == "pending"

    # 2. REAL dispatcher drains the outbox to the REAL Delta app (via the ASGI client).
    summary = await dispatch_pending(_DELTA_URL, http_client=client)
    assert summary.forwarded >= 1
    assert summary.scanned >= 1

    # 3. Exactly one balanced debit landed in the Delta ledger for this tenant.
    snap = await read_tenant_ledger(tenant_id)
    assert snap["txns"] == 1
    assert snap["entries"] == 2
    assert snap["debit"] == 1234
    assert snap["credit"] == 1234
    assert snap["balanced"] is True

    # 4. The outbox row flipped 'pending' -> 'forwarded'.
    assert await _orch_outbox_status(key) == "forwarded"

    # 5. Idempotent end to end: re-deliver the SAME envelope (Orchestrator dedup -> no new
    #    outbox row), then drain again. Delta still holds exactly ONE debit — no duplicate.
    replay = await _post_to_orchestrator(envelope)
    assert replay.status_code == 202, replay.text
    await dispatch_pending(_DELTA_URL, http_client=client)

    snap2 = await read_tenant_ledger(tenant_id)
    assert snap2["txns"] == 1
    assert snap2["entries"] == 2
    assert snap2["debit"] == 1234
