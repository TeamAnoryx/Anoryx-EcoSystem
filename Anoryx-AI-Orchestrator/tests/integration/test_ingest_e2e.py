"""Non-stubbed end-to-end ingest tests on a REAL Postgres (O-003, ADR-0003).

Proves the REAL path through the HMAC receiver → structural validation → pipeline → DB,
with NOTHING stubbed on the path under test:
  * a valid signed ingest persists in ingest_events with a valid ingest_audit_log chain
    link + a forward_outbox intent row;
  * a duplicate idempotency_key dedupes (no second ingest_events row);
  * a bad-version event reject-to-DLQs as a dead_letter_queue failure-envelope row;
  * RLS isolates tenants live (a tenant-B session cannot see tenant-A's row);
  * the hash chain is tamper-evident on a real DB mutation;
  * the narrow `except IntegrityError` does NOT swallow a logic error (ADR-0026).

The `db_conn` fixture is a live privileged (BYPASSRLS) asyncpg connection (see conftest).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time

import httpx
import pytest

pytestmark = pytest.mark.integration

_TEST_SECRET = "e2e-ingest-secret"  # noqa: S105 - test-only fake


def _sign_and_headers(body: bytes, *, secret: bytes, ts: int | None = None) -> dict[str, str]:
    ts = ts if ts is not None else int(time.time())
    signed = f"{ts}.".encode("utf-8") + body
    digest = hmac.new(secret, signed, hashlib.sha256).hexdigest()
    return {
        "X-Sentinel-Signature": f"sha256={digest}",
        "X-Sentinel-Timestamp": str(ts),
        "Content-Type": "application/json",
    }


async def _post(app, envelope: dict, *, secret: str = _TEST_SECRET, ts: int | None = None):
    body = json.dumps(envelope).encode("utf-8")
    headers = _sign_and_headers(body, secret=secret.encode("utf-8"), ts=ts)
    # raise_app_exceptions=False so a 5xx the app's fail-safe handler SENDS is returned to
    # the client (as a real HTTP server would) instead of being re-raised into the test —
    # the 202 paths never raise, so this only affects the deliberate fail-safe (503) case.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/v1/ingest/events", content=body, headers=headers)


@pytest.fixture
def app(db_ready, monkeypatch):
    """Construct the ingest app with a deterministic test HMAC secret."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", _TEST_SECRET)
    from orchestrator.app import create_app

    return create_app()


async def test_valid_ingest_persists_with_chain_and_outbox(app, db_conn, make_valid_envelope):
    env = make_valid_envelope()
    resp = await _post(app, env)
    assert resp.status_code == 202, resp.text
    assert resp.json() == {"status": "accepted", "event_id": env["idempotency_key"]}

    row = await db_conn.fetchrow(
        "SELECT * FROM ingest_events WHERE idempotency_key = $1", env["idempotency_key"]
    )
    assert row is not None
    assert row["tenant_id"] == env["payload"]["tenant_id"]
    assert row["source_sequence"] == env["sequence"]
    chain = await db_conn.fetchrow(
        "SELECT * FROM ingest_audit_log WHERE idempotency_key = $1 AND disposition = 'accepted'",
        env["idempotency_key"],
    )
    assert chain is not None
    outbox = await db_conn.fetchrow(
        "SELECT * FROM forward_outbox WHERE idempotency_key = $1", env["idempotency_key"]
    )
    assert outbox is not None
    assert outbox["status"] == "pending"

    # The full chain validates (real recompute through the production code).
    from orchestrator.persistence import repositories as repo
    from orchestrator.persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        assert await repo.validate_chain(session) is True


async def test_duplicate_idempotency_key_dedupes(app, db_conn, make_valid_envelope):
    env = make_valid_envelope()
    assert (await _post(app, env)).status_code == 202
    assert (await _post(app, env)).status_code == 202  # re-deliver the SAME signed envelope

    count = await db_conn.fetchval(
        "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1",
        env["idempotency_key"],
    )
    assert count == 1  # deduped — no second row


async def test_bad_version_reject_to_dlq(app, db_conn, make_valid_envelope):
    env = make_valid_envelope()
    env["schema_version"] = 2  # unknown version — structurally valid, pipeline → DLQ
    resp = await _post(app, env)
    assert resp.status_code == 202  # received + durably recorded (as a DLQ entry)

    dlq = await db_conn.fetchrow(
        "SELECT * FROM dead_letter_queue WHERE original_envelope->>'envelope_id' = $1",
        env["envelope_id"],
    )
    assert dlq is not None
    assert dlq["reason"] == "unknown_schema_version"
    assert dlq["event_type"] == "policy_decision_deny"
    # No event row was persisted for a dead-lettered envelope.
    events = await db_conn.fetchval(
        "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1",
        env["idempotency_key"],
    )
    assert events == 0
    # A dead_lettered chain link was appended.
    chain = await db_conn.fetchrow(
        "SELECT * FROM ingest_audit_log WHERE dlq_id = $1", dlq["dlq_id"]
    )
    assert chain is not None
    assert chain["disposition"] == "dead_lettered"
    assert chain["dlq_reason"] == "unknown_schema_version"


_OTHER_TENANT = "00000000-0000-4000-8000-000000000000"


async def test_rls_isolates_tenants_live(app, app_db_conn, make_valid_envelope):
    """RLS isolation via the live orchestrator_app (NOBYPASSRLS) role + the tenant GUC —
    the exact DB-level isolation the runtime get_tenant_session relies on."""
    env = make_valid_envelope()
    assert (await _post(app, env)).status_code == 202
    tenant_a = env["payload"]["tenant_id"]
    key = env["idempotency_key"]

    # Scoped to tenant A: the row is visible.
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", key
        )
        == 1
    )

    # Scoped to a different tenant: RLS hides it (NOBYPASSRLS role cannot widen).
    await app_db_conn.execute(
        "SELECT set_config('app.current_tenant_id', $1, false)", _OTHER_TENANT
    )
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", key
        )
        == 0
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="SQLAlchemy+asyncpg direct connect from the bare test coroutine is flaky on "
    "Windows (WinError 10054); the runtime path is exercised on Linux CI. RLS isolation is "
    "also proven Windows-robustly via the orchestrator_app raw conn in the test above.",
)
async def test_rls_isolation_via_get_tenant_session(app, make_valid_envelope):
    """Linux/CI: prove RLS through the EXACT runtime path — get_tenant_session (autobegin,
    no session.begin()) on the app role — not just the DB-level equivalent."""
    env = make_valid_envelope()
    assert (await _post(app, env)).status_code == 202
    key = env["idempotency_key"]
    tenant_a = env["payload"]["tenant_id"]

    from sqlalchemy import text

    from orchestrator.persistence.database import get_tenant_session

    async with get_tenant_session(tenant_a) as session:
        seen = await session.execute(
            text("SELECT count(*) FROM ingest_events WHERE idempotency_key = :k"), {"k": key}
        )
        assert seen.scalar_one() == 1
    async with get_tenant_session(_OTHER_TENANT) as session:
        hidden = await session.execute(
            text("SELECT count(*) FROM ingest_events WHERE idempotency_key = :k"), {"k": key}
        )
        assert hidden.scalar_one() == 0


async def test_chain_is_tamper_evident_on_real_db(app, db_conn, make_valid_envelope):
    env = make_valid_envelope()
    assert (await _post(app, env)).status_code == 202

    from orchestrator.persistence import repositories as repo
    from orchestrator.persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        assert await repo.validate_chain(session) is True

    # Tamper at the DB layer (bypass the append-only trigger as superuser), then restore.
    original = await db_conn.fetchval(
        "SELECT tenant_id FROM ingest_audit_log WHERE idempotency_key = $1 "
        "AND disposition = 'accepted'",
        env["idempotency_key"],
    )
    await db_conn.execute("ALTER TABLE ingest_audit_log DISABLE TRIGGER trg_ial_deny_update")
    try:
        await db_conn.execute(
            "UPDATE ingest_audit_log SET tenant_id = $1 WHERE idempotency_key = $2 "
            "AND disposition = 'accepted'",
            "00000000-0000-4000-8000-000000000000",
            env["idempotency_key"],
        )
        async with get_privileged_session() as session:
            assert await repo.validate_chain(session) is False  # tamper detected
        # Restore so the global chain validates for other tests.
        await db_conn.execute(
            "UPDATE ingest_audit_log SET tenant_id = $1 WHERE idempotency_key = $2 "
            "AND disposition = 'accepted'",
            original,
            env["idempotency_key"],
        )
    finally:
        await db_conn.execute("ALTER TABLE ingest_audit_log ENABLE TRIGGER trg_ial_deny_update")

    async with get_privileged_session() as session:
        assert await repo.validate_chain(session) is True  # restored


async def test_logic_error_not_swallowed_returns_503(
    app, db_conn, monkeypatch, make_valid_envelope
):
    """ADR-0026: a logic error (InvalidRequestError — the double-begin class) injected into
    the insert path must NOT be swallowed by the narrow `except IntegrityError`. Driven
    end-to-end through the app: it propagates to the fail-safe handler → 503 (a BLOCK),
    never a 202. A swallow would have produced a benign 202 + a persisted row.
    """
    from sqlalchemy.exc import InvalidRequestError

    from orchestrator.persistence import repositories as repo

    async def _boom(*_args, **_kwargs):
        raise InvalidRequestError("simulated double-begin / logic defect")

    monkeypatch.setattr(repo, "insert_ingest_event", _boom)

    env = make_valid_envelope()
    resp = await _post(app, env)
    assert resp.status_code == 503  # fail-safe BLOCK, NOT 202 (the error was not swallowed)
    count = await db_conn.fetchval(
        "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", env["idempotency_key"]
    )
    assert count == 0  # nothing persisted — the insert failed and was not silently accepted


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="SQLAlchemy+asyncpg direct connect from the bare test coroutine is flaky on "
    "Windows (WinError 10054); exercised on Linux CI. The no-swallow behaviour is also "
    "proven Windows-robustly end-to-end (503) in the test above.",
)
async def test_logic_error_propagates_direct(db_ready, monkeypatch, make_valid_envelope):
    """Linux/CI: assert process_envelope RAISES the injected logic error directly (the
    narrow `except IntegrityError` does not catch InvalidRequestError)."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", _TEST_SECRET)
    from sqlalchemy.exc import InvalidRequestError

    from orchestrator.config import get_ingest_settings
    from orchestrator.persistence import repositories as repo
    from orchestrator.pipeline.ingest_pipeline import process_envelope

    async def _boom(*_args, **_kwargs):
        raise InvalidRequestError("simulated double-begin / logic defect")

    monkeypatch.setattr(repo, "insert_ingest_event", _boom)
    env = make_valid_envelope()
    with pytest.raises(InvalidRequestError):
        await process_envelope(env, settings=get_ingest_settings())
