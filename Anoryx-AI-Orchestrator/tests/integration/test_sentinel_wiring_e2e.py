"""X-001 — Sentinel <-> Orchestrator wiring validated (ADR-0016, non-stubbed).

Every existing O-003 ingest test (test_ingest_e2e.py) drives Orchestrator's real receiver
with a HAND-TYPED envelope from `make_valid_envelope` -- useful for pipeline-internals
coverage, but it never proves that a genuinely Sentinel-produced event is shaped the way
Orchestrator expects. This file closes that gap for X-001: it drives Sentinel's REAL F-005
secret detector + HookContext stamping logic (the exact functions `HookContext.emit()` calls
in production, imported unmodified from the installed Sentinel package) to produce an actual
event payload, wraps it in the real O-002 envelope, signs it with Sentinel's REAL F-020/ADR-0002
signer (`orchestration.webhooks.signer.sign_body` -- ADR-0003 documents this as the mirrored
contract for this seam), and POSTs it into Orchestrator's real ingest app.

Scope boundary (honesty, ADR-0016): this proves the EVENT SHAPE + HMAC TRANSPORT are
compatible end-to-end. It does NOT re-drive Sentinel's own audit-log append / hash-chain
path -- Sentinel's own non-stubbed suite (Anoryx-Sentinel/tests/orchestration/test_integration.py)
already proves that in-product path. `HookContext._stamp_event` (a pure function, the exact
logic `emit()` runs before appending) is used here to obtain the real production payload shape
without requiring a live Sentinel database in this suite.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration

_TEST_SECRET = "x-001-wiring-e2e-secret"  # noqa: S105 - test-only fake


async def _build_real_sentinel_envelope() -> dict:
    """Return a real O-002 envelope wrapping a genuinely Sentinel-produced secret_leaked event.

    Drives Sentinel's REAL SecretInboundHook (F-005 regex+entropy detector) against an
    OpenAI-key-shaped string, then stamps the resulting event through HookContext's REAL
    production stamping logic. Nothing about the event shape below is hand-typed by this test.
    """
    from gateway.context import TenantContext
    from orchestration.config import OrchestrationSettings
    from orchestration.context import HookContext
    from orchestration.detectors.secret_detector import SecretInboundHook

    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    request_id = "req-" + uuid.uuid4().hex[:24]
    leaked_content = "here is my key sk-abcdefghijklmnopqrstuvwxyz0123456789"

    tenant_context = TenantContext(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
        virtual_key_id=str(uuid.uuid4()),
    )
    ctx = HookContext(
        tenant_context=tenant_context,
        request_id=request_id,
        original_user_content=leaked_content,
        phase="pre_request",
    )

    hook = SecretInboundHook(settings=OrchestrationSettings())
    result = await hook.inspect(leaked_content, ctx)
    assert result.action == "block", "fixture secret must trip the real detector"
    assert result.event is not None

    # The exact stamping logic HookContext.emit() runs before appending to the audit log.
    stamped = ctx._stamp_event(result.event, detector_slug=SecretInboundHook.detector_slug)

    return {
        "schema_version": 1,
        "envelope_id": str(uuid.uuid4()),
        "event_type": stamped["event_type"],
        "source_product": "sentinel",
        "occurred_at": stamped["event_timestamp"],
        "idempotency_key": stamped["event_id"],
        "sequence": 1,
        "correlation_id": stamped["request_id"],
        "payload": stamped,
    }


def _sign(envelope: dict, *, secret: str = _TEST_SECRET) -> tuple[bytes, dict[str, str]]:
    """Sign *envelope* with Sentinel's REAL outbound signer (mirrors production, ADR-0003)."""
    from orchestration.webhooks.signer import sign_body

    body_str = json.dumps(envelope)
    signed = sign_body(secret.encode("utf-8"), body_str)
    headers = {
        "X-Sentinel-Signature": signed.x_sentinel_signature,
        "X-Sentinel-Timestamp": signed.x_sentinel_timestamp,
        "Content-Type": "application/json",
    }
    return body_str.encode("utf-8"), headers


async def _post(app, body: bytes, headers: dict[str, str]):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/v1/ingest/events", content=body, headers=headers)


@pytest.fixture
async def app(db_ready, monkeypatch):
    """Construct the real Orchestrator ingest app with a deterministic test HMAC secret.

    Resets the module-global engine singletons first (ADR-0026 discipline): this file
    collects after test_migration_roundtrip.py, whose downgrade/upgrade cycle recreates
    every table: a connection pool populated before that cycle would otherwise be reused
    here, giving stale relation state for a role-permission check on the recreated table.
    """
    from orchestrator.persistence import database as db

    await db.reset_engines()
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", _TEST_SECRET)
    from orchestrator.app import create_app

    return create_app()


async def test_real_sentinel_event_ingested_end_to_end(app, db_conn):
    """A genuinely Sentinel-produced event is accepted, persisted, and chain-valid."""
    envelope = await _build_real_sentinel_envelope()
    body, headers = _sign(envelope)

    resp = await _post(app, body, headers)
    assert resp.status_code == 202, resp.text
    assert resp.json() == {"status": "accepted", "event_id": envelope["idempotency_key"]}

    payload = envelope["payload"]
    row = await db_conn.fetchrow(
        "SELECT * FROM ingest_events WHERE idempotency_key = $1", envelope["idempotency_key"]
    )
    assert row is not None
    assert row["tenant_id"] == payload["tenant_id"]
    assert row["team_id"] == payload["team_id"]
    assert row["project_id"] == payload["project_id"]
    assert row["event_type"] == "secret_leaked"
    assert row["source_sequence"] == envelope["sequence"]

    chain = await db_conn.fetchrow(
        "SELECT * FROM ingest_audit_log WHERE idempotency_key = $1 AND disposition = 'accepted'",
        envelope["idempotency_key"],
    )
    assert chain is not None

    # The full chain validates (real recompute through the production code).
    from orchestrator.persistence import repositories as repo
    from orchestrator.persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        assert await repo.validate_chain(session) is True


async def test_real_sentinel_event_rls_isolated_by_its_own_tenant_id(app, app_db_conn):
    """RLS scoping uses the real tenant_id Sentinel's own code resolved -- not a test double."""
    envelope = await _build_real_sentinel_envelope()
    body, headers = _sign(envelope)

    resp = await _post(app, body, headers)
    assert resp.status_code == 202, resp.text

    tenant_id = envelope["payload"]["tenant_id"]
    key = envelope["idempotency_key"]
    other_tenant = str(uuid.uuid4())

    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_id)
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", key
        )
        == 1
    )

    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", other_tenant)
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", key
        )
        == 0
    )


async def test_tampered_real_sentinel_event_rejected_before_persist(app, db_conn):
    """A byte flipped after Sentinel's real signature is computed is rejected, not ingested.

    Proves the wiring's security boundary: Orchestrator never trusts an envelope shape it
    merely recognizes -- the HMAC Sentinel's own signer computed must still verify.
    """
    envelope = await _build_real_sentinel_envelope()
    body, headers = _sign(envelope)

    tampered = json.loads(body)
    tampered["payload"]["secret_type"] = "private_key"  # noqa: S105 - differs from signed value
    tampered_body = json.dumps(tampered).encode("utf-8")

    resp = await _post(app, tampered_body, headers)
    assert resp.status_code == 403, resp.text

    count = await db_conn.fetchval(
        "SELECT count(*) FROM ingest_events WHERE idempotency_key = $1", envelope["idempotency_key"]
    )
    assert count == 0
