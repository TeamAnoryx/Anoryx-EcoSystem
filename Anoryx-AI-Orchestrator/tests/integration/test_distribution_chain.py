"""Distribution audit hash-chain integrity on a REAL DB (O-004, ADR-0004).

The distribution_audit_log is a global, append-only, hash-chained ledger (its own genesis +
advisory-lock key, distinct from the ingest chain). This proves, end-to-end through the real
append path (a seeded `submitted` link + the engine's `distributed` links):
  * validate_distribution_chain() recomputes every row_hash and links it to its predecessor
    → True on an untampered chain;
  * a DB-level mutation (bypassing the append-only trigger as superuser) is detected → False,
    then restored → True.
"""

from __future__ import annotations

import uuid

import pytest

from orchestrator.distribution.engine import drive_distribution
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session

pytestmark = pytest.mark.integration

ORCH_SERVICE_TOKEN = "o004-orch-service-token"  # noqa: S105 - test-only fake
_TARGET = "sentinel-test"


@pytest.fixture
def dist_app(sentinel_db_ready, sentinel_shim_server, monkeypatch):
    import json

    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "o004-ingest-secret")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", ORCH_SERVICE_TOKEN)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "o004-sentinel-admin-token")
    monkeypatch.setenv("ORCH_DISTRIBUTION_TARGETS", json.dumps({_TARGET: sentinel_shim_server}))
    monkeypatch.setenv("ORCH_SENTINEL_INTAKE_PATH", "/admin/policies/intake")
    monkeypatch.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "2")

    from orchestrator.app import create_app

    return create_app()


async def test_distribution_chain_validates_and_is_tamper_evident(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
):
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy("model_allowlist", tenant_id=tenant, allowed_model_ids=["gpt-4o"])
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )
    await drive_distribution(distribution_id, tenant, settings=dist_app.state.distribution_settings)

    # The real append path produced a contiguous chain (submitted + distributed links).
    async with get_privileged_session() as session:
        assert await repo.validate_distribution_chain(session) is True

    # Tamper one row at the DB layer (disable the append-only trigger as superuser), then restore.
    original = await db_conn.fetchval(
        "SELECT policy_type FROM distribution_audit_log WHERE distribution_id = $1 "
        "ORDER BY sequence_number ASC LIMIT 1",
        distribution_id,
    )
    await db_conn.execute("ALTER TABLE distribution_audit_log DISABLE TRIGGER trg_dal_deny_update")
    try:
        await db_conn.execute(
            "UPDATE distribution_audit_log SET policy_type = $1 WHERE distribution_id = $2 "
            "AND sequence_number = (SELECT MIN(sequence_number) FROM distribution_audit_log "
            "WHERE distribution_id = $2)",
            "tampered_type",
            distribution_id,
        )
        async with get_privileged_session() as session:
            assert await repo.validate_distribution_chain(session) is False  # tamper detected
        # Restore so the global chain validates for any later test.
        await db_conn.execute(
            "UPDATE distribution_audit_log SET policy_type = $1 WHERE distribution_id = $2 "
            "AND sequence_number = (SELECT MIN(sequence_number) FROM distribution_audit_log "
            "WHERE distribution_id = $2)",
            original,
            distribution_id,
        )
    finally:
        await db_conn.execute(
            "ALTER TABLE distribution_audit_log ENABLE TRIGGER trg_dal_deny_update"
        )

    async with get_privileged_session() as session:
        assert await repo.validate_distribution_chain(session) is True  # restored
