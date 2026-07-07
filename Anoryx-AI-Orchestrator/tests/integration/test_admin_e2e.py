"""Non-stubbed admin-API read seams on a REAL Postgres (O-007, ADR-0007).

Proves the two NEW cross-tenant admin reads on the real privileged-session path:
  1. `list_recent_events_admin` sees BOTH tenant A's and tenant B's ingest_events rows
     (deliberately cross-tenant — the honesty-boundary opposite of the O-006 per-tenant
     `/v1/events` seam) and projects metadata only (never `payload`).
  2. `list_recent_distributions_admin` sees distributions across tenants and projects only
     the AdminDistributionSummary columns — never `signed_record` / `content_hash`.
  3. Both reads are newest-first and `limit`-bounded.

Seeding uses the privileged conn directly (events) and the real tenant-session insert path
(distributions, mirroring `distribution/router.py`) so the rows are genuinely persisted, not
mocked.
"""

from __future__ import annotations

import uuid

import pytest

from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    insert_policy_distribution,
    list_recent_distributions_admin,
    list_recent_events_admin,
)

pytestmark = pytest.mark.integration


async def _seed_event(db_conn, tenant_id: str, *, event_type: str = "policy_decision_deny") -> str:
    """INSERT one ingest_events row for *tenant_id* on the privileged conn; return its event_id."""
    eid = str(uuid.uuid4())
    short = eid[:8]
    await db_conn.execute(
        "INSERT INTO ingest_events (envelope_id, idempotency_key, source_product, "
        "source_sequence, schema_version, occurred_at, correlation_id, event_id, event_type, "
        "event_timestamp, request_id, tenant_id, team_id, project_id, agent_id, payload, "
        "content_hash) VALUES ($1, $2, 'sentinel', 1024, 1, '2026-07-01T12:00:01Z', $3, $4, "
        "$5, '2026-07-01T12:00:00Z', $6, $7, $8, $9, 'gateway-core', $10::jsonb, $11)",
        str(uuid.uuid4()),
        eid,
        "req-" + short,
        eid,
        event_type,
        "req-" + short,
        tenant_id,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        '{"note": "secret payload must never appear on the admin read seam"}',
        "a" * 64,
    )
    return eid


async def _seed_distribution(tenant_id: str, *, policy_type: str = "budget_limit") -> str:
    """Persist one policy_distributions row for *tenant_id* via the real tenant-session path."""
    distribution_id = str(uuid.uuid4())
    async with get_tenant_session(tenant_id) as session:
        await insert_policy_distribution(
            session,
            {
                "distribution_id": distribution_id,
                "policy_id": str(uuid.uuid4()),
                "policy_version": 1,
                "tenant_id": tenant_id,
                "policy_type": policy_type,
                "state": "pending",
                "signed_record": {"secret": "policy body must never appear on the admin read"},
                "content_hash": "b" * 64,
            },
        )
        await session.commit()
    return distribution_id


async def test_recent_events_is_cross_tenant_and_metadata_only(db_conn) -> None:
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    event_a = await _seed_event(db_conn, tenant_a)
    event_b = await _seed_event(db_conn, tenant_b)

    async with get_privileged_session() as session:
        rows = await list_recent_events_admin(session, limit=200)

    ids = {row["event_id"] for row in rows}
    assert event_a in ids
    assert event_b in ids  # cross-tenant by design — NOT tenant-scoped like /v1/events
    for row in rows:
        assert "payload" not in row


async def test_recent_events_is_newest_first_and_limit_bounded(db_conn) -> None:
    tenant_id = str(uuid.uuid4())
    older = await _seed_event(db_conn, tenant_id)
    newer = await _seed_event(db_conn, tenant_id)

    async with get_privileged_session() as session:
        rows = await list_recent_events_admin(session, limit=1)

    assert len(rows) == 1
    assert rows[0]["event_id"] == newer
    assert rows[0]["event_id"] != older


async def test_recent_distributions_is_cross_tenant_and_never_leaks_policy_body(db_ready) -> None:
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    dist_a = await _seed_distribution(tenant_a)
    dist_b = await _seed_distribution(tenant_b)

    async with get_privileged_session() as session:
        rows = await list_recent_distributions_admin(session, limit=200)

    ids = {row["distribution_id"] for row in rows}
    assert dist_a in ids
    assert dist_b in ids
    for row in rows:
        assert "signed_record" not in row
        assert "content_hash" not in row
        assert set(row) == {
            "distribution_id",
            "policy_id",
            "tenant_id",
            "policy_type",
            "state",
            "created_at",
        }


async def test_recent_distributions_is_newest_first_and_limit_bounded(db_ready) -> None:
    tenant_id = str(uuid.uuid4())
    older = await _seed_distribution(tenant_id)
    newer = await _seed_distribution(tenant_id)

    async with get_privileged_session() as session:
        rows = await list_recent_distributions_admin(session, limit=1)

    assert len(rows) == 1
    assert rows[0]["distribution_id"] == newer
    assert rows[0]["distribution_id"] != older
