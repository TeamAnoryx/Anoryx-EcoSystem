"""Non-stubbed command-center + guarded-rollback e2e (O-014, ADR-0014).

Drives the REAL FastAPI app over httpx.ASGITransport (real auth resolution, real DB
writes) on a fresh Postgres, proving:

  * A rollback re-submits the immediately-prior distribution's signed_record
    byte-for-byte as a brand-new distribution, targeting the SAME sentinel_ids the prior
    distribution targeted.
  * The rollback-correlation chain records the correct (source, superseded, new)
    distribution-id triple and validates in full.
  * A rollback attempted with fewer than two distributions for the (tenant_id, policy_id)
    pair is a genuine 409 `nothing_to_roll_back_to`.
  * The command-center summary reflects real seeded registry/distribution data.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_rollback_chain

pytestmark = pytest.mark.integration

_ADMIN_TOKEN = "o014-operator-token"  # noqa: S105 - test-only fake


def _app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    from orchestrator.app import create_app

    return create_app()


async def _client(app) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://orch")


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


async def _seed_distribution(
    db_conn, *, tenant_id: str, policy_id: str, policy_version: int, targets: list[str]
) -> str:
    """INSERT one policy_distributions row + its targets (privileged conn)."""
    distribution_id = str(uuid.uuid4())
    signed_record = {
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_type": "budget_limit",
        "note": f"version {policy_version}",
    }
    content_hash = "a" * 63 + str(policy_version % 10)
    await db_conn.execute(
        "INSERT INTO policy_distributions "
        "(distribution_id, policy_id, policy_version, tenant_id, policy_type, state, "
        "signed_record, content_hash) VALUES ($1, $2, $3, $4, 'budget_limit', 'distributed', "
        "$5::jsonb, $6)",
        distribution_id,
        policy_id,
        policy_version,
        tenant_id,
        json.dumps(signed_record),
        content_hash,
    )
    for sentinel_id in targets:
        await db_conn.execute(
            "INSERT INTO policy_distribution_targets "
            "(target_id, distribution_id, tenant_id, sentinel_id, state, attempt_count, "
            "max_attempts) VALUES ($1, $2, $3, $4, 'distributed', 1, 5)",
            str(uuid.uuid4()),
            distribution_id,
            tenant_id,
            sentinel_id,
        )
    return distribution_id


async def test_rollback_restores_prior_signed_record_and_targets(
    command_center_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_id = str(uuid.uuid4())
    policy_id = "policy-" + uuid.uuid4().hex[:8]

    dist_v1 = await _seed_distribution(
        db_conn, tenant_id=tenant_id, policy_id=policy_id, policy_version=1, targets=["sentinel-a"]
    )
    dist_v2 = await _seed_distribution(
        db_conn, tenant_id=tenant_id, policy_id=policy_id, policy_version=2, targets=["sentinel-a"]
    )

    async with await _client(app) as client:
        resp = await client.post(
            "/v1/admin/policy-distributions/rollback",
            headers=_admin_headers(),
            json={"tenant_id": tenant_id, "policy_id": policy_id},
        )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["rolled_back_to_distribution_id"] == dist_v1
    assert body["superseded_distribution_id"] == dist_v2
    new_distribution_id = body["distribution_id"]
    assert new_distribution_id not in (dist_v1, dist_v2)

    row = await db_conn.fetchrow(
        "SELECT signed_record, content_hash, policy_version FROM policy_distributions "
        "WHERE distribution_id = $1",
        new_distribution_id,
    )
    assert row is not None
    original = await db_conn.fetchrow(
        "SELECT signed_record, content_hash, policy_version FROM policy_distributions "
        "WHERE distribution_id = $1",
        dist_v1,
    )
    assert json.loads(row["signed_record"]) == json.loads(original["signed_record"])
    assert row["content_hash"] == original["content_hash"]
    assert row["policy_version"] == original["policy_version"]

    target_sentinel_ids = {
        r["sentinel_id"]
        for r in await db_conn.fetch(
            "SELECT sentinel_id FROM policy_distribution_targets WHERE distribution_id = $1",
            new_distribution_id,
        )
    }
    assert target_sentinel_ids == {"sentinel-a"}

    correlation = await db_conn.fetchrow(
        "SELECT source_distribution_id, superseded_distribution_id, new_distribution_id "
        "FROM distribution_rollbacks WHERE new_distribution_id = $1",
        new_distribution_id,
    )
    assert correlation is not None
    assert correlation["source_distribution_id"] == dist_v1
    assert correlation["superseded_distribution_id"] == dist_v2

    async with get_privileged_session() as session:
        assert await validate_rollback_chain(session) is True


async def test_rollback_with_only_one_distribution_is_409(
    command_center_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_id = str(uuid.uuid4())
    policy_id = "policy-" + uuid.uuid4().hex[:8]
    await _seed_distribution(
        db_conn, tenant_id=tenant_id, policy_id=policy_id, policy_version=1, targets=[]
    )

    async with await _client(app) as client:
        resp = await client.post(
            "/v1/admin/policy-distributions/rollback",
            headers=_admin_headers(),
            json={"tenant_id": tenant_id, "policy_id": policy_id},
        )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"]["code"] == "nothing_to_roll_back_to"


async def test_summary_reflects_seeded_registry_and_distributions(
    command_center_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    sentinel_id = "sentinel-" + uuid.uuid4().hex[:8]
    await db_conn.execute(
        "INSERT INTO sentinel_registry (sentinel_id, endpoint, capabilities, health_status) "
        "VALUES ($1, 'https://example-sentinel.invalid', '[]'::jsonb, 'healthy')",
        sentinel_id,
    )
    tenant_id = str(uuid.uuid4())
    policy_id = "policy-" + uuid.uuid4().hex[:8]
    await _seed_distribution(
        db_conn, tenant_id=tenant_id, policy_id=policy_id, policy_version=1, targets=[]
    )

    async with await _client(app) as client:
        resp = await client.get("/v1/admin/command-center/summary", headers=_admin_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registry"]["healthy"] >= 1
    assert body["distributions"]["distributed"] >= 1
    assert set(body["registry"]) == {"unknown", "healthy", "degraded", "unreachable"}
    assert set(body["distributions"]) == {"pending", "distributed", "partial", "failed"}
