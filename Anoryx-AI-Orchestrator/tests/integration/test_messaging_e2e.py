"""Non-stubbed agent-messaging + shared-state-store e2e (O-012, ADR-0012).

Drives the REAL FastAPI app over httpx.ASGITransport (real auth resolution, real body
validation, real DB writes) on a fresh Postgres, proving:

  * Two real messages sent between two agents in the same tenant are durably recorded and
    the inbox read returns them ordered by sequence_number ASCENDING.
  * `since_sequence` is a genuine EXCLUSIVE lower bound (a second page only returns
    messages strictly after the cursor).
  * A duplicate send (same idempotency_key) is `disposition: "deduped"`, returns the
    ORIGINAL message's sequence_number/created_at unchanged, and does NOT create a second
    row.
  * A message never appears in another tenant's inbox poll (RLS isolation).
  * The agent-messaging hash chain validates in full, including both a `sent` and a
    `deduped` link for the SAME idempotency_key.
  * The shared-state store's create-only-if-absent / version-match / version-mismatch
    semantics are real (not merely documented).
  * TWO CONCURRENT state writers racing on the SAME (tenant_id, state_key) with the SAME
    expected_version: EXACTLY ONE wins (a genuine 409 for the other, never a silent
    overwrite) — the single most important correctness property of the optimistic-
    concurrency design, proven via real concurrent HTTP requests (httpx.AsyncClient +
    asyncio.gather), not a mocked race.
  * The shared-state hash chain validates in full, and a version-conflict rejection
    produces NO chain row (mirrors ADR-0011's automation_executions choice).
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import pytest
from sqlalchemy import text

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_messaging_chain, validate_state_chain

pytestmark = pytest.mark.integration


def _app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    from orchestrator.app import create_app

    return create_app()


def _message_body(**overrides) -> dict:
    body = {
        "sender_team_id": "team-1",
        "sender_project_id": "proj-1",
        "sender_agent_id": "agent-a",
        "recipient_team_id": "team-1",
        "recipient_project_id": "proj-1",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "body": {"hello": "world"},
        "idempotency_key": "msg-" + uuid.uuid4().hex,
    }
    body.update(overrides)
    return body


async def _client(app) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://orch")


# --------------------------------------------------------------------------- #
# Agent mailbox relay.
# --------------------------------------------------------------------------- #


async def test_send_persists_orders_and_paginates_inbox(
    messaging_ready, monkeypatch, seed_query_token, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    token = await seed_query_token(tenant)
    headers = {"Authorization": f"Bearer {token}"}

    async with await _client(app) as client:
        msg1 = _message_body()
        msg2 = _message_body()
        r1 = await client.post("/v1/messaging/messages", headers=headers, json=msg1)
        assert r1.status_code == 202
        assert r1.json()["disposition"] == "sent"
        r2 = await client.post("/v1/messaging/messages", headers=headers, json=msg2)
        assert r2.status_code == 202
        assert r2.json()["disposition"] == "sent"
        seq1 = r1.json()["sequence_number"]
        seq2 = r2.json()["sequence_number"]
        assert seq2 > seq1

        # Full inbox, ascending order.
        full = await client.get(
            "/v1/messaging/inbox/team-1/proj-1/agent-b", headers=headers, params={"limit": 200}
        )
        assert full.status_code == 200
        seqs = [row["sequence_number"] for row in full.json()["data"]]
        assert seqs == sorted(seqs)
        assert seq1 in seqs and seq2 in seqs

        # since_sequence is a genuine EXCLUSIVE lower bound.
        page2 = await client.get(
            "/v1/messaging/inbox/team-1/proj-1/agent-b",
            headers=headers,
            params={"since_sequence": seq1, "limit": 200},
        )
        assert page2.status_code == 200
        page2_seqs = {row["sequence_number"] for row in page2.json()["data"]}
        assert seq1 not in page2_seqs
        assert seq2 in page2_seqs

    count = await db_conn.fetchval(
        "SELECT count(*) FROM agent_messages WHERE idempotency_key IN ($1, $2)",
        msg1["idempotency_key"],
        msg2["idempotency_key"],
    )
    assert count == 2


async def test_duplicate_send_dedupes_and_both_attempts_are_chain_audited(
    messaging_ready, monkeypatch, seed_query_token, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    token = await seed_query_token(tenant)
    headers = {"Authorization": f"Bearer {token}"}
    msg = _message_body()

    async with await _client(app) as client:
        r1 = await client.post("/v1/messaging/messages", headers=headers, json=msg)
        assert r1.status_code == 202
        assert r1.json()["disposition"] == "sent"

        r2 = await client.post("/v1/messaging/messages", headers=headers, json=msg)
        assert r2.status_code == 202
        assert r2.json()["disposition"] == "deduped"
        assert r2.json()["sequence_number"] == r1.json()["sequence_number"]
        assert r2.json()["created_at"] == r1.json()["created_at"]

    count = await db_conn.fetchval(
        "SELECT count(*) FROM agent_messages WHERE idempotency_key = $1", msg["idempotency_key"]
    )
    assert count == 1  # still exactly one row -- no duplicate insert

    async with get_privileged_session() as session:
        result = await session.execute(
            text(
                "SELECT disposition FROM agent_messaging_audit_log WHERE idempotency_key = :k "
                "ORDER BY sequence_number ASC"
            ),
            {"k": msg["idempotency_key"]},
        )
        dispositions = result.scalars().all()
        assert dispositions == ["sent", "deduped"]
        assert await validate_messaging_chain(session) is True


async def test_message_is_invisible_from_another_tenants_inbox(
    messaging_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_a = await seed_query_token(tenant_a)
    token_b = await seed_query_token(tenant_b)
    msg = _message_body()

    async with await _client(app) as client:
        r1 = await client.post(
            "/v1/messaging/messages",
            headers={"Authorization": f"Bearer {token_a}"},
            json=msg,
        )
        assert r1.status_code == 202

        inbox_a = await client.get(
            "/v1/messaging/inbox/team-1/proj-1/agent-b",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert any(
            row["idempotency_key"] == msg["idempotency_key"] for row in inbox_a.json()["data"]
        )

        inbox_b = await client.get(
            "/v1/messaging/inbox/team-1/proj-1/agent-b",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert inbox_b.json()["data"] == []


# --------------------------------------------------------------------------- #
# Shared state store -- optimistic concurrency.
# --------------------------------------------------------------------------- #


async def test_state_create_update_and_conflict_semantics(
    messaging_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    token = await seed_query_token(tenant)
    headers = {"Authorization": f"Bearer {token}"}
    key = "counter-" + uuid.uuid4().hex

    async with await _client(app) as client:
        # create-only-if-absent.
        create = await client.put(
            f"/v1/state/{key}",
            headers=headers,
            json={"expected_version": None, "value": {"n": 0}},
        )
        assert create.status_code == 200
        assert create.json()["version"] == 1

        # create again on the SAME key -> 409 already_exists, current version echoed.
        create_again = await client.put(
            f"/v1/state/{key}",
            headers=headers,
            json={"expected_version": None, "value": {"n": 99}},
        )
        assert create_again.status_code == 409
        assert create_again.json()["error"]["code"] == "already_exists"
        assert create_again.json()["current_version"] == 1

        # version-match update succeeds and increments by exactly 1.
        update = await client.put(
            f"/v1/state/{key}",
            headers=headers,
            json={"expected_version": 1, "value": {"n": 1}},
        )
        assert update.status_code == 200
        assert update.json()["version"] == 2

        # stale version -> 409 version_conflict, current version echoed.
        stale = await client.put(
            f"/v1/state/{key}",
            headers=headers,
            json={"expected_version": 1, "value": {"n": 2}},
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "version_conflict"
        assert stale.json()["current_version"] == 2

        # GET reflects the last successful write.
        got = await client.get(f"/v1/state/{key}", headers=headers)
        assert got.status_code == 200
        assert got.json()["value"] == {"n": 1}
        assert got.json()["version"] == 2

        # GET on an unknown key -> 404.
        missing = await client.get(f"/v1/state/unknown-{uuid.uuid4().hex}", headers=headers)
        assert missing.status_code == 404

    async with get_privileged_session() as session:
        assert await validate_state_chain(session) is True


async def test_state_is_invisible_from_another_tenant(
    messaging_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_a = await seed_query_token(tenant_a)
    token_b = await seed_query_token(tenant_b)
    key = "cross-tenant-" + uuid.uuid4().hex

    async with await _client(app) as client:
        created = await client.put(
            f"/v1/state/{key}",
            headers={"Authorization": f"Bearer {token_a}"},
            json={"expected_version": None, "value": {"secret": 1}},
        )
        assert created.status_code == 200

        # tenant B cannot see it -- RLS makes it structurally invisible, so tenant B can
        # even "create" the SAME key under its own tenant without conflict.
        other = await client.get(f"/v1/state/{key}", headers={"Authorization": f"Bearer {token_b}"})
        assert other.status_code == 404

        other_create = await client.put(
            f"/v1/state/{key}",
            headers={"Authorization": f"Bearer {token_b}"},
            json={"expected_version": None, "value": {"secret": 2}},
        )
        assert other_create.status_code == 200
        assert other_create.json()["version"] == 1  # a FRESH row for tenant B, not a conflict


async def test_concurrent_writers_race_exactly_one_wins(
    messaging_ready, monkeypatch, seed_query_token
) -> None:
    """The single most important correctness property of the CAS design: TWO CONCURRENT
    real HTTP requests racing on the SAME (tenant_id, state_key) with the SAME
    expected_version must produce exactly ONE success and ONE genuine 409 -- never a
    silent overwrite where both appear to succeed."""
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    token = await seed_query_token(tenant)
    headers = {"Authorization": f"Bearer {token}"}
    key = "race-" + uuid.uuid4().hex

    async with await _client(app) as client:
        seed = await client.put(
            f"/v1/state/{key}",
            headers=headers,
            json={"expected_version": None, "value": {"n": 0}},
        )
        assert seed.status_code == 200
        assert seed.json()["version"] == 1

        async def _racer(n: int) -> httpx.Response:
            return await client.put(
                f"/v1/state/{key}",
                headers=headers,
                json={"expected_version": 1, "value": {"n": n}},
            )

        results = await asyncio.gather(*(_racer(i) for i in range(8)))
        statuses = [r.status_code for r in results]
        assert statuses.count(200) == 1, f"expected exactly one winner, got {statuses}"
        assert statuses.count(409) == 7

        # The final stored version is exactly 2 (one real increment) -- never higher (which
        # would mean more than one writer's CAS matched) and never still 1 (which would mean
        # no writer's CAS matched at all).
        final = await client.get(f"/v1/state/{key}", headers=headers)
        assert final.json()["version"] == 2

    async with get_privileged_session() as session:
        # Exactly one 'updated' row was appended for this key's version-2 transition --
        # the 7 conflicting racers produced NO chain rows (mirrors ADR-0011's choice).
        result = await session.execute(
            text("SELECT count(*) FROM agent_state_audit_log WHERE state_key = :k AND version = 2"),
            {"k": key},
        )
        assert result.scalar_one() == 1
        assert await validate_state_chain(session) is True
