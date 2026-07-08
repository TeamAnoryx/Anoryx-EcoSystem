"""Non-stubbed governed-relay e2e (O-009, ADR-0009) — THE gate.

Stands up a REAL loopback Sentinel shim (genuine socket, real httpx, the shim's chat-route
stand-in — see `_sentinel_shim._make_chat_route`'s docstring for why it stands in rather than
driving Sentinel's real gateway) and proves, on a fresh Postgres:

  * A dispatch through the REAL `/v1/relay/dispatch` HTTP router — real auth resolution, real
    body validation, real registry lookup, real SSRF re-validation, a real outbound httpx call
    over a genuine socket — reaches a registered + healthy Sentinel and relays its REAL
    response (status + body) back UNCHANGED (Fork H, transparent relay).
  * The dispatch is durably, correctly hash-chain audited as `forwarded` with the real status
    code — proving the audit path is not stubbed either.
  * A dispatch to an UNREGISTERED sentinel_id is BLOCKED before any outbound call (no socket
    touched) and audited `blocked` with reason `unknown_target`.
  * A WRONG tenant Sentinel-key is forwarded to Sentinel UNCHANGED — Sentinel's own real 401 is
    relayed transparently, and the audit disposition is still `forwarded` (Sentinel answered),
    never miscast as a relay failure.
  * The relay-dispatch chain validates in full.

Gated by relay_ready, which FAILS (not skips) under ORCH_REQUIRE_RELAY_E2E=1 so this gate
provably EXECUTES on CI.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from orchestrator.coordination.health import run_health_cycle
from orchestrator.coordination.registry import register_sentinel
from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_relay_chain
from orchestrator.relay.client import RelayTargetUnavailable, relay_request

pytestmark = pytest.mark.integration

_SENTINEL_AUTH_HEADER = "X-Sentinel-Authorization"
# Matches conftest._RELAY_SOURCE_TOKEN / conftest.coordination_settings' relay.source_tokens.
_RELAY_SOURCE_TOKEN = "o009-relay-delta-token"  # noqa: S105 - test-only fake
_RELAY_TARGET_PATH = "/v1/chat/completions"
# Matches _sentinel_shim.create_shim_app's chat_token default.
_SENTINEL_CHAT_TOKEN = "shim-tenant-sentinel-key"  # noqa: S105 - test-only fake


async def _latest_relay_audit_row(sentinel_id: str) -> dict:
    """Fetch the most recent relay_audit_log row for *sentinel_id* (privileged raw query)."""
    async with get_privileged_session() as session:
        from sqlalchemy import select

        from orchestrator.persistence.models.relay_audit_log import RelayAuditLog

        result = await session.execute(
            select(RelayAuditLog)
            .where(RelayAuditLog.sentinel_id == sentinel_id)
            .order_by(RelayAuditLog.sequence_number.desc())
            .limit(1)
        )
        row = result.scalar_one()
        return {c.name: getattr(row, c.name) for c in RelayAuditLog.__table__.columns}


async def test_relay_dispatch_forwards_over_real_socket_and_audits(
    relay_ready,
    clean_registry,
    spawn_sentinel_shim,
    coordination_settings,
    monkeypatch,
) -> None:
    shim = spawn_sentinel_shim()
    sentinel_id = "sentinel-relay-a"
    tenant_id = str(uuid.uuid4())

    await register_sentinel(
        sentinel_id=sentinel_id,
        endpoint=shim.base_url,
        capabilities=["model_allowlist"],
        settings=coordination_settings,
    )
    results = await run_health_cycle(settings=coordination_settings)
    assert {r["sentinel_id"]: r["status"] for r in results}[sentinel_id] == "healthy"

    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv("ORCH_RELAY_SOURCE_TOKENS", f'{{"delta": "{_RELAY_SOURCE_TOKEN}"}}')
    # The app's OWN CoordinationSettings (built inside create_app()) must allow the loopback
    # shim endpoint through its SSRF gate too — it is a SEPARATE settings object from the
    # `coordination_settings` fixture used above for the direct register/health calls.
    monkeypatch.setenv("ORCH_REGISTRY_ENDPOINT_ALLOWLIST", "127.0.0.1")
    monkeypatch.setenv("ORCH_REGISTRY_ALLOW_HTTP", "1")
    monkeypatch.setenv("ORCH_HEALTH_UNREACHABLE_THRESHOLD", "1")
    from orchestrator.app import create_app

    app = create_app()
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.post(
            "/v1/relay/dispatch",
            headers={
                "Authorization": f"Bearer {_RELAY_SOURCE_TOKEN}",
                _SENTINEL_AUTH_HEADER: _SENTINEL_CHAT_TOKEN,
            },
            json={
                "tenant_id": tenant_id,
                "sentinel_id": sentinel_id,
                "target_path": _RELAY_TARGET_PATH,
                "payload": {
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            },
        )

    # --- REAL forward proof: Sentinel's REAL response relayed back unchanged --------------- #
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "shim response"
    assert body["model"] == "gpt-4o-mini"

    # --- REAL audit proof: durably recorded as forwarded, with the real status code -------- #
    row = await _latest_relay_audit_row(sentinel_id)
    assert row["disposition"] == "forwarded"
    assert row["status_code"] == 200
    assert row["tenant_id"] == tenant_id
    assert row["source_product"] == "delta"
    assert row["target_path"] == _RELAY_TARGET_PATH
    assert row["content_hash"] is not None

    async with get_privileged_session() as session:
        assert await validate_relay_chain(session) is True


async def test_relay_blocks_unregistered_target_without_any_outbound_call(
    relay_ready, clean_registry, coordination_settings
) -> None:
    tenant_id = str(uuid.uuid4())
    with pytest.raises(RelayTargetUnavailable) as exc_info:
        await relay_request(
            sentinel_id="sentinel-never-registered",
            target_path="/v1/chat/completions",
            tenant_id=tenant_id,
            source_product="delta",
            body_bytes=b'{"model":"gpt-4o-mini"}',
            sentinel_authorization="whatever",
            settings=coordination_settings,
        )
    assert exc_info.value.reason == "unknown_target"

    row = await _latest_relay_audit_row("sentinel-never-registered")
    assert row["disposition"] == "blocked"
    assert row["error_reason"] == "unknown_target"
    assert row["status_code"] is None  # nothing was ever sent


async def test_relay_forwards_sentinels_own_rejection_transparently(
    relay_ready, clean_registry, spawn_sentinel_shim, coordination_settings
) -> None:
    shim = spawn_sentinel_shim()
    sentinel_id = "sentinel-relay-wrongkey"
    tenant_id = str(uuid.uuid4())

    await register_sentinel(
        sentinel_id=sentinel_id,
        endpoint=shim.base_url,
        capabilities=["model_allowlist"],
        settings=coordination_settings,
    )
    await run_health_cycle(settings=coordination_settings)

    status_code, resp_body, _content_type = await relay_request(
        sentinel_id=sentinel_id,
        target_path="/v1/chat/completions",
        tenant_id=tenant_id,
        source_product="rendly",
        body_bytes=b'{"model":"gpt-4o-mini"}',
        sentinel_authorization="not-the-real-tenant-key",
        settings=coordination_settings,
    )

    # Sentinel's REAL 401 is relayed transparently — the relay never substitutes its own
    # interpretation of Sentinel's auth decision.
    assert status_code == 401
    assert b"unauthorized" in resp_body

    # A dispatch Sentinel actually answered is `forwarded`, even though Sentinel itself
    # rejected it — never miscast as `blocked`/`failed` (Fork H).
    row = await _latest_relay_audit_row(sentinel_id)
    assert row["disposition"] == "forwarded"
    assert row["status_code"] == 401
    assert row["source_product"] == "rendly"
