"""F-017 vector 12: the inert-feature catcher — ZERO stubs on the lock path.

Proves the FULL chain without stubbing any data-lock component:

    real upsert('data_lock')  →  real load_data_lock_config  →  real DataLockDetector
    →  real run_data_lock through the real gateway  →  field ACTUALLY withheld

The ONLY mocks are orthogonal to F-017 (identical set to the F-016 CRIT-2 e2e):
  - the upstream LLM provider (deterministic assistant JSON content),
  - _enforce_policies_pre_request (F-008/Redis; Redis down in test env),
  - _resolve_policy (F-006 routing; avoids the double-begin on a tenant session).

Everything else — auth, audit, get_tenant_session, PolicyRepository,
load_data_lock_config, DataLockDetector, selector/condition evaluation, the
gateway non-stream withhold wiring — is REAL.

DB-GATED + SENTINEL_PROVISION_APP_ROLE=1 (same pattern as the F-016 e2e).
"""

from __future__ import annotations

import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from data_lock.selector import WITHHELD_PLACEHOLDER

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


def _make_jws() -> str:
    seg = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    return f"{seg}.{seg}.{seg}"


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — skipping F-017 e2e"
)

# Assistant content is a JSON document; the data_lock rule withholds result.ssn.
_FAKE_COMPLETION = {
    "id": "chatcmpl-f017-e2e",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-3.5-turbo",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": json.dumps({"result": {"ssn": "123-45-6789", "name": "Ada Lovelace"}}),
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 15, "total_tokens": 25},
}

# Far-future unlock → the field stays WITHHELD for this request.
_DATA_LOCK_PAYLOAD = {
    "enabled": True,
    "rules": [
        {
            "field_path": "result.ssn",
            "condition": {"type": "time", "unlock_at": "2099-01-01T00:00:00Z"},
        }
    ],
}


@pytest_asyncio.fixture()
async def e2e_seed():
    db_raw = os.environ.get("DATABASE_URL", "")
    app_raw = os.environ.get("APP_DATABASE_URL", "")
    if not db_raw or not app_raw:
        pytest.skip(_SKIP_REASON)
    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        pytest.skip(_SKIP_REASON)
    try:
        probe = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await probe.close()
    except Exception:
        pytest.skip(_SKIP_REASON)

    db_url = _to_asyncpg_url(db_raw)
    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    agent_id = "f017-e2e"
    policy_id = str(uuid.uuid4())
    import secrets as _secrets

    plaintext = "sk-f017-" + _secrets.token_urlsafe(24)

    engine = _privileged_engine(db_url)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"f017-{tenant_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
            ),
            {"tm": team_id, "t": tenant_id, "n": f"team-{team_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
            ),
            {"p": project_id, "tm": team_id, "t": tenant_id, "n": f"proj-{project_id[:8]}"},
        )

    from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository

    async with factory() as sess:
        async with sess.begin():
            await VirtualApiKeyRepository(sess).create(
                plaintext,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                label="f017-e2e",
            )

    # Persist the data_lock policy through the REAL write path (no stubs).
    from persistence.repositories.policy_repository import PolicyRepository

    async with factory() as sess:
        async with sess.begin():
            await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="data_lock",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=_DATA_LOCK_PAYLOAD,
            )
    await engine.dispose()

    async def _cleanup():
        ce = _privileged_engine(db_url)
        try:
            async with ce.begin() as conn:
                await conn.execute(text("TRUNCATE events_audit_log"))
                await conn.execute(
                    text("DELETE FROM policy_versions WHERE policy_id = :pid"), {"pid": policy_id}
                )
                await conn.execute(
                    text("DELETE FROM policies WHERE policy_id = :pid"), {"pid": policy_id}
                )
                await conn.execute(
                    text("DELETE FROM virtual_api_keys WHERE tenant_id = :t"), {"t": tenant_id}
                )
                await conn.execute(
                    text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tenant_id}
                )
                await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tenant_id})
                await conn.execute(
                    text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id}
                )
        finally:
            await ce.dispose()

    yield {
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "plaintext": plaintext,
        "db_url": db_url,
    }
    await _cleanup()


@pytest.mark.asyncio
async def test_real_path_end_to_end_nonstubbed(e2e_seed, monkeypatch):
    """Vector 12: the locked field is ACTUALLY withheld through the real gateway."""
    import httpx
    from httpx import ASGITransport

    tenant_id = e2e_seed["tenant_id"]

    # Assert the REAL load returns armed (the loader is NOT patched).
    from data_lock.config import load_data_lock_config

    cfg = await load_data_lock_config(tenant_id)
    assert (
        cfg.armed is True
    ), "data_lock policy did not load armed — feature would be inert (CRIT-2)"

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    if not os.environ.get("UPSTREAM_BASE_URL"):
        monkeypatch.setenv("UPSTREAM_BASE_URL", "https://upstream.example.invalid")
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")

    from gateway.config import _reset_settings
    from gateway.middleware.rate_limit import reset_state_for_testing

    _reset_settings()
    reset_state_for_testing()
    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    async def fake_proxy_non_stream(
        validated_body, request_id, upstream_api_key=None, overall_timeout=60.0
    ):
        from gateway.models import ChatCompletionResponse

        return ChatCompletionResponse(**_FAKE_COMPLETION), 10, 15

    from policy.enforcement import BudgetOk, ModelAllow

    async def _allow_enforce(tenant_context, body):
        return ModelAllow(None), BudgetOk(), []

    from persistence.repositories.tenant_routing_policy_repository import default_policy

    async def _fake_resolve_policy(tenant_context):
        return default_policy(tenant_context.tenant_id)

    from unittest.mock import patch

    patchers = [
        patch(
            "gateway.router.providers.openai_provider.proxy_non_stream",
            side_effect=fake_proxy_non_stream,
        ),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve_policy),
    ]
    try:
        for p in patchers:
            p.start()
        from gateway.main import create_app

        app = create_app()
        body = json.dumps(
            {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "give me the record"}],
                "stream": False,
            }
        )
        headers = {
            "X-Anoryx-Tenant-Id": tenant_id,
            "X-Anoryx-Team-Id": e2e_seed["team_id"],
            "X-Anoryx-Project-Id": e2e_seed["project_id"],
            "X-Anoryx-Agent-Id": e2e_seed["agent_id"],
            "Authorization": f"Bearer {e2e_seed['plaintext']}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/v1/chat/completions", content=body, headers=headers)
    finally:
        for p in patchers:
            p.stop()
        reset_state_for_testing()
        _reset_settings()

    assert (
        resp.status_code == 200
    ), f"expected 200 (withhold, not block). Got {resp.status_code}: {resp.text[:600]}"
    payload = resp.json()
    content = json.loads(payload["choices"][0]["message"]["content"])
    assert content["result"]["ssn"] == WITHHELD_PLACEHOLDER, (
        "THE INERT-FEATURE CATCHER: result.ssn was NOT withheld through the real "
        f"gateway. Got {content['result']['ssn']!r}. The lock did not enforce."
    )
    assert content["result"]["name"] == "Ada Lovelace"  # unmatched field untouched (vector 8)

    # A real field_locked audit row was written for this tenant (vector 9).
    engine = _privileged_engine(e2e_seed["db_url"])
    try:
        async with engine.connect() as conn:
            row = await conn.execute(
                text(
                    "SELECT count(*) FROM events_audit_log "
                    "WHERE tenant_id = :t AND event_type = 'field_locked'"
                ),
                {"t": tenant_id},
            )
            assert row.scalar_one() >= 1, "no field_locked audit row written for the withhold"
    finally:
        await engine.dispose()
