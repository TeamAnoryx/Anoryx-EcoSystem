"""F-019 vector 12: the inert-feature catcher — ZERO stubs on the enforcement path.

Proves the FULL default-deny chain through the REAL gateway, with NO stub on the
approval/inventory/enforcement path (the F-016 lesson — an enforcement layer that
silently allows is a security hole):

    real model_approval policy  ->  real evaluate_model_policies (default-deny branch)
    ->  real ModelInventoryRepository.get_state  ->  real _policy_deny  ->  403 policy_blocked

Crucially, UNLIKE the F-017 e2e, this does NOT patch _enforce_policies_pre_request —
that IS the path under test. The only mocks are orthogonal to F-019 and apply ONLY to
the post-approval ALLOW case (to avoid a real upstream call + F-006 routing once
enforcement has already passed): the upstream proxy and _resolve_policy. The DENY case
patches nothing on the request path — the block is produced entirely by real code.

DB-GATED + SENTINEL_PROVISION_APP_ROLE=1 (same pattern as the F-017 e2e).
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets as _secrets
import uuid
from datetime import datetime, timezone

import asyncpg
import httpx
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — skipping F-019 e2e"
)


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


_FAKE_COMPLETION = {
    "id": "chatcmpl-f019-e2e",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-3.5-turbo",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "hello from an approved model"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}

_MODEL = "gpt-3.5-turbo"


@pytest_asyncio.fixture()
async def e2e_seed():
    """Seed tenant/team/project + virtual key + an ACTIVE model_approval policy."""
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
    tenant_id, team_id, project_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    agent_id = "f019-e2e"
    policy_id = str(uuid.uuid4())
    plaintext = "sk-f019-" + _secrets.token_urlsafe(24)

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
            {"t": tenant_id, "n": f"f019-{tenant_id[:8]}"},
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
                label="f019-e2e",
            )

    # ACTIVE model_approval policy scoped to this exact request scope (switch ON).
    from persistence.repositories.policy_repository import PolicyRepository

    payload = {
        "policy_type": "model_approval",
        "policy_id": policy_id,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "policy_version": 1,
        "enforcement_mode": "default_deny",
    }
    async with factory() as sess:
        async with sess.begin():
            await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="model_approval",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=payload,
            )
    await engine.dispose()

    async def _cleanup():
        ce = _privileged_engine(db_url)
        try:
            async with ce.begin() as conn:
                await conn.execute(text("TRUNCATE events_audit_log"))
                await conn.execute(
                    text("DELETE FROM model_inventory WHERE tenant_id = :t"), {"t": tenant_id}
                )
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


def _headers(seed: dict) -> dict:
    return {
        "X-Anoryx-Tenant-Id": seed["tenant_id"],
        "X-Anoryx-Team-Id": seed["team_id"],
        "X-Anoryx-Project-Id": seed["project_id"],
        "X-Anoryx-Agent-Id": seed["agent_id"],
        "Authorization": f"Bearer {seed['plaintext']}",
        "Content-Type": "application/json",
    }


def _gateway_env(monkeypatch) -> None:
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


@pytest.mark.asyncio
async def test_unapproved_model_blocked_e2e(e2e_seed, monkeypatch):
    """Vector 12 (deny): a non-approved model is 403 policy_blocked on the REAL path.

    NOTHING on the request path is stubbed — the 403 is produced entirely by real
    code: real evaluate_model_policies default-deny branch -> real inventory get_state
    (model is unknown -> deny) -> real _policy_deny -> GatewayError('policy_blocked').
    """
    _gateway_env(monkeypatch)
    from gateway.main import create_app

    app = create_app()
    body = json.dumps(
        {"model": _MODEL, "messages": [{"role": "user", "content": "hi"}], "stream": False}
    )
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", content=body, headers=_headers(e2e_seed))

    assert resp.status_code == 403, (
        "THE INERT-FEATURE CATCHER: a non-approved model was NOT blocked through the "
        f"real gateway. Got {resp.status_code}: {resp.text[:600]}"
    )
    assert resp.json()["error_code"] == "policy_blocked"

    # The denial is audited via the existing policy_decision_deny (reason carried).
    engine = _privileged_engine(e2e_seed["db_url"])
    try:
        async with engine.connect() as conn:
            n = await conn.execute(
                text(
                    "SELECT count(*) FROM events_audit_log WHERE tenant_id = :t "
                    "AND event_type = 'policy_decision_deny'"
                ),
                {"t": e2e_seed["tenant_id"]},
            )
            assert n.scalar_one() >= 1, "no policy_decision_deny audit row for the denial"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_approved_model_allowed_e2e(e2e_seed, monkeypatch):
    """Vector 12 (allow): once an operator approves the model, the REAL path lets it through.

    The approval + inventory + enforcement are REAL (no stub). Only the post-enforcement
    upstream proxy + F-006 _resolve_policy are mocked — they run AFTER the default-deny
    gate has already passed, so they do not touch the path under test.
    """
    # Operator approves the model through the REAL inventory write path.
    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import ModelInventoryRepository

    t = e2e_seed["tenant_id"]
    now = datetime.now(timezone.utc)
    async with get_tenant_session(t) as sess:
        repo = ModelInventoryRepository(sess)
        await repo.adopt(t, _MODEL, "base")
        await repo.transition(t, _MODEL, "approved", operator_id="op-e2e", now=now)
        await sess.commit()

    _gateway_env(monkeypatch)

    async def _fake_proxy_non_stream(
        validated_body, request_id, upstream_api_key=None, overall_timeout=60.0
    ):
        from gateway.models import ChatCompletionResponse

        return ChatCompletionResponse(**_FAKE_COMPLETION), 10, 5

    from persistence.repositories.tenant_routing_policy_repository import default_policy

    async def _fake_resolve_policy(tenant_context):
        return default_policy(tenant_context.tenant_id)

    from unittest.mock import patch

    patchers = [
        patch(
            "gateway.router.providers.openai_provider.proxy_non_stream",
            side_effect=_fake_proxy_non_stream,
        ),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve_policy),
    ]
    try:
        for p in patchers:
            p.start()
        from gateway.main import create_app

        app = create_app()
        body = json.dumps(
            {"model": _MODEL, "messages": [{"role": "user", "content": "hi"}], "stream": False}
        )
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions", content=body, headers=_headers(e2e_seed)
            )
    finally:
        for p in patchers:
            p.stop()
        from gateway.config import _reset_settings
        from gateway.middleware.rate_limit import reset_state_for_testing

        reset_state_for_testing()
        _reset_settings()

    assert resp.status_code == 200, (
        f"an APPROVED model was not allowed through the real gateway. "
        f"Got {resp.status_code}: {resp.text[:600]}"
    )
    assert resp.json()["choices"][0]["message"]["content"] == "hello from an approved model"


@pytest.mark.asyncio
async def test_retired_model_blocked_e2e(e2e_seed, monkeypatch):
    """F-021 vector 5+12 (the inert-feature catcher for RETIREMENT): a past-grace model
    is 403 policy_blocked on the REAL gateway path — ZERO stubs on the enforcement chain.

    Real approval + real retirement (retire_at in the PAST) -> real
    evaluate_model_policies (approved but past-grace branch) -> ModelDeny('model_retired')
    -> real _policy_deny -> 403 policy_blocked. If retirement enforcement were inert, an
    approved-then-retired model would still be allowed — this proves it is NOT.
    """
    from datetime import timedelta

    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import ModelInventoryRepository

    t = e2e_seed["tenant_id"]
    now = datetime.now(timezone.utc)
    async with get_tenant_session(t) as sess:
        repo = ModelInventoryRepository(sess)
        await repo.adopt(t, _MODEL, "base")
        await repo.transition(t, _MODEL, "approved", operator_id="op-e2e", now=now)
        # Past grace deadline (the repo permits a past retire_at; the API guards it).
        await repo.set_retirement(t, _MODEL, now - timedelta(hours=1), now=now)
        await sess.commit()

    _gateway_env(monkeypatch)
    from gateway.main import create_app

    app = create_app()
    body = json.dumps(
        {"model": _MODEL, "messages": [{"role": "user", "content": "hi"}], "stream": False}
    )
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", content=body, headers=_headers(e2e_seed))

    assert resp.status_code == 403, (
        "THE INERT-FEATURE CATCHER (retirement): an approved-then-RETIRED model past its "
        f"grace deadline was NOT blocked through the real gateway. Got {resp.status_code}: "
        f"{resp.text[:600]}"
    )
    assert resp.json()["error_code"] == "policy_blocked"
