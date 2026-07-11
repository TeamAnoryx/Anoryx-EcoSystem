"""F-022 H1 remediation — passive-region write-exclusion guard.

Proves the app-tier fail-closed gate (gateway/middleware/region_guard.py):

- On a PASSIVE region, a governed request is refused 503 BEFORE the terminal
  audit runs — so AuditLogRepository.append is NEVER called (the region cannot
  write its local events_audit_log and therefore cannot fork the hash chain).
- Liveness/readiness probes are still served on passive (k8s keeps the pod alive
  and promotable on failover).
- On an ACTIVE region the guard is a pass-through and the normal audit path is
  intact (a pre-auth 401 still writes an audit row) — proving the guard, not some
  other change, is what suppresses the write on passive.
- An unset role defaults to active (single-region deployments serve normally).
- An invalid SENTINEL_REGION_ROLE fails startup (fail-loud), never silently
  serving under an unenforced posture.

Uses the same audit-intercept harness as test_audit_bypass_regression.py: the
full middleware stack runs; only the terminal DB sink is observed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
)


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """Isolate provider config: the CI/sandbox may inject a half-set of AWS vars
    (keys but no region), which trips GatewaySettings' Bedrock half-config
    validator before this feature's code runs. Clear them so these tests exercise
    only the region-role posture."""
    for var in ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    yield


def _governed_headers() -> dict[str, str]:
    # Valid Sentinel ID headers but NO Authorization — a governed request that,
    # on an active region, produces a pre-auth 401 + an audit row.
    return {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Content-Type": "application/json",
    }


def _body() -> dict:
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}


def _make_audit_context():
    """Intercept AuditLogRepository.append so we can assert whether it fired."""
    audit_repo_mock = MagicMock()
    audit_repo_mock.append = AsyncMock(return_value=MagicMock())

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    patches = [
        patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock),
    ]
    return audit_repo_mock, patches


def _create_app():
    _reset_settings()
    from gateway.main import create_app

    return create_app()


@pytest.mark.asyncio
async def test_passive_refuses_governed_request_without_audit_write(settings_env, monkeypatch):
    monkeypatch.setenv("SENTINEL_REGION_ROLE", "passive")
    audit_repo, audit_patches = _make_audit_context()

    with audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post("/v1/chat/completions", headers=_governed_headers(), json=_body())

    assert resp.status_code == 503
    assert resp.json()["error_code"] == "region_passive_standby"
    # THE key H1 assertion: no audit row was written — the passive region cannot
    # append to its local events_audit_log, so the hash chain cannot fork.
    audit_repo.append.assert_not_awaited()


@pytest.mark.asyncio
async def test_passive_still_serves_liveness_probe(settings_env, monkeypatch):
    monkeypatch.setenv("SENTINEL_REGION_ROLE", "passive")
    audit_repo, audit_patches = _make_audit_context()

    with audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.get("/livez")

    # Probes are exempt (never write audit) so they stay served for failover.
    assert resp.status_code != 503
    audit_repo.append.assert_not_awaited()


@pytest.mark.asyncio
async def test_active_serves_and_audits(settings_env, monkeypatch):
    """Control: on active, the guard passes through and the audit path still fires."""
    monkeypatch.setenv("SENTINEL_REGION_ROLE", "active")
    audit_repo, audit_patches = _make_audit_context()

    with audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post("/v1/chat/completions", headers=_governed_headers(), json=_body())

    assert resp.status_code == 401  # pre-auth rejection (no Authorization header)
    # The guard did NOT block, and the normal terminal-audit path wrote its row.
    audit_repo.append.assert_awaited_once()


@pytest.mark.asyncio
async def test_unset_region_role_defaults_active(settings_env, monkeypatch):
    monkeypatch.delenv("SENTINEL_REGION_ROLE", raising=False)
    audit_repo, audit_patches = _make_audit_context()

    with audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post("/v1/chat/completions", headers=_governed_headers(), json=_body())

    # Default active — single-region / unset deployments serve normally.
    assert resp.status_code == 401
    audit_repo.append.assert_awaited_once()


def test_invalid_region_role_fails_startup(settings_env, monkeypatch):
    """Fail-loud: an unrecognised role must crash startup, never serve unenforced."""
    from pydantic import ValidationError

    monkeypatch.setenv("SENTINEL_REGION_ROLE", "standbyy")
    with pytest.raises(ValidationError):
        _create_app()
