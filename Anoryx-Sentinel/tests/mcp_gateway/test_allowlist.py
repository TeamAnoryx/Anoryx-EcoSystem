"""F-026 (ADR-0032) real allow-list drill — no mocks on the DB path.

Requires DATABASE_URL / APP_DATABASE_URL (skips at collection if absent,
matching tests/dr and tests/onboarding's convention).
"""

from __future__ import annotations

import os
import uuid

import pytest

from mcp_gateway.allowlist import is_server_allowed, list_servers, register_server, revoke_server
from mcp_gateway.exceptions import InvalidServerName, ServerUrlRejected
from persistence.database import get_privileged_session
from persistence.repositories.tenant_repository import TenantRepository

if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
    pytest.skip("DATABASE_URL/APP_DATABASE_URL not set", allow_module_level=True)


async def _new_tenant() -> str:
    async with get_privileged_session() as ps, ps.begin():
        row = await TenantRepository(ps).create(name=f"mcp-test-{uuid.uuid4().hex[:12]}")
        return row.tenant_id


@pytest.mark.asyncio
async def test_register_list_revoke_round_trip():
    tenant_id = await _new_tenant()

    server = await register_server(tenant_id, "docs-search", "https://example.com/rpc")
    assert server.tenant_id == tenant_id
    assert server.is_active is True

    active = await list_servers(tenant_id)
    assert [s.server_id for s in active] == [server.server_id]

    assert await is_server_allowed(tenant_id, "https://example.com/rpc") is True
    assert await is_server_allowed(tenant_id, "https://example.org/rpc") is False

    revoked = await revoke_server(tenant_id, server.server_id)
    assert revoked.is_active is False

    assert await list_servers(tenant_id) == []
    assert await list_servers(tenant_id, active_only=False) != []
    assert await is_server_allowed(tenant_id, "https://example.com/rpc") is False


@pytest.mark.asyncio
async def test_private_ip_url_rejected_before_persistence():
    tenant_id = await _new_tenant()
    with pytest.raises(ServerUrlRejected):
        await register_server(tenant_id, "evil-internal", "https://169.254.169.254/rpc")
    assert await list_servers(tenant_id, active_only=False) == []


@pytest.mark.asyncio
async def test_http_scheme_rejected():
    tenant_id = await _new_tenant()
    with pytest.raises(ServerUrlRejected):
        await register_server(tenant_id, "plaintext", "http://example.com/rpc")


@pytest.mark.asyncio
async def test_invalid_name_rejected_before_url_validation():
    tenant_id = await _new_tenant()
    with pytest.raises(InvalidServerName):
        await register_server(tenant_id, "has a space", "https://example.com/rpc")


@pytest.mark.asyncio
async def test_scoped_to_team_and_project():
    tenant_id = await _new_tenant()
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    server = await register_server(
        tenant_id,
        "scoped-server",
        "https://example.com/rpc",
        team_id=team_id,
        project_id=project_id,
    )
    assert server.team_id == team_id
    assert server.project_id == project_id


@pytest.mark.asyncio
async def test_different_tenants_cannot_see_each_others_servers():
    tenant_a = await _new_tenant()
    tenant_b = await _new_tenant()
    await register_server(tenant_a, "a-server", "https://example.com/server-a")

    assert await list_servers(tenant_b) == []
    assert await is_server_allowed(tenant_b, "https://example.com/server-a") is False
