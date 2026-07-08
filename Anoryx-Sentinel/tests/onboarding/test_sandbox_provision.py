"""F-025 (ADR-0031) real sandbox-provisioning drill — no mocks on the DB path.

Requires DATABASE_URL / APP_DATABASE_URL (skips at collection if absent,
matching tests/dr's convention) since this exercises the real
TenantRepository / TeamRepository / ProjectRepository / VirtualApiKeyRepository
chain against a live Postgres, not a stub.
"""

from __future__ import annotations

import os
import uuid

import pytest

from onboarding.sandbox import InvalidSandboxName, provision_sandbox
from onboarding.templates import sandbox_templates
from persistence.database import get_privileged_session
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyAuthError,
    VirtualApiKeyRepository,
)

if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
    pytest.skip("DATABASE_URL/APP_DATABASE_URL not set", allow_module_level=True)


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@pytest.mark.asyncio
async def test_provision_sandbox_creates_usable_key():
    name = _unique_name("sandbox-test")
    result = await provision_sandbox(name)

    assert result.tenant_name == name
    assert result.plaintext_key.startswith("sk-sentinel-")

    async with get_privileged_session() as ps:
        row = await VirtualApiKeyRepository(ps).lookup_by_plaintext(result.plaintext_key)
    assert row.tenant_id == result.tenant_id
    assert row.team_id == result.team_id
    assert row.project_id == result.project_id
    assert row.agent_id == result.agent_id
    assert row.is_active is True


@pytest.mark.asyncio
async def test_provision_sandbox_wrong_key_rejected():
    name = _unique_name("sandbox-test")
    result = await provision_sandbox(name)

    async with get_privileged_session() as ps:
        with pytest.raises(VirtualApiKeyAuthError):
            await VirtualApiKeyRepository(ps).lookup_by_plaintext(result.plaintext_key + "x")


@pytest.mark.asyncio
async def test_provision_sandbox_rejects_invalid_name():
    with pytest.raises(InvalidSandboxName):
        await provision_sandbox("has a space")


@pytest.mark.asyncio
async def test_provision_sandbox_same_name_twice_yields_distinct_tenants():
    """tenants.name has no uniqueness constraint (tenant_id is the real
    identity, matching admin/tenants.py's own create_tenant) — provisioning
    twice with the same name must succeed twice, as distinct tenants."""
    name = _unique_name("sandbox-test")
    first = await provision_sandbox(name)
    second = await provision_sandbox(name)
    assert first.tenant_id != second.tenant_id


@pytest.mark.asyncio
async def test_provision_sandbox_custom_team_project_names():
    name = _unique_name("sandbox-test")
    result = await provision_sandbox(name, team_name="growth-team", project_name="pilot-project")
    assert result.team_id
    assert result.project_id


def test_sandbox_templates_reference_the_given_tenant():
    tenant_id = str(uuid.uuid4())
    templates = sandbox_templates(tenant_id)
    assert set(templates) == {"budget-daily-cap", "model-allowlist-starter"}
    for record in templates.values():
        assert record["tenant_id"] == tenant_id
        assert "signature" not in record  # raw templates — signed by sentinel-cli, not here
