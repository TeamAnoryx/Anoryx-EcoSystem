"""F-028 real admin round-trip drill — no mocks on the DB path.

Requires DATABASE_URL / APP_DATABASE_URL (skips at collection if absent,
matching tests/mcp_gateway and tests/onboarding's convention).
"""

from __future__ import annotations

import os
import uuid

import pytest

from data_protection.custom_pii.admin import list_patterns, register_pattern, revoke_pattern
from data_protection.custom_pii.config import _reset_custom_pii_settings_for_testing
from data_protection.custom_pii.exceptions import (
    InvalidPattern,
    InvalidPatternName,
    PatternLimitExceeded,
)
from persistence.database import get_privileged_session
from persistence.repositories.tenant_repository import TenantRepository

if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
    pytest.skip("DATABASE_URL/APP_DATABASE_URL not set", allow_module_level=True)


@pytest.fixture(autouse=True)
def _reset_settings():
    _reset_custom_pii_settings_for_testing()
    yield
    _reset_custom_pii_settings_for_testing()


async def _new_tenant() -> str:
    async with get_privileged_session() as ps, ps.begin():
        row = await TenantRepository(ps).create(name=f"cpii-test-{uuid.uuid4().hex[:12]}")
        return row.tenant_id


@pytest.mark.asyncio
async def test_register_list_revoke_round_trip():
    tenant_id = await _new_tenant()

    row = await register_pattern(tenant_id, "employee_id", r"EMP-\d{6}", score=0.9)
    assert row.tenant_id == tenant_id
    assert row.name == "EMPLOYEE_ID"  # normalized
    assert row.is_active is True

    active = await list_patterns(tenant_id)
    assert [p.pattern_id for p in active] == [row.pattern_id]

    revoked = await revoke_pattern(tenant_id, row.pattern_id)
    assert revoked.is_active is False
    assert revoked.version == 2  # bumped on revoke

    assert await list_patterns(tenant_id) == []
    assert await list_patterns(tenant_id, active_only=False) != []


@pytest.mark.asyncio
async def test_invalid_name_rejected_before_write():
    tenant_id = await _new_tenant()
    with pytest.raises(InvalidPatternName):
        await register_pattern(tenant_id, "1bad", r"EMP-\d{6}")
    assert await list_patterns(tenant_id, active_only=False) == []


@pytest.mark.asyncio
async def test_redos_pattern_rejected_before_write():
    tenant_id = await _new_tenant()
    with pytest.raises(InvalidPattern):
        await register_pattern(tenant_id, "boom", r"(a+)+$")
    assert await list_patterns(tenant_id, active_only=False) == []


@pytest.mark.asyncio
async def test_per_tenant_cap_enforced(monkeypatch):
    monkeypatch.setenv("CUSTOM_PII_MAX_PATTERNS_PER_TENANT", "2")
    _reset_custom_pii_settings_for_testing()
    tenant_id = await _new_tenant()
    await register_pattern(tenant_id, "one", r"A-\d")
    await register_pattern(tenant_id, "two", r"B-\d")
    with pytest.raises(PatternLimitExceeded):
        await register_pattern(tenant_id, "three", r"C-\d")


@pytest.mark.asyncio
async def test_different_tenants_isolated():
    tenant_a = await _new_tenant()
    tenant_b = await _new_tenant()
    await register_pattern(tenant_a, "a_only", r"A-\d{4}")

    assert await list_patterns(tenant_b) == []
    assert len(await list_patterns(tenant_a)) == 1
