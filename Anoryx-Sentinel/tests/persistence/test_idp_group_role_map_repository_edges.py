"""IdpGroupRoleMapRepository edge-branch coverage (F-014 STEP 3/D6, additive).

Companion to test_idp_config_repository.py (which holds the main set/list/resolve
tests). This file closes the remaining branches:

  * the caller_tenant_id guard on set_mapping, list_for_tenant, and resolve_role
    (defense-in-depth — raises before any DB access);
  * resolve_role's precedence loop when ONLY the lower-privilege role
    (tenant_auditor) is mapped — the loop skips tenant_admin (the 141->140 partial)
    and returns tenant_auditor.

Uses the privileged `session` fixture (BYPASSRLS / SAVEPOINT-isolated), mirroring
the existing repo tests. Skips when no DB.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.idp_group_role_map_repository import (
    IdpGroupRoleMapRepository,
)

pytestmark = pytest.mark.asyncio


def _uid() -> str:
    return str(uuid.uuid4())


async def _insert_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) "
            "VALUES (:tid, :name, true) ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"tid": tenant_id, "name": "GRM edge tenant " + tenant_id[:8]},
    )


# --------------------------------------------------------------------------- #
# caller_tenant_id guards (raise before any DB access).
# --------------------------------------------------------------------------- #
async def test_set_mapping_tenant_mismatch_raises(session: AsyncSession) -> None:
    """set_mapping raises ValueError when caller_tenant_id != tenant_id (line 68)."""
    repo = IdpGroupRoleMapRepository(session)
    with pytest.raises(ValueError, match="tenant mismatch"):
        await repo.set_mapping(
            tenant_id=_uid(),
            idp_group="admins",
            role="tenant_admin",
            caller_tenant_id=_uid(),
        )


async def test_list_for_tenant_tenant_mismatch_raises(session: AsyncSession) -> None:
    """list_for_tenant raises ValueError when caller_tenant_id != tenant_id (line 95)."""
    repo = IdpGroupRoleMapRepository(session)
    with pytest.raises(ValueError, match="tenant mismatch"):
        await repo.list_for_tenant(tenant_id=_uid(), caller_tenant_id=_uid())


async def test_resolve_role_tenant_mismatch_raises(session: AsyncSession) -> None:
    """resolve_role raises ValueError when caller_tenant_id != tenant_id (line 126)."""
    repo = IdpGroupRoleMapRepository(session)
    with pytest.raises(ValueError, match="tenant mismatch"):
        await repo.resolve_role(tenant_id=_uid(), groups=["admins"], caller_tenant_id=_uid())


# --------------------------------------------------------------------------- #
# resolve_role precedence loop: only the lower role is mapped.
# --------------------------------------------------------------------------- #
async def test_resolve_role_only_auditor_mapped_returns_auditor(session: AsyncSession) -> None:
    """When only tenant_auditor is mapped, the precedence loop skips tenant_admin
    (141->140) and returns tenant_auditor (line 142)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpGroupRoleMapRepository(session)
    await repo.set_mapping(
        tenant_id=tenant_id,
        idp_group="readonly",
        role="tenant_auditor",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    role = await repo.resolve_role(
        tenant_id=tenant_id, groups=["readonly"], caller_tenant_id=tenant_id
    )
    assert role == "tenant_auditor"
