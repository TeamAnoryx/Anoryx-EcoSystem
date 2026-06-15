"""Repository tests against live Postgres (F-003).

Tests: TenantRepository, TeamRepository, ProjectRepository, PolicyRepository.
VirtualApiKeyRepository has its own dedicated test file (test_virtual_api_key.py).
AuditLogRepository has its own dedicated test file (test_audit_chain.py).

NOTE: get_by_id on all repositories is a PK-only lookup in F-003.
Tenant-scoped isolation on get_by_id is deferred to F-003b.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.tenant_repository import TenantNotFoundError, TenantRepository
from persistence.repositories.team_repository import TeamNotFoundError, TeamRepository
from persistence.repositories.project_repository import ProjectNotFoundError, ProjectRepository
from persistence.repositories.policy_repository import (
    PolicyMonotonicityError,
    PolicyNotFoundError,
    PolicyRepository,
)


def _uid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# TenantRepository
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_create_and_get(session: AsyncSession) -> None:
    """Create a tenant and retrieve it by ID."""
    repo = TenantRepository(session)
    tenant = await repo.create(name="Acme Corp", display_name="Acme Corporation")
    assert len(tenant.tenant_id) > 0
    assert tenant.name == "Acme Corp"
    assert tenant.is_active is True

    fetched = await repo.get_by_id(tenant.tenant_id)
    assert fetched.tenant_id == tenant.tenant_id
    assert fetched.name == "Acme Corp"


@pytest.mark.asyncio
async def test_tenant_not_found_raises(session: AsyncSession) -> None:
    """get_by_id with a nonexistent ID raises TenantNotFoundError."""
    repo = TenantRepository(session)
    with pytest.raises(TenantNotFoundError):
        await repo.get_by_id(_uid())


@pytest.mark.asyncio
async def test_tenant_list_active(session: AsyncSession) -> None:
    """list_active returns created active tenants."""
    repo = TenantRepository(session)
    t = await repo.create(name="ListTest Tenant")
    tenants = await repo.list_active()
    ids = [x.tenant_id for x in tenants]
    assert t.tenant_id in ids


@pytest.mark.asyncio
async def test_tenant_deactivate(session: AsyncSession) -> None:
    """Deactivating a tenant sets is_active=False."""
    repo = TenantRepository(session)
    t = await repo.create(name="Deactivate Me")
    deactivated = await repo.deactivate(t.tenant_id)
    assert deactivated.is_active is False


# ---------------------------------------------------------------------------
# TeamRepository
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_team_create_and_get(session: AsyncSession) -> None:
    """Create a team under a tenant and retrieve it by PK."""
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)

    tenant = await t_repo.create(name="Team Test Tenant")
    team = await team_repo.create(tenant_id=tenant.tenant_id, name="Engineering")

    assert team.team_id
    assert team.tenant_id == tenant.tenant_id
    assert team.name == "Engineering"

    fetched = await team_repo.get_by_id(team.team_id)
    assert fetched.team_id == team.team_id


@pytest.mark.asyncio
async def test_team_not_found_raises(session: AsyncSession) -> None:
    repo = TeamRepository(session)
    with pytest.raises(TeamNotFoundError):
        await repo.get_by_id(_uid())


@pytest.mark.asyncio
async def test_team_list_for_tenant(session: AsyncSession) -> None:
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)
    tenant = await t_repo.create(name="List Teams Tenant")
    team = await team_repo.create(tenant_id=tenant.tenant_id, name="Alpha Team")
    teams = await team_repo.list_for_tenant(tenant.tenant_id)
    ids = [x.team_id for x in teams]
    assert team.team_id in ids


@pytest.mark.asyncio
async def test_team_list_for_tenant_limit_cap(session: AsyncSession) -> None:
    """list_for_tenant clamps limit to 1000 and rejects <= 0."""
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)
    tenant = await t_repo.create(name="Limit Cap Tenant")

    # A large limit is silently clamped to 1000.
    rows = await team_repo.list_for_tenant(tenant.tenant_id, limit=9999)
    assert isinstance(rows, list)

    # limit=0 raises ValueError.
    with pytest.raises(ValueError, match="limit must be > 0"):
        await team_repo.list_for_tenant(tenant.tenant_id, limit=0)

    # limit=-1 raises ValueError.
    with pytest.raises(ValueError, match="limit must be > 0"):
        await team_repo.list_for_tenant(tenant.tenant_id, limit=-1)


# ---------------------------------------------------------------------------
# ProjectRepository
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_project_create_and_get(session: AsyncSession) -> None:
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)
    proj_repo = ProjectRepository(session)

    tenant = await t_repo.create(name="Proj Tenant")
    team = await team_repo.create(tenant_id=tenant.tenant_id, name="Proj Team")
    project = await proj_repo.create(
        tenant_id=tenant.tenant_id,
        team_id=team.team_id,
        name="My Project",
    )
    assert project.project_id
    fetched = await proj_repo.get_by_id(project.project_id)
    assert fetched.project_id == project.project_id


@pytest.mark.asyncio
async def test_project_not_found_raises(session: AsyncSession) -> None:
    repo = ProjectRepository(session)
    with pytest.raises(ProjectNotFoundError):
        await repo.get_by_id(_uid())


# ---------------------------------------------------------------------------
# PolicyRepository
# ---------------------------------------------------------------------------


def _make_jws() -> str:
    """Return a syntactically valid compact-JWS placeholder."""
    import base64

    seg = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    return f"{seg}.{seg}.{seg}"


@pytest.mark.asyncio
async def test_policy_upsert_and_get(session: AsyncSession) -> None:
    """Create a policy and retrieve it by PK."""
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name="Policy Tenant")
    p_repo = PolicyRepository(session)

    policy_id = _uid()
    sig = _make_jws()

    policy, version = await p_repo.upsert_policy(
        policy_id=policy_id,
        policy_type="budget_limit",
        policy_version=1,
        tenant_id=tenant.tenant_id,
        team_id=_uid(),
        project_id=_uid(),
        agent_id="gateway-core",
        effective_from=datetime.now(timezone.utc),
        signature=sig,
        policy_payload={"period": "daily", "scope": "tenant", "max_tokens_per_period": 1000},
    )
    assert policy.policy_id == policy_id
    assert policy.current_version == 1
    assert version.policy_version == 1

    fetched = await p_repo.get_by_id(policy_id)
    assert fetched.policy_id == policy_id


@pytest.mark.asyncio
async def test_policy_version_monotonicity_enforced(session: AsyncSession) -> None:
    """Inserting policy_version <= current raises PolicyMonotonicityError."""
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name="Mono Tenant")
    p_repo = PolicyRepository(session)

    policy_id = _uid()
    sig = _make_jws()
    kwargs = dict(
        policy_id=policy_id,
        policy_type="model_allowlist",
        tenant_id=tenant.tenant_id,
        team_id=_uid(),
        project_id=_uid(),
        agent_id="gateway-core",
        effective_from=datetime.now(timezone.utc),
        signature=sig,
        policy_payload={"allowed_model_ids": ["gpt-4"]},
    )

    # Insert version 2.
    await p_repo.upsert_policy(policy_version=2, **kwargs)  # type: ignore[arg-type]

    # Attempt version 1 (< 2) — must be rejected.
    with pytest.raises(PolicyMonotonicityError):
        await p_repo.upsert_policy(policy_version=1, **kwargs)  # type: ignore[arg-type]

    # Attempt version 2 (== 2) — must be rejected.
    with pytest.raises(PolicyMonotonicityError):
        await p_repo.upsert_policy(policy_version=2, **kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_policy_version_history(session: AsyncSession) -> None:
    """get_versions returns all version records in ascending order."""
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name="History Tenant")
    p_repo = PolicyRepository(session)

    policy_id = _uid()
    sig = _make_jws()
    base_kwargs: dict = dict(
        policy_id=policy_id,
        policy_type="model_denylist",
        tenant_id=tenant.tenant_id,
        team_id=_uid(),
        project_id=_uid(),
        agent_id="gateway-core",
        effective_from=datetime.now(timezone.utc),
        signature=sig,
        policy_payload={"denied_model_ids": ["bad-model"], "reason": "audit test"},
    )

    await p_repo.upsert_policy(policy_version=1, **base_kwargs)  # type: ignore[arg-type]
    await p_repo.upsert_policy(policy_version=2, **base_kwargs)  # type: ignore[arg-type]
    await p_repo.upsert_policy(policy_version=3, **base_kwargs)  # type: ignore[arg-type]

    versions = await p_repo.get_versions(policy_id)
    assert [v.policy_version for v in versions] == [1, 2, 3]


@pytest.mark.asyncio
async def test_policy_not_found_raises(session: AsyncSession) -> None:
    p_repo = PolicyRepository(session)
    with pytest.raises(PolicyNotFoundError):
        await p_repo.get_by_id(_uid())


@pytest.mark.asyncio
async def test_policy_invalid_type_raises(session: AsyncSession) -> None:
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name="Bad Type Tenant")
    p_repo = PolicyRepository(session)
    with pytest.raises(ValueError, match="Invalid policy_type"):
        await p_repo.upsert_policy(
            policy_id=_uid(),
            policy_type="super_secret_policy",
            policy_version=1,
            tenant_id=tenant.tenant_id,
            team_id=_uid(),
            project_id=_uid(),
            agent_id="gateway-core",
            effective_from=datetime.now(timezone.utc),
            signature=_make_jws(),
            policy_payload={},
        )


@pytest.mark.asyncio
async def test_policy_list_for_tenant_limit_cap(session: AsyncSession) -> None:
    """list_for_tenant clamps limit to 1000 and rejects <= 0."""
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name="Policy Limit Tenant")
    p_repo = PolicyRepository(session)

    rows = await p_repo.list_for_tenant(tenant.tenant_id, limit=5000)
    assert isinstance(rows, list)

    with pytest.raises(ValueError, match="limit must be > 0"):
        await p_repo.list_for_tenant(tenant.tenant_id, limit=0)
