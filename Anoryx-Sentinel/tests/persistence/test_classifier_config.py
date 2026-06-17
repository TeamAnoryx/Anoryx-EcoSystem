"""Classifier config persistence (F-007, ADR-0010 §6/§7, migration 0009).

Covers: resolve_classifier_config reads the tenant row + applies the inheritance
resolver; NULL model_id / no row → UNCONFIGURED; and the migration 0009 CHECK
constraints reject out-of-allow-list presets and bad audit_mode values.

Uses the privileged `session` fixture (the repo's WHERE clause is the app-layer
guard; RLS is exercised separately in the isolation suite).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.tenant_routing_policy_repository import (
    TenantRoutingPolicyRepository,
)


def _uid() -> str:
    return str(uuid.uuid4())


async def _create_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant_id, "n": "T " + tenant_id[:8]},
    )


async def _insert_policy(
    session: AsyncSession,
    tenant_id: str,
    *,
    classifier_model_id=None,
    audit_mode: str = "full",
) -> None:
    await session.execute(
        text(
            "INSERT INTO tenant_routing_policy "
            "(tenant_id, team_id, project_id, agent_id, allowed_providers, "
            " fallback_order, classifier_model_id, audit_mode) "
            "VALUES (:t, :team, :proj, 'gateway-core', 'openai', 'openai', :cm, :am)"
        ),
        {
            "t": tenant_id,
            "team": _uid(),
            "proj": _uid(),
            "cm": classifier_model_id,
            "am": audit_mode,
        },
    )


@pytest.mark.asyncio
async def test_no_row_is_unconfigured(session: AsyncSession) -> None:
    repo = TenantRoutingPolicyRepository(session)
    tid = "cls-none-" + _uid()[:8]
    cfg = await repo.resolve_classifier_config(tid, caller_tenant_id=tid)
    assert cfg.model_id is None
    assert cfg.audit_mode == "full"


@pytest.mark.asyncio
async def test_row_with_preset_and_redacted_mode(session: AsyncSession) -> None:
    tid = "cls-set-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(
        session, tid, classifier_model_id="anthropic:claude-haiku-4-5", audit_mode="redacted"
    )
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    cfg = await repo.resolve_classifier_config(tid, caller_tenant_id=tid)
    assert cfg.model_id == "anthropic:claude-haiku-4-5"
    assert cfg.audit_mode == "redacted"


@pytest.mark.asyncio
async def test_null_model_id_is_unconfigured(session: AsyncSession) -> None:
    tid = "cls-null-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(session, tid, classifier_model_id=None, audit_mode="full")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    cfg = await repo.resolve_classifier_config(tid, caller_tenant_id=tid)
    assert cfg.model_id is None
    assert cfg.audit_mode == "full"


@pytest.mark.asyncio
async def test_caller_mismatch_is_unconfigured(session: AsyncSession) -> None:
    # Defense-in-depth: a mismatched caller_tenant_id excludes the row → UNCONFIGURED.
    tid = "cls-guard-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(session, tid, classifier_model_id="openai:gpt-4o-mini")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    cfg = await repo.resolve_classifier_config(tid, caller_tenant_id="other-tenant")
    assert cfg.model_id is None


@pytest.mark.asyncio
async def test_check_rejects_unknown_preset(session: AsyncSession) -> None:
    tid = "cls-badm-" + _uid()[:8]
    await _create_tenant(session, tid)
    with pytest.raises(IntegrityError):
        await _insert_policy(session, tid, classifier_model_id="anthropic:claude-3-opus")
        await session.flush()


@pytest.mark.asyncio
async def test_check_rejects_bad_audit_mode(session: AsyncSession) -> None:
    tid = "cls-bada-" + _uid()[:8]
    await _create_tenant(session, tid)
    with pytest.raises(IntegrityError):
        await _insert_policy(session, tid, classifier_model_id=None, audit_mode="loud")
        await session.flush()
