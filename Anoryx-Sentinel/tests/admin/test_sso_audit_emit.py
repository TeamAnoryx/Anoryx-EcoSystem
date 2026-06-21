"""Unit tests for admin.sso.audit.emit_sso_event (F-014 STEP 3, ADR-0017 D9).

Covers:
  - actor_id is included in the appended row ONLY when not None;
  - agent_id carries the passed subsystem slug (operator-sso / admin-console);
  - a non-SSO event_type raises ValueError before any append;
  - idp_config_changed appends a row with action_taken="logged".

Uses the privileged `session` fixture (append() requires the privileged role).
Skips when no DB is configured. No secret material is asserted into any log.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.sso.audit import (
    ADMIN_CONSOLE_PRINCIPAL,
    OPERATOR_SSO_PRINCIPAL,
    emit_sso_event,
)
from persistence.models.events_audit_log import EventsAuditLog
from policy.constants import WILDCARD_UUID

pytestmark = pytest.mark.asyncio


def _uid() -> str:
    return str(uuid.uuid4())


async def test_idp_config_changed_appends_logged_row(session: AsyncSession) -> None:
    """idp_config_changed appends a row attributed to admin-console, action 'logged'."""
    tenant_id = _uid()
    rid = "req-" + uuid.uuid4().hex[:16]
    await emit_sso_event(
        session,
        event_type="idp_config_changed",
        target_tenant_id=tenant_id,
        request_id=rid,
        agent_id=ADMIN_CONSOLE_PRINCIPAL,
        actor_id=None,
    )
    await session.flush()

    row = (
        await session.execute(select(EventsAuditLog).where(EventsAuditLog.request_id == rid))
    ).scalar_one()
    assert row.event_type == "idp_config_changed"
    assert row.agent_id == "admin-console"
    assert row.tenant_id == tenant_id  # TARGET tenant, never nil-UUID
    assert row.action_taken == "logged"
    assert row.actor_id is None  # break-glass carries no operator identity
    assert row.team_id == WILDCARD_UUID and row.project_id == WILDCARD_UUID


async def test_actor_id_persisted_when_present(session: AsyncSession) -> None:
    """When actor_id is supplied (operator-attributed), it is stored on the row."""
    tenant_id = _uid()
    actor = _uid()
    rid = "req-" + uuid.uuid4().hex[:16]
    await emit_sso_event(
        session,
        event_type="operator_sso_login",
        target_tenant_id=tenant_id,
        request_id=rid,
        agent_id=OPERATOR_SSO_PRINCIPAL,
        actor_id=actor,
    )
    await session.flush()

    row = (
        await session.execute(select(EventsAuditLog).where(EventsAuditLog.request_id == rid))
    ).scalar_one()
    assert row.agent_id == "operator-sso"
    assert row.actor_id == actor  # honest per-operator attribution
    assert row.action_taken == "logged"


async def test_denied_uses_blocked_action(session: AsyncSession) -> None:
    """operator_sso_denied is appended with action_taken='blocked' and actor_id None."""
    rid = "req-" + uuid.uuid4().hex[:16]
    await emit_sso_event(
        session,
        event_type="operator_sso_denied",
        target_tenant_id=WILDCARD_UUID,  # pre-binding denial -> SYSTEM_TENANT_ID
        request_id=rid,
        agent_id=OPERATOR_SSO_PRINCIPAL,
        actor_id=None,
        action_taken="blocked",
    )
    await session.flush()

    row = (
        await session.execute(select(EventsAuditLog).where(EventsAuditLog.request_id == rid))
    ).scalar_one()
    assert row.event_type == "operator_sso_denied"
    assert row.action_taken == "blocked"
    assert row.actor_id is None


async def test_non_sso_event_type_raises() -> None:
    """A non-SSO event_type raises ValueError before any DB write (no session needed)."""
    with pytest.raises(ValueError):
        await emit_sso_event(
            None,  # never reached — the guard runs first
            event_type="admin_key_minted",
            target_tenant_id=_uid(),
            request_id="req-x",
            agent_id=ADMIN_CONSOLE_PRINCIPAL,
        )
