"""D-017 service-layer DB tests: exception mapping + the one-time-reveal /
hash-lookup round-trip (delta.rbac.service).
"""

from __future__ import annotations

import pytest

from delta.persistence.database import get_tenant_session
from delta.rbac.schemas import AccessTokenCreateRequest, AccessTokenRevokeRequest
from delta.rbac.service import (
    TokenNotFoundError,
    create_token,
    list_token_views,
    resolve_role_from_bearer,
    revoke_token,
)

from .conftest import db_required


@db_required
async def test_create_token_reveals_raw_token_once(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        issued = await create_token(
            session, AccessTokenCreateRequest(tenant_id=tenant_id, name="Key", role="tenant_admin")
        )
    assert issued.token
    assert len(issued.token) > 20  # a real random token, not a placeholder


@db_required
async def test_list_token_views_never_exposes_raw_token(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await create_token(
            session, AccessTokenCreateRequest(tenant_id=tenant_id, name="Key", role="tenant_admin")
        )
    async with get_tenant_session(tenant_id) as session:
        views = await list_token_views(session, limit=10)
    assert len(views) == 1
    assert not hasattr(views[0], "token")


@db_required
async def test_resolve_role_from_bearer_finds_issued_token(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        issued = await create_token(
            session,
            AccessTokenCreateRequest(tenant_id=tenant_id, name="Key", role="tenant_auditor"),
        )
    async with get_tenant_session(tenant_id) as session:
        role = await resolve_role_from_bearer(session, bearer_token=issued.token)
    assert role == "tenant_auditor"


@db_required
async def test_resolve_role_from_bearer_unknown_token_returns_none(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        role = await resolve_role_from_bearer(session, bearer_token="not-a-real-token")
    assert role is None


@db_required
async def test_resolve_role_from_bearer_revoked_token_returns_none(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        issued = await create_token(
            session, AccessTokenCreateRequest(tenant_id=tenant_id, name="Key", role="tenant_admin")
        )
    async with get_tenant_session(tenant_id) as session:
        await revoke_token(
            session, token_id=issued.token_id, req=AccessTokenRevokeRequest(tenant_id=tenant_id)
        )
    async with get_tenant_session(tenant_id) as session:
        role = await resolve_role_from_bearer(session, bearer_token=issued.token)
    assert role is None


@db_required
async def test_revoke_missing_token_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TokenNotFoundError):
            await revoke_token(
                session,
                token_id="99999999-9999-4999-8999-999999999999",
                req=AccessTokenRevokeRequest(tenant_id=tenant_id),
            )
