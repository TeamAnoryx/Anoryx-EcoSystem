"""R-004 SECURITY SPINE — cross-tenant RLS denial + fail-closed GUC behaviour.

The database (not the application) is the isolation authority: rendly_app is NOBYPASSRLS,
so even a wrong tenant_id, a forged tenant context, an unset GUC, or an empty GUC yields
ZERO rows — never an error, never a leak, never another tenant's data.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from rendly.persistence.database import get_tenant_session
from rendly.persistence.models import RefreshTokenRow, UserRow
from rendly.persistence.refresh_store import DbRefreshTokenStore
from rendly.persistence.user_store import DbUserStore

T_A = "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6"
U_A = "7d9e2f3a-1234-5c6b-8def-0123456789ab"
T_B = "9f8e7d6c-1122-4a3b-8c9d-e0f1a2b3c4d5"
U_B = "3e4f5a6b-7777-4888-9999-aaaabbbbcccc"


def _seed_two(seed_identity) -> None:
    seed_identity(tenant_id=T_A, user_id=U_A, username="alex@a.example", password="pw-a")
    seed_identity(tenant_id=T_B, user_id=U_B, username="kim@b.example", password="pw-b")


def test_tenant_a_cannot_read_tenant_b_user(seed_identity) -> None:
    _seed_two(seed_identity)
    # Under tenant A's context, query for B's user id directly: RLS must return zero rows.
    with get_tenant_session(T_A) as session:
        rows = session.execute(select(UserRow).where(UserRow.user_id == U_B)).scalars().all()
    assert rows == []  # cross-tenant deny: zero rows, not an error, not B's data


def test_store_get_user_is_tenant_scoped(seed_identity) -> None:
    _seed_two(seed_identity)
    store = DbUserStore()
    # Each tenant sees only its own user; the other's id resolves to None under its scope.
    assert store.get_user(U_A, T_A) is not None
    assert store.get_user(U_B, T_B) is not None
    assert store.get_user(U_B, T_A) is None  # B's user, A's scope -> None
    assert store.get_user(U_A, T_B) is None  # A's user, B's scope -> None


def test_forged_tenant_context_yields_zero_rows(seed_identity) -> None:
    _seed_two(seed_identity)
    # Open B's tenant context but ask for A's row (the forged/mismatched case): zero rows.
    with get_tenant_session(T_B) as session:
        rows = session.execute(select(UserRow).where(UserRow.user_id == U_A)).scalars().all()
    assert rows == []


def test_refresh_rows_are_tenant_isolated(seed_identity) -> None:
    _seed_two(seed_identity)
    store = DbRefreshTokenStore()
    store.issue(
        user_id=U_A,
        tenant_id=T_A,
        scopes=frozenset({"profile:read"}),
        roles=("member",),
        ttl_seconds=3600,
    )
    # Tenant B cannot see A's refresh token rows.
    with get_tenant_session(T_B) as session:
        rows = session.execute(select(RefreshTokenRow)).scalars().all()
    assert rows == []


def test_no_guc_session_is_fail_closed(seed_identity, app_session_no_guc) -> None:
    _seed_two(seed_identity)
    # A rendly_app session that never set the GUC: current_setting -> NULL -> NULLIF -> NULL
    # -> predicate false -> zero rows. Fail-closed, never widening.
    session = app_session_no_guc()
    try:
        rows = session.execute(select(UserRow)).scalars().all()
    finally:
        session.close()
    assert rows == []


def test_empty_guc_session_is_fail_closed(seed_identity, app_session_empty_guc) -> None:
    _seed_two(seed_identity)
    # GUC explicitly set to '' : NULLIF('', '') -> NULL -> predicate false -> zero rows.
    session = app_session_empty_guc()
    try:
        rows = session.execute(select(UserRow)).scalars().all()
    finally:
        session.close()
    assert rows == []


def test_get_tenant_session_rejects_blank_tenant() -> None:
    from rendly.persistence.database import TenantContextRequiredError

    import pytest

    for blank in ("", "   ", None):
        with pytest.raises(TenantContextRequiredError):
            with get_tenant_session(blank):  # type: ignore[arg-type]
                pass


def test_random_unseeded_tenant_sees_nothing(seed_identity) -> None:
    _seed_two(seed_identity)
    stranger = str(uuid.uuid4())
    with get_tenant_session(stranger) as session:
        rows = session.execute(select(UserRow)).scalars().all()
    assert rows == []
