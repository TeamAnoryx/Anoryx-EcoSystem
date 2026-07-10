"""R-027: the B2B platform RBAC permission-resolution seam (platform_rbac.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rendly.enums import OrgRole
from rendly.platform_rbac import (
    PlatformPermission,
    has_platform_permission,
    resolve_platform_permissions,
)
from rendly.profile import Profile
from rendly.tenant import Tenant

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT_ID = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT_ID = "99999999-9999-4999-8999-999999999999"
_USER = "11111111-1111-4111-8111-111111111111"

_ALL_PERMISSIONS = frozenset(
    {
        PlatformPermission.MANAGE_TENANT_MEMBERS,
        PlatformPermission.MANAGE_TENANT_CHANNELS,
        PlatformPermission.VIEW_TENANT_AUDIT_LOG,
    }
)


def _tenant(tenant_id: str = _TENANT_ID) -> Tenant:
    return Tenant(tenant_id=tenant_id, created_at=_NOW)


def _profile(org_role: OrgRole, tenant_id: str = _TENANT_ID) -> Profile:
    return Profile(user_id=_USER, tenant_id=tenant_id, org_role=org_role)


# --- resolve_platform_permissions: the fixed ORG-ROLE -> PLATFORM-PERMISSION matrix ------------


def test_admin_holds_every_platform_permission():
    permissions = resolve_platform_permissions(_tenant(), _profile(OrgRole.ADMIN))
    assert permissions == _ALL_PERMISSIONS


def test_member_holds_no_platform_permission():
    permissions = resolve_platform_permissions(_tenant(), _profile(OrgRole.MEMBER))
    assert permissions == frozenset()


def test_guest_holds_no_platform_permission():
    permissions = resolve_platform_permissions(_tenant(), _profile(OrgRole.GUEST))
    assert permissions == frozenset()


@pytest.mark.parametrize("org_role", list(OrgRole))
def test_every_org_role_is_covered_by_the_matrix(org_role):
    # The matrix is total over the closed OrgRole enum -- no role falls through
    # to an implicit default.
    permissions = resolve_platform_permissions(_tenant(), _profile(org_role))
    assert isinstance(permissions, frozenset)


# --- has_platform_permission: the fail-closed per-permission check -----------------------------


@pytest.mark.parametrize("permission", list(PlatformPermission))
def test_admin_has_every_individual_permission(permission):
    assert has_platform_permission(_tenant(), _profile(OrgRole.ADMIN), permission) is True


@pytest.mark.parametrize("permission", list(PlatformPermission))
def test_member_has_no_individual_permission(permission):
    assert has_platform_permission(_tenant(), _profile(OrgRole.MEMBER), permission) is False


@pytest.mark.parametrize("permission", list(PlatformPermission))
def test_guest_has_no_individual_permission(permission):
    assert has_platform_permission(_tenant(), _profile(OrgRole.GUEST), permission) is False


# --- cross-tenant guard: fail LOUD, not a silent empty/False ------------------------------------


def test_resolve_rejects_a_cross_tenant_profile():
    with pytest.raises(ValueError, match="cross-tenant"):
        resolve_platform_permissions(
            _tenant(_TENANT_ID), _profile(OrgRole.ADMIN, tenant_id=_OTHER_TENANT_ID)
        )


def test_has_permission_rejects_a_cross_tenant_profile():
    with pytest.raises(ValueError, match="cross-tenant"):
        has_platform_permission(
            _tenant(_TENANT_ID),
            _profile(OrgRole.ADMIN, tenant_id=_OTHER_TENANT_ID),
            PlatformPermission.VIEW_TENANT_AUDIT_LOG,
        )


def test_same_tenant_does_not_raise():
    # Sanity: the guard only rejects a MISMATCH, not every call.
    resolve_platform_permissions(
        _tenant(_TENANT_ID), _profile(OrgRole.MEMBER, tenant_id=_TENANT_ID)
    )
