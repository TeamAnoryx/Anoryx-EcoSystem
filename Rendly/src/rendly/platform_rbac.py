"""Platform RBAC — a fixed, tenant-scoped, org-role permission-resolution seam
for Rendly's B2B-platform tier (R-027 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "B2B tenant + RBAC" ships here as a
pure, deterministic RESOLUTION from an existing ``OrgRole`` (``enums.py``,
already carried by every ``Profile`` since R-002) to a small, closed set of
platform-wide (tenant-scoped, not channel-scoped) capabilities — NOT
tenant-definable/custom roles, NOT a persisted role/permission catalog, NOT any
REST/wire/UI surface, and NOT B2B tenant onboarding or self-serve provisioning.

This is a deliberate scope-down of R-027 (first task of Rendly's Phase 4
"Platform-as-a-Service" vision tier, 🏦 POST-INVESTMENT, "Depends on:
R-005/R-007/R-008 + Delta") to a minimal seam, in the same spirit as
R-012/R-016 through R-026's own scoped deliveries (see ADR-0027). It closes a
gap this codebase's own ``realtime/authz.py`` already named: that module's
permission matrix is scoped to a single CHANNEL's ``ChannelRole`` and
explicitly defers "tenant-definable custom roles" as post-investment; it never
built the simpler, still-missing piece underneath — a fixed matrix answering
"what can this ``OrgRole`` do at the TENANT level" at all. This module is that
matrix, not the tenant-definable/custom-role system ``authz.py`` deferred.

NOT BUILT HERE: any tenant-definable/custom role or persisted role/permission
catalog (``OrgRole`` stays the fixed ``{admin, member, guest}`` enum from
``enums.py`` — unchanged, un-extended); any REST/wire surface or UI
(``contracts/openapi.yaml`` is unchanged, no endpoint calls this); any wiring
into ``realtime/authz.py``'s existing per-channel matrix or its token-scope
pre-gate (a future REST/token layer MAY call :func:`has_platform_permission`,
none does today); any B2B tenant onboarding, self-serve signup, or tenant
provisioning workflow; any seat limits, billing, or plan tiers tied to a
tenant (Delta/X-005 territory — unreachable from this subproject regardless);
and any persistence (this is a pure function of caller-supplied ``Tenant`` /
``Profile`` objects, no new table, no new migration).
"""

from __future__ import annotations

from enum import StrEnum

from .enums import OrgRole
from .profile import Profile
from .tenant import Tenant


class PlatformPermission(StrEnum):
    """A closed set of tenant-wide (not channel-scoped) platform capabilities.

    Each member is the tenant-level analog of something this codebase already
    gates per-channel or names as a product goal: ``MANAGE_TENANT_MEMBERS`` and
    ``MANAGE_TENANT_CHANNELS`` are the org-wide counterparts of
    ``realtime.authz.ChannelAction.MANAGE_MEMBERS``/``MAP_TO_TEAM`` (which are
    scoped to ONE channel's roster, not the tenant's); ``VIEW_TENANT_AUDIT_LOG``
    names R-008's "complete administrative audit/oversight of all internal
    comms" goal as a checkable capability. The set is fixed — see the module
    docstring's honesty boundary and ADR-0027 Fork B.
    """

    MANAGE_TENANT_MEMBERS = "manage_tenant_members"
    MANAGE_TENANT_CHANNELS = "manage_tenant_channels"
    VIEW_TENANT_AUDIT_LOG = "view_tenant_audit_log"


# The fixed ORG-ROLE -> PLATFORM-PERMISSION matrix (ADR-0027 Fork C = C1). OrgRole
# has no tier between ADMIN and MEMBER (enums.py: "there is deliberately no
# owner"), so this is a two-tier ALL-or-NOTHING matrix, not a graduated one:
# ADMIN holds every platform permission, MEMBER and GUEST hold none.
_ORG_ROLE_PERMISSIONS: dict[OrgRole, frozenset[PlatformPermission]] = {
    OrgRole.ADMIN: frozenset(
        {
            PlatformPermission.MANAGE_TENANT_MEMBERS,
            PlatformPermission.MANAGE_TENANT_CHANNELS,
            PlatformPermission.VIEW_TENANT_AUDIT_LOG,
        }
    ),
    OrgRole.MEMBER: frozenset(),
    OrgRole.GUEST: frozenset(),
}


def resolve_platform_permissions(tenant: Tenant, profile: Profile) -> frozenset[PlatformPermission]:
    """Resolve the full set of platform permissions ``profile`` holds within ``tenant``.

    Requires ``profile.tenant_id == tenant.tenant_id`` and RAISES ``ValueError``
    otherwise (ADR-0027 Fork D = D1) — mirrors :func:`rendly.membership.bind_membership`
    and :func:`rendly.profile.bind_profile`: a caller passing a profile and a
    tenant that disagree is a caller bug, not a security decision, and must fail
    loud rather than resolve to a silently-empty (and therefore indistinguishable
    from "no permissions") result.

    Pure and total over the closed ``OrgRole`` enum: every member has an entry in
    the matrix above, so this never falls through to an implicit default.
    """
    if profile.tenant_id != tenant.tenant_id:
        raise ValueError(
            "cross-tenant permission resolution rejected: profile.tenant_id != tenant.tenant_id"
        )
    return _ORG_ROLE_PERMISSIONS[profile.org_role]


def has_platform_permission(
    tenant: Tenant, profile: Profile, permission: PlatformPermission
) -> bool:
    """Whether ``profile`` holds ``permission`` within ``tenant``.

    Thin, fail-closed convenience wrapper over :func:`resolve_platform_permissions`
    (propagates its ``ValueError`` on a cross-tenant ``tenant``/``profile`` pair
    rather than swallowing it into a default answer).
    """
    return permission in resolve_platform_permissions(tenant, profile)
