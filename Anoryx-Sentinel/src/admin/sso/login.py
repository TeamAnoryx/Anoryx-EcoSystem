"""SSO login finalization — group→role resolution + JIT provisioning (F-014 STEP 6).

ADR-0017 §7 (D6 group→role, fail-closed), §10 (D9 events + honest attribution),
§12 vectors 14/16. This is the single place where a fully-VALIDATED assertion
(VerifiedOidcIdentity / VerifiedSamlIdentity — both carry idp_subject, groups,
tenant_id [the idp_config owner, R1], idp_config_id) is turned into a real,
tenant-scoped, role-bearing principal:

  1. resolve_role(tenant_id, groups) under get_tenant_session(tenant) (RLS in force).
     None -> raise SsoAccessDenied AFTER emitting operator_sso_denied exactly once
     (fail-closed, vector 14). No admin_user is provisioned on the denial path.
  2. On a resolved role: just-in-time provision under the SAME tenant session —
     provision_tenant_roles (idempotent seed), upsert_by_subject (idempotent),
     assign (idempotent), set_last_login. Repeat logins for the same subject yield
     ONE admin_users row and ONE role assignment (no dupes).
  3. Emit operator_sso_login on a SEPARATE privileged session (the F-012a
     mutate-then-audit pattern: append() asserts the privileged role).

HONEST ATTRIBUTION (D9, vector 16): the operator_sso_login row carries
  tenant_id = the operator's REAL tenant (the idp_config owner — never WILDCARD/nil),
  agent_id = "operator-sso" (the emitting subsystem slug),
  actor_id = the provisioned admin_users.id (never nil, never the tenant's own id).

The denied path is audited HERE (one place) so a route never double-emits. The
caller (oidc_routes / saml_routes) translates SsoAccessDenied into a 403 and never
mints a session on any rejection path (R4). STEP 7 adds the operator-session/cookie
minting on top of the ProvisionedPrincipal this returns.

R6: this module never logs the idp_subject verbatim, never carries secret material,
and the audit row carries only the opaque admin_users.id (not PII).
"""

from __future__ import annotations

from dataclasses import dataclass

from admin.sso.audit import OPERATOR_SSO_PRINCIPAL, emit_sso_event
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.admin_role_assignment_repository import (
    AdminRoleAssignmentRepository,
)
from persistence.repositories.admin_user_repository import AdminUserRepository
from persistence.repositories.idp_group_role_map_repository import (
    IdpGroupRoleMapRepository,
)


class SsoAccessDenied(Exception):
    """A validated assertion resolved to NO role (fail-closed, vector 14).

    Raised AFTER operator_sso_denied has been emitted exactly once. The caller
    translates this to a 403 and produces no operator session (R4).
    """


@dataclass(frozen=True)
class ProvisionedPrincipal:
    """The result of a successful SSO login finalization.

    tenant_id is the operator's REAL tenant (the idp_config owner, R1).
    admin_user_id is the internal admin_users.id (the actor_id carrier, D9).
    role is the highest mapped role. idp_subject is the IdP's stable subject.
    """

    tenant_id: str
    admin_user_id: str
    role: str
    idp_subject: str


class _Identity:
    """Structural type: VerifiedOidcIdentity / VerifiedSamlIdentity both match.

    Documented here only; both verified identities are frozen dataclasses with
    these four attributes, so finalize_sso_login accepts either by duck typing.
    """

    idp_subject: str
    groups: list[str]
    tenant_id: str
    idp_config_id: str


async def finalize_sso_login(identity, *, request_id: str) -> ProvisionedPrincipal:
    """Resolve role, JIT-provision, and emit operator_sso_login. Fail-closed.

    Args:
        identity: a fully-validated VerifiedOidcIdentity or VerifiedSamlIdentity.
            Its tenant_id is the idp_config OWNER (R1) — never a token value.
        request_id: correlation id for the audit row (events.schema ^[A-Za-z0-9._-]{1,64}$).

    Returns:
        ProvisionedPrincipal on success.

    Raises:
        SsoAccessDenied: groups map to no role. operator_sso_denied is emitted
            exactly once BEFORE the raise (vector 14); no admin_user is provisioned.
    """
    tenant_id = identity.tenant_id

    # 1. Resolve groups -> role under the verified tenant's RLS session.
    async with get_tenant_session(tenant_id) as ts:
        role = await IdpGroupRoleMapRepository(ts).resolve_role(
            tenant_id=tenant_id,
            groups=identity.groups,
            caller_tenant_id=tenant_id,
        )

        # 2. Fail-closed (vector 14): no mapped role -> deny + audit once, NO
        #    provisioning. The denial is emitted HERE so a route never re-emits.
        if role is None:
            await _emit_denied(tenant_id=tenant_id, request_id=request_id)
            raise SsoAccessDenied("no_role")

        # 3. Just-in-time provisioning (all idempotent) under the SAME tenant
        #    session so RLS scopes every write to the operator's own tenant.
        assignments = AdminRoleAssignmentRepository(ts)
        await assignments.provision_tenant_roles(tenant_id=tenant_id)

        admin_user = await AdminUserRepository(ts).upsert_by_subject(
            tenant_id=tenant_id,
            idp_subject=identity.idp_subject,
            caller_tenant_id=tenant_id,
            idp_config_id=identity.idp_config_id,
        )
        admin_user_id = admin_user.id

        await assignments.assign(
            tenant_id=tenant_id,
            admin_user_id=admin_user_id,
            role=role,
            caller_tenant_id=tenant_id,
        )
        await AdminUserRepository(ts).set_last_login(
            user_id=admin_user_id,
            caller_tenant_id=tenant_id,
        )
        await ts.commit()

    # 4. Emit operator_sso_login on a SEPARATE privileged session (append()
    #    asserts the privileged role — the F-012a mutate-then-audit pattern).
    #    HONEST ATTRIBUTION (vector 16): real tenant, operator-sso slug, the
    #    provisioned admin_user.id as actor_id (never nil, never the tenant id).
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_sso_event(
                ps,
                event_type="operator_sso_login",
                target_tenant_id=tenant_id,
                request_id=request_id,
                agent_id=OPERATOR_SSO_PRINCIPAL,
                actor_id=admin_user_id,
                action_taken="logged",
            )

    return ProvisionedPrincipal(
        tenant_id=tenant_id,
        admin_user_id=admin_user_id,
        role=role,
        idp_subject=identity.idp_subject,
    )


async def _emit_denied(*, tenant_id: str, request_id: str) -> None:
    """Append operator_sso_denied (blocked) on a privileged session — exactly once.

    The assertion was valid and the tenant resolved (the idp_config owner), so the
    TARGET tenant is the real tenant — never WILDCARD. actor_id is NULL (no operator
    identity is provisioned on the denial path).
    """
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_sso_event(
                ps,
                event_type="operator_sso_denied",
                target_tenant_id=tenant_id,
                request_id=request_id,
                agent_id=OPERATOR_SSO_PRINCIPAL,
                actor_id=None,
                action_taken="blocked",
            )
