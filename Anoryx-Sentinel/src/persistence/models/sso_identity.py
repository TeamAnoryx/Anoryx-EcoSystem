"""SSO identity ORM models (F-014 STEP 2).

Five tenant-scoped tables for the RBAC + IdP-config + group-role-mapping
identity layer (ADR-0017 D1, D3, D6, D10):

  AdminUser              — per-tenant operator identity keyed by (tenant_id, idp_subject).
  AdminRole              — seeded role set per tenant (tenant_admin, tenant_auditor).
  AdminRoleAssignment    — (tenant, user) → role binding.
  IdpConfig              — per-tenant IdP configuration with encrypted-at-rest secrets.
  IdpGroupRoleMap        — per-tenant IdP group → role mapping (fail-closed D6).

All five tables are tenant-scoped and RLS-isolated via the standard
sentinel_app + NOBYPASSRLS + NULLIF predicate from migration 0006 / ADR-0005.

ALL id columns and tenant_id columns use String(64) / VARCHAR(64) — the same
type used across the entire schema (tenants, teams, virtual_api_keys, etc.).
IDs are generated as str(uuid.uuid4()) at the application layer, not by the DB.
There are NO native uuid columns in this module.

SECURITY NOTES:
- IdpConfig.client_secret_enc and IdpConfig.sp_private_key_enc are bytea columns
  that ONLY ever contain AES-256-GCM ciphertext (ADR-0017 D3, R6).
  The decryption helper lives in src/admin/sso/secret_box.py (STEP 3).
  Never return ciphertext or plaintext secrets to any client or log.
- AdminUser.idp_subject is the IdP's stable subject (OIDC sub / SAML NameID),
  never a password. It is opaque infrastructure metadata, not PII in the usual
  sense, but it is treated carefully per honest-language / R6 rules.
- AdminRole rows are provisioned lazily per-tenant by
  AdminRoleAssignmentRepository.provision_tenant_roles() — never seeded in SQL.
"""

from __future__ import annotations

from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class IdpConfig(Base):
    """Per-tenant IdP configuration (OIDC or SAML).

    One active config per (tenant_id, protocol) is enforced by a partial unique
    index in the migration (ADR-0017 Fork 5).

    Secret columns (client_secret_enc, sp_private_key_enc) store AES-256-GCM
    ciphertext only — never plaintext. The IdP x509 cert is public material and
    is stored plaintext.
    """

    __tablename__ = "idp_config"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean(), nullable=False, default=True)

    # OIDC fields
    issuer: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    client_id: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    client_secret_enc: Mapped[bytes | None] = mapped_column(sa.LargeBinary(), nullable=True)
    scopes: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)

    # SAML fields
    idp_entity_id: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    idp_sso_url: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    idp_x509_cert: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    sp_acs_url: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    audience: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    sp_private_key_enc: Mapped[bytes | None] = mapped_column(sa.LargeBinary(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_idp_config_protocol"),
        sa.Index("ix_idp_config_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<IdpConfig id={self.id!r} tenant_id={self.tenant_id!r} "
            f"protocol={self.protocol!r} is_active={self.is_active!r}>"
        )


class AdminUser(Base):
    """Per-tenant operator identity.

    idp_subject is the IdP's stable subject identifier (OIDC sub / SAML NameID).
    The pair (tenant_id, idp_subject) is unique — a subject is scoped to one tenant.

    idp_config_id may be NULL when the user was provisioned outside a specific IdP
    context (e.g., migrated record or break-glass provisioning).
    """

    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    idp_subject: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    idp_config_id: Mapped[str | None] = mapped_column(
        sa.String(64),
        sa.ForeignKey("idp_config.id", ondelete="SET NULL"),
        nullable=True,
    )
    display_name: Mapped[str | None] = mapped_column(sa.Text(), nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean(), nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "idp_subject", name="uq_admin_users_tenant_subject"),
        sa.Index("ix_admin_users_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AdminUser id={self.id!r} tenant_id={self.tenant_id!r} "
            f"is_active={self.is_active!r}>"
        )


class AdminRole(Base):
    """Seeded role set per tenant (tenant_admin, tenant_auditor).

    Rows are provisioned lazily at first SSO login via
    AdminRoleAssignmentRepository.provision_tenant_roles(). They are never
    seeded in the migration (no tenants exist at migrate time).
    """

    __tablename__ = "admin_roles"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    role_name: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            "role_name IN ('tenant_admin', 'tenant_auditor')",
            name="ck_admin_roles_role_name",
        ),
        sa.UniqueConstraint("tenant_id", "role_name", name="uq_admin_roles_tenant_role"),
        sa.Index("ix_admin_roles_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AdminRole id={self.id!r} tenant_id={self.tenant_id!r} "
            f"role_name={self.role_name!r}>"
        )


class AdminRoleAssignment(Base):
    """(tenant, user) → role binding.

    A user with no assignment has no access (fail-closed, ADR-0017 D1 R4).
    The role column uses the same two-value CHECK as admin_roles.role_name.
    """

    __tablename__ = "admin_role_assignments"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    admin_user_id: Mapped[str] = mapped_column(
        sa.String(64),
        sa.ForeignKey("admin_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            "role IN ('tenant_admin', 'tenant_auditor')",
            name="ck_admin_role_assignments_role",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "admin_user_id",
            "role",
            name="uq_admin_role_assignments_user_role",
        ),
        sa.Index("ix_admin_role_assignments_tenant_id", "tenant_id"),
        sa.Index("ix_admin_role_assignments_user_id", "admin_user_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AdminRoleAssignment id={self.id!r} tenant_id={self.tenant_id!r} "
            f"admin_user_id={self.admin_user_id!r} role={self.role!r}>"
        )


class IdpGroupRoleMap(Base):
    """Per-tenant IdP group → role mapping (ADR-0017 D6).

    Fail-closed: an IdP group with no row in this table grants NO access.
    One mapping per (tenant_id, idp_group) — enforced by unique constraint.
    """

    __tablename__ = "idp_group_role_map"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    idp_group: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    role: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            "role IN ('tenant_admin', 'tenant_auditor')",
            name="ck_idp_group_role_map_role",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idp_group",
            name="uq_idp_group_role_map_tenant_group",
        ),
        sa.Index("ix_idp_group_role_map_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<IdpGroupRoleMap id={self.id!r} tenant_id={self.tenant_id!r} "
            f"idp_group={self.idp_group!r} role={self.role!r}>"
        )


class OidcLoginTransaction(Base):
    """Pre-auth, single-use OIDC login transaction store (F-014 STEP 4, ADR-0017 §5).

    GLOBAL table (NOT tenant-RLS-scoped): the OIDC login endpoints are
    unauthenticated, so no tenant session context exists at login-start. The row
    is keyed by an unguessable random `state` and binds `tenant_id` (the idp_config
    OWNER — the R1 tenant binding, never read from the token). Written/read ONLY
    via get_privileged_session(); sentinel_app has no grant on it (migration 0016).

    Single-use replay guard: `consumed_at` is set atomically on the first consume;
    a second consume of the same `state` matches nothing (vector 10). A row past
    `expires_at` is non-consumable (vector 9/10 fail-closed).

    NEVER stores tokens, the authorization code, or claims — only the server-side
    handles (state/nonce/code_verifier) and the tenant binding (R6).
    """

    __tablename__ = "oidc_login_transaction"

    state: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    code_verifier: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idp_config_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (sa.Index("ix_oidc_login_transaction_expires_at", "expires_at"),)

    def __repr__(self) -> str:
        return (
            f"<OidcLoginTransaction state=<redacted> tenant_id={self.tenant_id!r} "
            f"consumed={self.consumed_at is not None!r}>"
        )


class SamlLoginTransaction(Base):
    """Pre-auth, single-use SAML login transaction store (F-014 STEP 5, ADR-0017 §6).

    GLOBAL table (NOT tenant-RLS-scoped): the SAML login + ACS endpoints are
    unauthenticated (the signed assertion IS the auth), so no tenant session
    context exists at login-start. The row is keyed by the SP-generated AuthnRequest
    `request_id` and binds `tenant_id` (the SAML idp_config OWNER — the R1 tenant
    binding, never read from the assertion). Written/read ONLY via
    get_privileged_session(); sentinel_app has no grant on it (migration 0017).

    Single-use replay guard (vector 7): `consumed_at` is set atomically on the first
    consume; a second consume of the same `request_id` matches nothing. A SAMLResponse
    whose `InResponseTo` is unknown/absent (IdP-initiated injection) consumes nothing
    and is rejected. A row past `expires_at` is non-consumable (fail-closed).

    NEVER stores the SAMLResponse, the assertion, or any attribute — only the
    server-side AuthnRequest handle and the tenant binding (R6).
    """

    __tablename__ = "saml_login_transaction"

    request_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idp_config_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (sa.Index("ix_saml_login_transaction_expires_at", "expires_at"),)

    def __repr__(self) -> str:
        return (
            f"<SamlLoginTransaction request_id=<redacted> tenant_id={self.tenant_id!r} "
            f"consumed={self.consumed_at is not None!r}>"
        )
