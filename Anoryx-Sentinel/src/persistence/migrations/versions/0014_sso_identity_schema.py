"""SSO identity schema: RBAC tables + IdP config + group-role mapping (F-014 STEP 2).

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-21

Creates five tenant-scoped, RLS-isolated tables for the F-014 SSO / RBAC
identity layer (ADR-0017 D1, D3, D6, D10):

  admin_users          — per-tenant operator identities keyed by (tenant_id, idp_subject).
  admin_roles          — seeded role set (tenant_admin, tenant_auditor) per tenant.
  admin_role_assignments — (tenant, user) → role mapping.
  idp_config           — per-tenant IdP configuration; OIDC + SAML; secrets stored
                         only as AES-256-GCM ciphertext (bytea columns).
  idp_group_role_map   — per-tenant IdP group → role mapping (fail-closed D6).

ALL five tables use the standard sentinel_app + NOBYPASSRLS + NULLIF RLS pattern
from migration 0006 (ADR-0005 Option α). A tenant can only see its own rows.

NOTE: admin_roles rows are NOT seeded here — there are no tenants at migrate time.
The AdminRoleAssignmentRepository.provision_tenant_roles() helper seeds the two
rows lazily when a tenant's first SSO principal is provisioned (ADR-0017 D1).

idp_config stores OIDC client_secret and SAML SP private keys ONLY as ciphertext
(bytea, null when absent). The IdP signing certificate is public material and is
stored plaintext. The encryption helper is in src/admin/sso/secret_box.py (STEP 3).

downgrade() drops all five tables in FK-safe reverse order. Round-trip is loss-free
for all pre-F-014 data (no existing table is modified).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The strict RLS predicate — copied verbatim from migration 0006 (ADR-0005).
# TEXT comparison, NO ::uuid cast — the GUC is set as a string (VARCHAR(64)).
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# Tables created by this migration, in creation order (FK dependencies respected).
_SSO_TABLES = [
    "idp_config",
    "admin_users",
    "admin_roles",
    "admin_role_assignments",
    "idp_group_role_map",
]


def _apply_rls(conn: sa.engine.Connection, table: str) -> None:
    """Enable RLS + FORCE, drop-if-exists, then create the tenant_isolation policy."""
    conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (
                {_NULLIF_PREDICATE}
            )
            WITH CHECK (
                {_NULLIF_PREDICATE}
            )
            """
        )
    )


def _grant_to_sentinel_app(conn: sa.engine.Connection) -> None:
    """Grant minimal DML to sentinel_app on the five new SSO tables.

    SELECT + INSERT + UPDATE are needed for upsert/provision operations.
    DELETE is intentionally excluded — deactivation uses UPDATE is_active=false.
    """
    for table in _SSO_TABLES:
        conn.execute(sa.text(f"GRANT SELECT ON {table} TO sentinel_app"))
        conn.execute(sa.text(f"GRANT INSERT ON {table} TO sentinel_app"))
        conn.execute(sa.text(f"GRANT UPDATE ON {table} TO sentinel_app"))


def _revoke_from_sentinel_app(conn: sa.engine.Connection) -> None:
    """Revoke all grants in reverse order (downgrade path)."""
    for table in reversed(_SSO_TABLES):
        conn.execute(sa.text(f"REVOKE UPDATE ON {table} FROM sentinel_app"))  # noqa: S608
        conn.execute(sa.text(f"REVOKE INSERT ON {table} FROM sentinel_app"))  # noqa: S608
        conn.execute(sa.text(f"REVOKE SELECT ON {table} FROM sentinel_app"))  # noqa: S608


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 1. idp_config — per-tenant IdP configuration.
    #    One active config per (tenant_id, protocol) enforced by partial unique index.
    #    Encrypted-at-rest columns: client_secret_enc (OIDC) and sp_private_key_enc (SAML).
    #    The IdP x509 cert is public material — stored plaintext.
    # ------------------------------------------------------------------
    op.create_table(
        "idp_config",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "protocol",
            sa.Text(),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # OIDC fields
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("client_id", sa.Text(), nullable=True),
        sa.Column("client_secret_enc", sa.LargeBinary(), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=True),
        # SAML fields
        sa.Column("idp_entity_id", sa.Text(), nullable=True),
        sa.Column("idp_sso_url", sa.Text(), nullable=True),
        sa.Column("idp_x509_cert", sa.Text(), nullable=True),
        sa.Column("sp_acs_url", sa.Text(), nullable=True),
        sa.Column("audience", sa.Text(), nullable=True),
        sa.Column("sp_private_key_enc", sa.LargeBinary(), nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # CHECK: only known protocols accepted
        sa.CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_idp_config_protocol"),
    )
    # Partial unique index: one active config per (tenant, protocol).
    # Fork 5 (ADR-0017 §1.2): one IdP per tenant per protocol in v1.
    conn.execute(
        sa.text(
            """
            CREATE UNIQUE INDEX uq_idp_config_active_protocol
            ON idp_config (tenant_id, protocol)
            WHERE is_active = true
            """
        )
    )

    # ------------------------------------------------------------------
    # 2. admin_users — per-tenant operator identities.
    #    idp_subject = OIDC sub / SAML NameID — never a password.
    # ------------------------------------------------------------------
    op.create_table(
        "admin_users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("idp_subject", sa.Text(), nullable=False),
        sa.Column(
            "idp_config_id",
            sa.String(64),
            sa.ForeignKey("idp_config.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "idp_subject", name="uq_admin_users_tenant_subject"),
    )

    # ------------------------------------------------------------------
    # 3. admin_roles — small seeded role set per tenant (not user-editable in v1).
    #    Rows are provisioned lazily per-tenant by the repository, NOT here.
    # ------------------------------------------------------------------
    op.create_table(
        "admin_roles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("role_name", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "role_name IN ('tenant_admin', 'tenant_auditor')",
            name="ck_admin_roles_role_name",
        ),
        sa.UniqueConstraint("tenant_id", "role_name", name="uq_admin_roles_tenant_role"),
    )

    # ------------------------------------------------------------------
    # 4. admin_role_assignments — (tenant, user) → role.
    #    A user with no assignment has no access (fail-closed, R4/ADR-0017 D1).
    # ------------------------------------------------------------------
    op.create_table(
        "admin_role_assignments",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "admin_user_id",
            sa.String(64),
            sa.ForeignKey("admin_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
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
    )

    # ------------------------------------------------------------------
    # 5. idp_group_role_map — per-tenant IdP group → role mapping (D6).
    #    Fail-closed: an IdP group with no mapping grants NO access.
    #    One mapping per (tenant_id, idp_group) — enforced by unique constraint.
    # ------------------------------------------------------------------
    op.create_table(
        "idp_group_role_map",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("idp_group", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "role IN ('tenant_admin', 'tenant_auditor')",
            name="ck_idp_group_role_map_role",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idp_group",
            name="uq_idp_group_role_map_tenant_group",
        ),
    )

    # ------------------------------------------------------------------
    # 6. RLS on all five tables + grants to sentinel_app.
    # ------------------------------------------------------------------
    for table in _SSO_TABLES:
        _apply_rls(conn, table)

    _grant_to_sentinel_app(conn)


def downgrade() -> None:
    conn = op.get_bind()

    # Revoke grants before dropping tables.
    _revoke_from_sentinel_app(conn)

    # Drop tables in FK-safe reverse order.
    op.drop_table("idp_group_role_map")
    op.drop_table("admin_role_assignments")
    op.drop_table("admin_roles")
    op.drop_table("admin_users")
    op.drop_table("idp_config")
