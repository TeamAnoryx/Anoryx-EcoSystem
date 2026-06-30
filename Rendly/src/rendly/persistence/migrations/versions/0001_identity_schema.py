"""Rendly identity schema: tenants, users, profiles, credentials, refresh-token families,
RLS, and the rendly_app role (R-004).

Revision ID: 0001
Revises:
Create Date: 2026-06-30

This is the FIRST Rendly DDL. It makes the R-002 frozen identity domain real and gives
R-003's two left-open seams (``UserStore`` + ``RefreshTokenStore``) a Postgres home,
mirroring the Sentinel F-003b / Delta D-003 two-role RLS pattern (Fork A/B/C):

1. Schema (Fork A — OWNED): everything lives in ``rendly``; the alembic_version table is
   pinned there by env.py so Rendly's history never collides with another product's.

2. Tables (Fork C — identity + refresh ONLY; Channel + Membership are DEFERRED to R-005):
   - tenants   — GLOBAL registry, NO RLS (like Sentinel's tenants table).
   - users     — PK (tenant_id, user_id), FK tenant_id→tenants. RLS.
   - profiles  — PK (tenant_id, user_id) = one profile per user, FK→users. RLS.
   - credentials — username PK (global login key), FK (tenant_id,user_id)→users. RLS.
   - refresh_token_families — family_id PK. RLS.
   - refresh_tokens — token_hash PK (sha256 hex), FK family_id→families. RLS.
   ids are VARCHAR(64) (R-002 ids are plain dashed-hex strings, never a native uuid type).

3. RLS (Fork B — mirror F-003b Option α): ENABLE + FORCE on every tenant-scoped table
   with ONE permissive policy ``{tbl}_tenant FOR ALL`` using the strict NULLIF predicate
   in BOTH USING and WITH CHECK:
       tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
   An unset/empty GUC collapses the predicate to zero rows (fail-closed). Which COMMANDS
   rendly_app may issue is gated by the GRANTs below (the policy ∩ the grant), so e.g.
   users/profiles/credentials are read+insert only while the refresh tables also allow
   UPDATE (rotate flips ``used``; revoke flips ``revoked``). tenants has no RLS.

4. rendly_app role: created idempotently with NO password in SQL (the secrets rule). The
   SCRAM password is provisioned out-of-band POST-migrate (RENDLY_PROVISION_APP_ROLE=1) —
   see Rendly/docker-entrypoint.sh, the F-010 fix that makes a fresh ``compose up``
   authenticate. For LOCAL DEV without the entrypoint:
       ALTER ROLE rendly_app WITH PASSWORD 'your_local_dev_password';

DOWN: reverses every object in dependency order (policies, grants, tables child→parent,
role-if-unowned). It deliberately does NOT drop the ``rendly`` schema — that schema houses
the alembic_version table. It never touches tenant data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "rendly"
_APP_ROLE = "rendly_app"

# The strict fail-closed RLS predicate (identical in shape to F-003b Option α / Delta D-003).
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# Tenant-scoped tables that carry RLS (tenants is the global registry and is exempt).
_RLS_TABLES = ("users", "profiles", "credentials", "refresh_token_families", "refresh_tokens")


def _enable_rls(table: str) -> None:
    """ENABLE + FORCE RLS and create the single tenant policy on a rendly table.

    One ``FOR ALL`` policy carries the tenant predicate for every command; the GRANTs
    decide which commands rendly_app may actually issue (effective op = policy ∩ grant).
    """
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")
    op.execute(
        f"CREATE POLICY {table}_tenant ON {_SCHEMA}.{table} "
        f"FOR ALL USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")

    # ------------------------------------------------------------------- tenants (global)
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    # ----------------------------------------------------------------------------- users
    op.create_table(
        "users",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("status_text", sa.String(256), nullable=True),
        sa.Column("presence", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "user_id", name="pk_users"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{_SCHEMA}.tenants.tenant_id"], name="fk_users_tenant"
        ),
        sa.CheckConstraint(
            "presence IN ('online','away','busy','offline')", name="ck_users_presence"
        ),
        schema=_SCHEMA,
    )

    # -------------------------------------------------------------------------- profiles
    op.create_table(
        "profiles",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("org_role", sa.String(16), nullable=False),
        sa.Column("team", sa.String(128), nullable=True),
        # PK (tenant_id, user_id) IS the one-profile-per-user uniqueness constraint.
        sa.PrimaryKeyConstraint("tenant_id", "user_id", name="pk_profiles"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_profiles_user",
        ),
        sa.CheckConstraint("org_role IN ('admin','member','guest')", name="ck_profiles_org_role"),
        schema=_SCHEMA,
    )

    # ----------------------------------------------------------------------- credentials
    op.create_table(
        "credentials",
        sa.Column("username", sa.String(320), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_credentials_user",
        ),
        schema=_SCHEMA,
    )
    # Login resolves a credential by the (RLS-scoped) tenant under get_user, but the
    # password grant looks it up cross-tenant by the global username PK (privileged).

    # ------------------------------------------------------- refresh_token_families
    op.create_table(
        "refresh_token_families",
        sa.Column("family_id", sa.String(32), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        # Referential integrity: a family must belong to a real user. DEFERRABLE INITIALLY
        # DEFERRED so a future user-delete task can remove the user + cascade-tombstone its
        # families within one transaction; RI checks bypass RLS, so the check sees the user
        # row regardless of the tenant GUC. issue() commits in its own txn AFTER the user is
        # already committed, so the deferred check passes at COMMIT.
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_rtf_user",
            deferrable=True,
            initially="DEFERRED",
        ),
        schema=_SCHEMA,
    )

    # --------------------------------------------------------------- refresh_tokens
    op.create_table(
        "refresh_tokens",
        sa.Column("token_hash", sa.String(64), primary_key=True, nullable=False),
        sa.Column("family_id", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("generation", sa.Integer, nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scopes", sa.ARRAY(sa.Text), nullable=False),
        sa.Column("roles", sa.ARRAY(sa.Text), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["family_id"],
            [f"{_SCHEMA}.refresh_token_families.family_id"],
            name="fk_refresh_token_family",
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_refresh_tokens_family", "refresh_tokens", ["family_id"], schema=_SCHEMA)

    # ----------------------------------------- append-only flag hardening (triggers)
    # The refresh state is monotonic: a token's ``used`` only goes False->True (rotate
    # consumes it) and a family's ``revoked`` only goes False->True (revoke / reuse burns
    # it). A BEFORE UPDATE guard RAISEs on any attempt to REVERSE either flag, so a
    # compromised app role with the (legitimate) UPDATE grant cannot "un-use" a rotated
    # token or "un-revoke" a burned family. Mirrors Delta 0001's deny_ledger_modification
    # deny-trigger style; here the deny is conditional (the forward flip is allowed, the
    # reversal is forbidden) and idempotent re-writes (True->True) are no-ops.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_SCHEMA}.deny_refresh_token_unuse()
        RETURNS TRIGGER AS $$
        BEGIN
            IF OLD.used AND NOT NEW.used THEN
                RAISE EXCEPTION
                    'rendly refresh_tokens.used is append-only: cannot revert TRUE->FALSE for %',
                    OLD.token_hash;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute(f"DROP TRIGGER IF EXISTS trg_refresh_tokens_no_unuse ON {_SCHEMA}.refresh_tokens")
    op.execute(f"""
        CREATE TRIGGER trg_refresh_tokens_no_unuse
        BEFORE UPDATE ON {_SCHEMA}.refresh_tokens
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_refresh_token_unuse();
        """)
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_SCHEMA}.deny_family_unrevoke()
        RETURNS TRIGGER AS $$
        BEGIN
            IF OLD.revoked AND NOT NEW.revoked THEN
                RAISE EXCEPTION
                    'rendly refresh_token_families.revoked is append-only: cannot revert '
                    'TRUE->FALSE for %', OLD.family_id;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute(
        f"DROP TRIGGER IF EXISTS trg_families_no_unrevoke ON {_SCHEMA}.refresh_token_families"
    )
    op.execute(f"""
        CREATE TRIGGER trg_families_no_unrevoke
        BEFORE UPDATE ON {_SCHEMA}.refresh_token_families
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_family_unrevoke();
        """)

    # --------------------------------------------------- rendly_app role + grants
    # Idempotent; NO password in SQL (secrets rule). The entrypoint provisions the SCRAM
    # password POST-migrate (RENDLY_PROVISION_APP_ROLE=1).
    op.execute(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN
                CREATE ROLE {_APP_ROLE}
                    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
        """)
    op.execute(f"GRANT USAGE ON SCHEMA {_SCHEMA} TO {_APP_ROLE}")
    # tenants is global (read-only for the app; provisioning is privileged/admin) — needed
    # for the FK target and any in-tenant reads.
    op.execute(f"GRANT SELECT ON {_SCHEMA}.tenants TO {_APP_ROLE}")
    # Identity tables: read + insert (onboarding writes a user/profile/credential; password
    # changes / status updates are a later task). NEVER UPDATE/DELETE here.
    for table in ("users", "profiles", "credentials"):
        op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.{table} TO {_APP_ROLE}")
    # Refresh tables: read + insert + update (rotate flips used; revoke flips revoked).
    # Never DELETE (tokens are tombstoned via revoked/used, never removed).
    for table in ("refresh_token_families", "refresh_tokens"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.{table} TO {_APP_ROLE}")

    # ------------------------------------------------------------------------------- RLS
    for table in _RLS_TABLES:
        _enable_rls(table)


def downgrade() -> None:
    # Reverse dependency order. The `rendly` schema is intentionally retained — it houses
    # the alembic_version table. Never touches tenant data.
    for table in _RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")

    # Drop the append-only flag-hardening triggers (the functions are dropped after the
    # tables, below). DROP TABLE would remove the triggers anyway, but be explicit.
    op.execute(f"DROP TRIGGER IF EXISTS trg_refresh_tokens_no_unuse ON {_SCHEMA}.refresh_tokens")
    op.execute(
        f"DROP TRIGGER IF EXISTS trg_families_no_unrevoke ON {_SCHEMA}.refresh_token_families"
    )

    # Revoke grants before dropping the tables they reference.
    op.execute(f"REVOKE SELECT ON {_SCHEMA}.tenants FROM {_APP_ROLE}")
    for table in _RLS_TABLES:
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA {_SCHEMA} FROM {_APP_ROLE}")

    op.drop_index("ix_refresh_tokens_family", table_name="refresh_tokens", schema=_SCHEMA)
    op.drop_table("refresh_tokens", schema=_SCHEMA)
    op.drop_table("refresh_token_families", schema=_SCHEMA)
    op.drop_table("credentials", schema=_SCHEMA)
    op.drop_table("profiles", schema=_SCHEMA)
    op.drop_table("users", schema=_SCHEMA)
    op.drop_table("tenants", schema=_SCHEMA)

    # Drop the trigger functions now that the tables (and their triggers) are gone.
    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.deny_refresh_token_unuse()")
    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.deny_family_unrevoke()")

    # Drop rendly_app only if it owns no objects (never destructive).
    op.execute(f"""
        DO $$
        DECLARE owned_count INT;
        BEGIN
            SELECT COUNT(*) INTO owned_count
            FROM pg_class c JOIN pg_roles r ON c.relowner = r.oid
            WHERE r.rolname = '{_APP_ROLE}';
            IF owned_count = 0 THEN
                DROP ROLE IF EXISTS {_APP_ROLE};
            ELSE
                RAISE NOTICE '{_APP_ROLE} owns % object(s); role not dropped.', owned_count;
            END IF;
        END
        $$;
        """)
