"""Runtime tenant isolation: sentinel_app role, RLS hardening, scoped grants.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-16

This migration implements F-003b Option α (ADR-0005):

1. Creates the sentinel_app login role (idempotent, NO password in SQL).
   Password is provisioned out-of-band via Vault.
   For LOCAL DEV: connect as the privileged role and run:
       ALTER ROLE sentinel_app WITH PASSWORD 'your_local_dev_password';
   Never put passwords in migration SQL (Sentinel secrets rule).

2. Grants minimal DML to sentinel_app on tenant-serving tables.
   No DDL. No BYPASSRLS. No superuser.

3. Adds RLS (ENABLE + FORCE) to virtual_api_keys, policies, policy_versions
   (the three tables that had no RLS in F-003).

4. Replaces the dead `OR ... IS NULL` branch in the existing 5 RLS tables
   (teams, projects, users, role_assignments, events_audit_log eal_select)
   with the strict NULLIF predicate. See ADR-0005 GUC-defect section.

   The strict predicate:
       tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
   is unsatisfiable when the GUC is unset or empty (NULLIF collapses '' to NULL,
   and tenant_id = NULL is UNKNOWN). This is intentional fail-closed behaviour.
   The application layer raises TenantContextRequiredError before any query; the
   DB predicate is the backstop. Neither layer ever silently grants cross-tenant
   access.

5. Preserves events_audit_log append-only policies exactly:
   eal_insert  (WITH CHECK true)       — privileged-session chain writes
   eal_deny_update (USING false)       — triggers already block; belt-and-suspenders
   eal_deny_delete (USING false)       — idem

DOWN: reverses grants, restores the F-003 IS-NULL-branch policies on the 5 tables,
drops the 3 new-table policies + disables their RLS, drops sentinel_app if it owns
no objects. Never touches data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that existed in F-003 with the defective OR-IS-NULL policy.
# These get their SELECT policy replaced with the strict NULLIF form.
_EXISTING_RLS_TABLES = [
    "teams",
    "projects",
    "users",
    "role_assignments",
]

# Tables gaining RLS for the first time in F-003b.
_NEW_RLS_TABLES = [
    "virtual_api_keys",
    "policies",
    "policy_versions",
]

# The strict NULLIF predicate (ADR-0005 requirement).
_NULLIF_PREDICATE = (
    "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"
)

# The old F-003 predicate (used in downgrade to restore prior behaviour).
_OLD_PREDICATE = (
    "tenant_id = current_setting('app.current_tenant_id', true) "
    "OR current_setting('app.current_tenant_id', true) IS NULL"
)

# Tables where sentinel_app needs INSERT (write path).
_INSERT_TABLES = [
    "teams",
    "projects",
    "users",
    "role_assignments",
    "virtual_api_keys",
    "policies",
    "policy_versions",
]

# Tables where sentinel_app needs UPDATE (write path).
_UPDATE_TABLES = [
    "teams",
    "projects",
    "users",
    "role_assignments",
    "virtual_api_keys",
    "policies",
]

# Tables where sentinel_app needs DELETE (deactivate / revoke paths).
_DELETE_TABLES = [
    # None currently — soft-delete via UPDATE is used for all deactivation.
    # Add here if a hard-delete path is ever introduced for a tenant table.
]


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 1. Create sentinel_app role (idempotent).
    #    NO password in SQL — provisioned out-of-band via Vault/KMS.
    #    For local dev: ALTER ROLE sentinel_app WITH PASSWORD '...';
    # ------------------------------------------------------------------
    conn.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT FROM pg_roles WHERE rolname = 'sentinel_app'
                ) THEN
                    CREATE ROLE sentinel_app
                        LOGIN
                        NOSUPERUSER
                        NOBYPASSRLS
                        NOCREATEDB
                        NOCREATEROLE;
                END IF;
            END
            $$;
            """
        )
    )

    # ------------------------------------------------------------------
    # 2. Grant minimal DML to sentinel_app.
    #    SELECT on all tenant-serving tables + global registry tables.
    #    INSERT/UPDATE where the repository actually writes.
    #    SELECT on events_audit_log (tenant audit viewing — RLS scopes it).
    #    No INSERT/UPDATE/DELETE on events_audit_log to sentinel_app — chain
    #    writes are privileged (privileged session only, per ADR-0005).
    #    No DDL. No BYPASSRLS.
    # ------------------------------------------------------------------

    # SELECT on all tables sentinel_app needs to read.
    _select_tables = [
        "tenants",
        "agents",
        "teams",
        "projects",
        "users",
        "role_assignments",
        "virtual_api_keys",
        "policies",
        "policy_versions",
        "events_audit_log",
    ]
    for table in _select_tables:
        conn.execute(sa.text(f"GRANT SELECT ON {table} TO sentinel_app"))

    for table in _INSERT_TABLES:
        conn.execute(sa.text(f"GRANT INSERT ON {table} TO sentinel_app"))

    for table in _UPDATE_TABLES:
        conn.execute(sa.text(f"GRANT UPDATE ON {table} TO sentinel_app"))

    for table in _DELETE_TABLES:
        conn.execute(sa.text(f"GRANT DELETE ON {table} TO sentinel_app"))

    # Sequence grants: the only BigSerial sequence is events_audit_log
    # (sequence_number). All PK columns in other tables use VARCHAR(64) — no
    # sequences. sentinel_app does not insert into events_audit_log, so no
    # sequence grant needed there. Grant USAGE+SELECT on the sequence so that
    # any future SELECT currval() calls succeed if needed.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE
                seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('events_audit_log', 'sequence_number')
                INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'GRANT USAGE, SELECT ON SEQUENCE %s TO sentinel_app',
                        seq_name
                    );
                END IF;
            END
            $$;
            """
        )
    )

    # ------------------------------------------------------------------
    # 3. RLS on 3 new tables: virtual_api_keys, policies, policy_versions.
    # ------------------------------------------------------------------
    for table in _NEW_RLS_TABLES:
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

    # ------------------------------------------------------------------
    # 4. Harden existing RLS tables: replace dead OR-IS-NULL with NULLIF.
    #    Also ensure FORCE ROW LEVEL SECURITY (0002 set it, but be explicit).
    # ------------------------------------------------------------------
    for table in _EXISTING_RLS_TABLES:
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

    # events_audit_log SELECT policy: drop old eal_select, recreate with NULLIF.
    # The three append-only policies (eal_insert, eal_deny_update, eal_deny_delete)
    # are preserved exactly as created in migration 0005 — not touched here.
    conn.execute(sa.text("DROP POLICY IF EXISTS eal_select ON events_audit_log"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY eal_select ON events_audit_log
            FOR SELECT
            USING (
                {_NULLIF_PREDICATE}
            )
            """
        )
    )
    # FORCE ROW LEVEL SECURITY was already set in 0005; restate for explicitness.
    conn.execute(sa.text("ALTER TABLE events_audit_log FORCE ROW LEVEL SECURITY"))


def downgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 1. Restore events_audit_log SELECT policy to the F-003 OR-IS-NULL form.
    #    Append-only policies are untouched (their semantics are unchanged).
    # ------------------------------------------------------------------
    conn.execute(sa.text("DROP POLICY IF EXISTS eal_select ON events_audit_log"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY eal_select ON events_audit_log
            FOR SELECT
            USING (
                {_OLD_PREDICATE}
            )
            """
        )
    )

    # ------------------------------------------------------------------
    # 2. Restore existing RLS tables to the F-003 OR-IS-NULL policy.
    # ------------------------------------------------------------------
    for table in _EXISTING_RLS_TABLES:
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        conn.execute(
            sa.text(
                f"""
                CREATE POLICY tenant_isolation ON {table}
                USING (
                    {_OLD_PREDICATE}
                )
                WITH CHECK (
                    {_OLD_PREDICATE}
                )
                """
            )
        )

    # ------------------------------------------------------------------
    # 3. Drop RLS from the 3 new tables.
    # ------------------------------------------------------------------
    for table in _NEW_RLS_TABLES:
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        conn.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))

    # ------------------------------------------------------------------
    # 4. Revoke grants from sentinel_app.
    #    Order: DELETE then UPDATE then INSERT then SELECT.
    # ------------------------------------------------------------------
    for table in _DELETE_TABLES:
        conn.execute(
            sa.text(f"REVOKE DELETE ON {table} FROM sentinel_app")
        )
    for table in _UPDATE_TABLES:
        conn.execute(
            sa.text(f"REVOKE UPDATE ON {table} FROM sentinel_app")
        )
    for table in _INSERT_TABLES:
        conn.execute(
            sa.text(f"REVOKE INSERT ON {table} FROM sentinel_app")
        )
    _select_tables = [
        "tenants",
        "agents",
        "teams",
        "projects",
        "users",
        "role_assignments",
        "virtual_api_keys",
        "policies",
        "policy_versions",
        "events_audit_log",
    ]
    for table in _select_tables:
        conn.execute(
            sa.text(f"REVOKE SELECT ON {table} FROM sentinel_app")  # noqa: S608
        )

    # Revoke sequence grant.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE
                seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('events_audit_log', 'sequence_number')
                INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'REVOKE USAGE, SELECT ON SEQUENCE %s FROM sentinel_app',
                        seq_name
                    );
                END IF;
            END
            $$;
            """
        )
    )

    # ------------------------------------------------------------------
    # 5. Drop sentinel_app role only if it owns no objects.
    #    Guard: never destructive to data.
    # ------------------------------------------------------------------
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE
                owned_count INT;
            BEGIN
                SELECT COUNT(*) INTO owned_count
                FROM pg_class c
                JOIN pg_roles r ON c.relowner = r.oid
                WHERE r.rolname = 'sentinel_app';

                IF owned_count = 0 THEN
                    DROP ROLE IF EXISTS sentinel_app;
                ELSE
                    RAISE NOTICE
                        'sentinel_app owns % object(s); role not dropped. '
                        'Reassign objects before re-running downgrade.',
                        owned_count;
                END IF;
            END
            $$;
            """
        )
    )
