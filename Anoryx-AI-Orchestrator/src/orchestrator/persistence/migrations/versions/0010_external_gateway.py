"""third_party_api_keys + external_gateway_audit_log + external_gateway_rate_limit_counters
(O-013, ADR-0013).

Revision ID: 0010_external_gateway
Revises: 0009_agent_messaging
Create Date: 2026-07-08

Extends the live head (0009_agent_messaging) with the O-013 third-party external-gateway
persistence (ADR-0013). Three tables:

  third_party_api_keys              — OPERATOR-GLOBAL (NO RLS, mirrors
                                      query_service_tokens/0005 exactly: the auth lookup
                                      must resolve the tenant BEFORE any tenant GUC is
                                      set, so this table cannot be RLS-scoped on itself).
                                      Only key_hash (SHA-256) is stored — the plaintext
                                      secret is returned once at issuance and never
                                      persisted. No orchestrator_app grant (least
                                      privilege — every access runs on the privileged
                                      session).
  external_gateway_audit_log        — GLOBAL tamper-evident hash chain (mirrors
                                      agent_messaging_audit_log/0009: privileged writes,
                                      RLS scopes SELECT to the row's own tenant_id).
                                      Records every request attempt for which a key
                                      resolved to a tenant (allowed / scope_denied /
                                      rate_limited / revoked) — the messaging chain's
                                      "every attempt" semantics, not automation's "only
                                      genuine outcomes" semantics (see ADR-0013).
  external_gateway_rate_limit_counters — OPERATOR-GLOBAL fixed-window counter (NO RLS,
                                      pure internal bookkeeping). PRIMARY KEY
                                      (key_id, window_start) makes the per-request
                                      increment a single atomic INSERT ... ON CONFLICT ...
                                      DO UPDATE (see persistence.repositories.
                                      increment_external_gateway_rate_limit).

The orchestrator_app role already exists (created in 0001).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_external_gateway"
down_revision: Union[str, None] = "0009_agent_messaging"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OUTCOMES = "'allowed','scope_denied','rate_limited','revoked'"
_STATUSES = "'active','revoked'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. third_party_api_keys — OPERATOR-GLOBAL (no RLS, mirrors query_service_tokens).
    # ------------------------------------------------------------------ #
    op.create_table(
        "third_party_api_keys",
        sa.Column("key_id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String(64)), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'active'")),
        sa.Column("rate_limit_per_minute", sa.Integer, nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(f"status IN ({_STATUSES})", name="ck_tpak_status"),
        sa.CheckConstraint("rate_limit_per_minute >= 1", name="ck_tpak_rate_limit_positive"),
        sa.UniqueConstraint("key_hash", name="uq_tpak_key_hash"),
    )
    op.create_index("ix_tpak_tenant_id", "third_party_api_keys", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 2. external_gateway_audit_log — GLOBAL hash chain (privileged writes, RLS-scoped
    #    SELECT). Mirrors agent_messaging_audit_log/0009.
    # ------------------------------------------------------------------ #
    op.create_table(
        "external_gateway_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("route", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"outcome IN ({_OUTCOMES})", name="ck_ega_outcome"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ega_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ega_row_hash_len"),
    )
    op.create_index("ix_ega_tenant_id", "external_gateway_audit_log", ["tenant_id"])
    op.create_index("ix_ega_key_id", "external_gateway_audit_log", ["key_id"])

    # ------------------------------------------------------------------ #
    # 3. external_gateway_rate_limit_counters — OPERATOR-GLOBAL fixed-window counter
    #    (no RLS, internal bookkeeping only).
    # ------------------------------------------------------------------ #
    op.create_table(
        "external_gateway_rate_limit_counters",
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("window_start", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("key_id", "window_start", name="pk_egrlc"),
        sa.CheckConstraint("request_count >= 0", name="ck_egrlc_count_nonnegative"),
    )

    # ------------------------------------------------------------------ #
    # 4. Append-only enforcement (BEFORE UPDATE/DELETE) on external_gateway_audit_log.
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_external_gateway_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'external_gateway_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ega_deny_update BEFORE UPDATE ON external_gateway_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_external_gateway_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ega_deny_delete BEFORE DELETE ON external_gateway_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_external_gateway_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 5. RLS on external_gateway_audit_log: SELECT scoped (NULLIF); INSERT permissive
    #    (privileged-only writes); UPDATE/DELETE denied (belt-and-suspenders with the
    #    triggers). Mirrors agent_messaging_audit_log (0009) — third_party_api_keys and
    #    external_gateway_rate_limit_counters carry NO RLS (operator-global infra, mirrors
    #    query_service_tokens).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE external_gateway_audit_log ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE external_gateway_audit_log FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY ega_select ON external_gateway_audit_log "
            f"FOR SELECT USING ({_NULLIF_PREDICATE})"
        )
    )
    conn.execute(
        sa.text(
            "CREATE POLICY ega_insert ON external_gateway_audit_log FOR INSERT WITH CHECK (true)"
        )
    )
    conn.execute(
        sa.text(
            "CREATE POLICY ega_deny_update ON external_gateway_audit_log FOR UPDATE USING (false)"
        )
    )
    conn.execute(
        sa.text(
            "CREATE POLICY ega_deny_delete ON external_gateway_audit_log FOR DELETE USING (false)"
        )
    )

    # ------------------------------------------------------------------ #
    # 6. Minimal DML grants. third_party_api_keys and
    #    external_gateway_rate_limit_counters get NO orchestrator_app grant at all
    #    (least privilege — every access to both runs on the privileged session).
    #    external_gateway_audit_log: SELECT only (inserts run on the privileged session),
    #    mirrors agent_messaging_audit_log.
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("GRANT SELECT ON external_gateway_audit_log TO orchestrator_app"))
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('external_gateway_audit_log', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'GRANT USAGE, SELECT ON SEQUENCE %s TO orchestrator_app', seq_name);
                END IF;
            END
            $$;
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('external_gateway_audit_log', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'REVOKE USAGE, SELECT ON SEQUENCE %s FROM orchestrator_app', seq_name);
                END IF;
            END
            $$;
            """
        )
    )

    conn.execute(sa.text("DROP POLICY IF EXISTS ega_deny_delete ON external_gateway_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ega_deny_update ON external_gateway_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ega_insert ON external_gateway_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ega_select ON external_gateway_audit_log"))

    conn.execute(
        sa.text("DROP TRIGGER IF EXISTS trg_ega_deny_update ON external_gateway_audit_log")
    )
    conn.execute(
        sa.text("DROP TRIGGER IF EXISTS trg_ega_deny_delete ON external_gateway_audit_log")
    )
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_external_gateway_audit_modification()"))

    op.drop_table("external_gateway_rate_limit_counters")
    op.drop_table("external_gateway_audit_log")
    op.drop_table("third_party_api_keys")
