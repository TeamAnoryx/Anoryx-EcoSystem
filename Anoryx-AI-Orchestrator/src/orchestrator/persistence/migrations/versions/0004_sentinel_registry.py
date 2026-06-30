"""Sentinel registry + registry-mutation audit chain (O-005, ADR-0005).

Revision ID: 0004_sentinel_registry
Revises: 0003_merge_o004_d004
Create Date: 2026-06-30

Extends the live head (0003_merge_o004_d004 — the O-004/D-004 converge) with the
multi-Sentinel coordination persistence. Two tables:

  sentinel_registry             — OPERATOR-GLOBAL registry of Sentinel instances (validated
                                  endpoint, non-secret peer-auth ref, declared capabilities,
                                  health status). NO RLS (no tenant dimension) and NO
                                  orchestrator_app grants — privileged-owner-only infra. The
                                  coordinated push reads it (privileged) to resolve targets.
  sentinel_registry_audit_log   — GLOBAL tamper-evident registry-mutation hash chain (mirrors
                                  distribution_audit_log). Append-only (deny-triggers).
                                  Privileged writes only; NO RLS.

The orchestrator_app role already exists (created in 0001). The registry tables are accessed
ONLY via the privileged session (operator infra), so this migration grants the app role
NOTHING — least privilege. A rejected (SSRF-blocked) registration is recorded in the chain, so
disposition allows 'accepted' | 'rejected'.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_sentinel_registry"
down_revision: Union[str, None] = "0003_merge_o004_d004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_HEALTH_STATES = "'unknown','healthy','degraded','unreachable'"
_REGISTRY_ACTIONS = "'register','modify','deregister','enable','disable'"
_REGISTRY_DISPOSITIONS = "'accepted','rejected'"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1a. sentinel_registry — operator-global instance registry (no RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "sentinel_registry",
        sa.Column("sentinel_id", sa.String(128), primary_key=True),
        sa.Column("endpoint", sa.Text, nullable=False),
        sa.Column(
            "peer_auth_ref", sa.String(128), nullable=False, server_default=sa.text("'global'")
        ),
        # Declared supported policy_types (static, Fork C1) — a JSON array of strings.
        sa.Column("capabilities", postgresql.JSONB, nullable=False),
        sa.Column(
            "health_status", sa.String(16), nullable=False, server_default=sa.text("'unknown'")
        ),
        sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("last_checked_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_healthy_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"health_status IN ({_HEALTH_STATES})", name="ck_sr_health_status"),
        sa.CheckConstraint("consecutive_failures >= 0", name="ck_sr_consecutive_failures"),
        sa.CheckConstraint("jsonb_typeof(capabilities) = 'array'", name="ck_sr_capabilities_array"),
    )
    op.create_index("ix_sr_health_status", "sentinel_registry", ["health_status"])
    op.create_index("ix_sr_enabled", "sentinel_registry", ["enabled"])

    # ------------------------------------------------------------------ #
    # 1b. sentinel_registry_audit_log — GLOBAL hash chain (privileged writes).
    # ------------------------------------------------------------------ #
    op.create_table(
        "sentinel_registry_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("sentinel_id", sa.String(128), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        # opt-in-when-present (folded into the hash iff not None).
        sa.Column("endpoint", sa.Text, nullable=True),
        sa.Column("capabilities", sa.Text, nullable=True),
        sa.Column("error_reason", sa.Text, nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"action IN ({_REGISTRY_ACTIONS})", name="ck_sral_action"),
        sa.CheckConstraint(
            f"disposition IN ({_REGISTRY_DISPOSITIONS})", name="ck_sral_disposition"
        ),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_sral_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_sral_row_hash_len"),
    )
    op.create_index("ix_sral_sentinel_id", "sentinel_registry_audit_log", ["sentinel_id"])

    # ------------------------------------------------------------------ #
    # 2. Append-only enforcement on sentinel_registry_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_registry_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'sentinel_registry_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_sral_deny_update BEFORE UPDATE ON sentinel_registry_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_registry_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_sral_deny_delete BEFORE DELETE ON sentinel_registry_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_registry_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 3. No RLS, no orchestrator_app grants. The registry is operator-global infra accessed
    #    ONLY via the privileged (owner) session; the app role has no reason to touch it
    #    (least privilege). The audit log's bigserial sequence is owned by the privileged
    #    role that inserts into it, so no sequence grant is needed either.
    # ------------------------------------------------------------------ #


def downgrade() -> None:
    conn = op.get_bind()

    # Drop triggers + function, then tables (no FKs between them; either order is safe).
    conn.execute(
        sa.text("DROP TRIGGER IF EXISTS trg_sral_deny_update ON sentinel_registry_audit_log")
    )
    conn.execute(
        sa.text("DROP TRIGGER IF EXISTS trg_sral_deny_delete ON sentinel_registry_audit_log")
    )
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_registry_audit_modification()"))

    op.drop_table("sentinel_registry_audit_log")
    op.drop_table("sentinel_registry")
