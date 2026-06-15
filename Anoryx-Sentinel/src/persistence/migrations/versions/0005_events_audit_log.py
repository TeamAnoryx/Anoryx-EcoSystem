"""Tamper-evident append-only events_audit_log with hash chain.

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-15

Hash-chain design:
  row_hash = SHA-256(canonical JSON of all content fields including
              event_timestamp + prev_hash, sorted keys, no whitespace, UTF-8).
  First row: prev_hash = GENESIS_HASH (SHA-256 of "anoryx-sentinel:events:genesis:v1").

APPEND-ONLY enforcement (dual-layer):
  1. BEFORE UPDATE trigger: raises immediately on any UPDATE.
  2. BEFORE DELETE trigger: raises immediately on any DELETE.
  3. RLS USING (false) WITH CHECK (false) for UPDATE/DELETE (no row is visible
     or modifiable via normal connections for those operations).

Tamper-evidence: altering a row changes its row_hash, breaking the chain for
that row and all subsequent rows. validate_chain() detects this in O(n).
An attacker with full Postgres superuser can rebuild the entire chain — this is
tamper-EVIDENT (rapid detection), not tamper-PROOF. Future: external WORM
attestation (see ADR-0004 for the full honest limits discussion).

Single-table design (nullable variant columns) chosen over per-type tables.
See ADR-0004 for the trade-off rationale.

Column names match contracts/events.schema.json field names exactly:
  severity          — PiiBlockedEvent.severity (NOT pii_severity)
  status            — ComplianceCheckedEvent.status (NOT compliance_status)

action_taken CHECK constraint covers the union of all valid values:
  pii_blocked:        masked | tokenized | blocked
  injection_detected: blocked | logged
  secret_leaked:      masked | tokenized | blocked
  policy_violated:    blocked | throttled | warned
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "events_audit_log",
        # Monotonic bigserial PK — defines chain order.
        sa.Column(
            "sequence_number",
            sa.BigInteger,
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        # ----------------------------------------------------------------
        # Common fields (required on every event)
        # ----------------------------------------------------------------
        sa.Column("event_id", sa.String(64), nullable=False, unique=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("event_timestamp", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        # ----------------------------------------------------------------
        # Variant-specific columns (nullable)
        # Column names match contracts/events.schema.json field names exactly.
        # ----------------------------------------------------------------
        # usage
        sa.Column("model", sa.String(256), nullable=True),
        sa.Column("tokens_in", sa.BigInteger, nullable=True),
        sa.Column("tokens_out", sa.BigInteger, nullable=True),
        sa.Column("latency_ms", sa.BigInteger, nullable=True),
        sa.Column("cost_estimate_cents", sa.Numeric(precision=20, scale=6), nullable=True),
        # pii_blocked — column name is `severity` (matches PiiBlockedEvent.severity)
        sa.Column("pattern_name", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("action_taken", sa.String(64), nullable=True),
        # injection_detected
        sa.Column("classifier_score", sa.Numeric(precision=5, scale=4), nullable=True),
        sa.Column("rule_matched", sa.String(128), nullable=True),
        # secret_leaked
        sa.Column("secret_type", sa.String(64), nullable=True),
        sa.Column("direction", sa.String(16), nullable=True),
        # policy_violated
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("violation_type", sa.String(128), nullable=True),
        # compliance_checked — column name is `status` (matches ComplianceCheckedEvent.status)
        sa.Column("framework", sa.String(32), nullable=True),
        sa.Column("control_id", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        # shadow_ai_detected
        sa.Column("detected_endpoint", sa.String(256), nullable=True),
        sa.Column("traffic_volume", sa.BigInteger, nullable=True),
        sa.Column("first_seen_at", sa.String(64), nullable=True),
        # ----------------------------------------------------------------
        # Hash-chain columns
        # ----------------------------------------------------------------
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        # ----------------------------------------------------------------
        # CHECK constraints (enforce contract bounds at DB layer)
        # ----------------------------------------------------------------
        sa.CheckConstraint(
            "event_type IN ("
            "'usage','pii_blocked','injection_detected',"
            "'secret_leaked','policy_violated','compliance_checked',"
            "'shadow_ai_detected')",
            name="ck_eal_event_type",
        ),
        sa.CheckConstraint(
            "tokens_in IS NULL OR (tokens_in >= 0 AND tokens_in <= 10000000)",
            name="ck_eal_tokens_in",
        ),
        sa.CheckConstraint(
            "tokens_out IS NULL OR (tokens_out >= 0 AND tokens_out <= 10000000)",
            name="ck_eal_tokens_out",
        ),
        sa.CheckConstraint(
            "latency_ms IS NULL OR (latency_ms >= 0 AND latency_ms <= 3600000)",
            name="ck_eal_latency_ms",
        ),
        sa.CheckConstraint(
            "classifier_score IS NULL OR " "(classifier_score >= 0 AND classifier_score <= 1)",
            name="ck_eal_classifier_score",
        ),
        sa.CheckConstraint(
            "traffic_volume IS NULL OR " "(traffic_volume >= 0 AND traffic_volume <= 1000000000)",
            name="ck_eal_traffic_volume",
        ),
        # severity — PiiBlockedEvent.severity (matches events.schema.json)
        sa.CheckConstraint(
            "severity IS NULL OR " "severity IN ('low','medium','high','critical')",
            name="ck_eal_severity",
        ),
        sa.CheckConstraint(
            "secret_type IS NULL OR "
            "secret_type IN ('api_key','token','private_key','credential')",
            name="ck_eal_secret_type",
        ),
        sa.CheckConstraint(
            "direction IS NULL OR direction IN ('inbound','outbound')",
            name="ck_eal_direction",
        ),
        sa.CheckConstraint(
            "framework IS NULL OR " "framework IN ('SOC2','GDPR','HIPAA','EU_AI_ACT')",
            name="ck_eal_framework",
        ),
        # status — ComplianceCheckedEvent.status (matches events.schema.json)
        sa.CheckConstraint(
            "status IS NULL OR " "status IN ('passed','failed','not_applicable')",
            name="ck_eal_status",
        ),
        # action_taken: union of valid values across all event variants that use it.
        # pii_blocked: masked|tokenized|blocked
        # injection_detected: blocked|logged
        # secret_leaked: masked|tokenized|blocked
        # policy_violated: blocked|throttled|warned
        sa.CheckConstraint(
            "action_taken IS NULL OR action_taken IN ("
            "'masked','tokenized','blocked','logged','throttled','warned')",
            name="ck_eal_action_taken",
        ),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_eal_row_hash_len"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_eal_prev_hash_len"),
    )

    # Indexes
    op.create_index("ix_eal_tenant_id", "events_audit_log", ["tenant_id"])
    op.create_index("ix_eal_event_type", "events_audit_log", ["event_type"])
    op.create_index("ix_eal_tenant_event_type", "events_audit_log", ["tenant_id", "event_type"])
    op.create_index("ix_eal_sequence_number", "events_audit_log", ["sequence_number"])
    # BRIN index for range scans on large, mostly-append tables.
    op.create_index(
        "ix_eal_seq_brin",
        "events_audit_log",
        ["sequence_number"],
        postgresql_using="brin",
    )

    conn = op.get_bind()

    # ------------------------------------------------------------------
    # Append-only enforcement triggers.
    # BEFORE UPDATE: always raises.
    # BEFORE DELETE: always raises.
    # ------------------------------------------------------------------
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_audit_log_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'events_audit_log is append-only: % is forbidden. '
                    'sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            """
            CREATE TRIGGER trg_eal_deny_update
            BEFORE UPDATE ON events_audit_log
            FOR EACH ROW EXECUTE FUNCTION deny_audit_log_modification();
            """
        )
    )
    conn.execute(
        sa.text(
            """
            CREATE TRIGGER trg_eal_deny_delete
            BEFORE DELETE ON events_audit_log
            FOR EACH ROW EXECUTE FUNCTION deny_audit_log_modification();
            """
        )
    )

    # ------------------------------------------------------------------
    # RLS: ENABLE and FORCE on events_audit_log.
    # USING (false) for UPDATE/DELETE policies means no rows are eligible.
    # INSERT and SELECT are permissive (app sets tenant context).
    # ------------------------------------------------------------------
    conn.execute(sa.text("ALTER TABLE events_audit_log ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE events_audit_log FORCE ROW LEVEL SECURITY"))
    # SELECT policy: allow reads for rows matching tenant context.
    # The OR ... IS NULL branch is intentionally retained for F-003; the strict
    # no-bypass policy is deferred to F-003b (app-role + RLS hardening).
    conn.execute(
        sa.text(
            """
            CREATE POLICY eal_select ON events_audit_log
            FOR SELECT
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) IS NULL
            )
            """
        )
    )
    # INSERT policy: allow inserts (the trigger + application handle validation).
    conn.execute(
        sa.text(
            """
            CREATE POLICY eal_insert ON events_audit_log
            FOR INSERT
            WITH CHECK (true)
            """
        )
    )
    # UPDATE policy: no rows are eligible (USING false = nothing visible to update).
    conn.execute(
        sa.text(
            """
            CREATE POLICY eal_deny_update ON events_audit_log
            FOR UPDATE
            USING (false)
            """
        )
    )
    # DELETE policy: no rows are eligible.
    conn.execute(
        sa.text(
            """
            CREATE POLICY eal_deny_delete ON events_audit_log
            FOR DELETE
            USING (false)
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("DROP POLICY IF EXISTS eal_deny_delete ON events_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS eal_deny_update ON events_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS eal_insert ON events_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS eal_select ON events_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_eal_deny_update ON events_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_eal_deny_delete ON events_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_audit_log_modification()"))

    op.drop_table("events_audit_log")
