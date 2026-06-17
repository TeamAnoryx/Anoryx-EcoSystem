"""Tenant routing policy table + routing_decision audit columns (F-006, ADR-0008).

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-17

This migration lands the gateway-core STEP-5 schema changes for F-006:

1. Creates tenant_routing_policy (one row per tenant) using the 0004 template:
   FK tenant_id -> tenants.tenant_id ondelete RESTRICT, CSV allowed_providers
   (CHECK non-empty), CSV fallback_order, optional cost_ceiling_cents.

2. RLS on tenant_routing_policy: ENABLE + FORCE + tenant_isolation policy using
   the strict NULLIF predicate (verbatim from 0006, ADR-0005 fail-closed form),
   USING + WITH CHECK.

3. GRANT SELECT, INSERT, UPDATE ON tenant_routing_policy TO sentinel_app.
   Without this a tenant session cannot read this NEW table (a new table gets NO
   access by default). No DELETE — deactivate via UPDATE (matches 0006).

4. Adds the 5 nullable routing_decision columns to events_audit_log + bounded
   CHECK constraints (ADR-0008 §5.6).

5. DROP + CREATE ck_eal_event_type to add 'routing_decision'.
   DROP + CREATE ck_eal_action_taken to add 'routed','failed_over'.

DOWN: fully reverses all of the above. Never touches data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The strict NULLIF predicate (verbatim from 0006 / ADR-0005).
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# events_audit_log event_type CHECK — old and new IN-lists (drop + recreate).
_OLD_EVENT_TYPE_IN = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected'"
)
_NEW_EVENT_TYPE_IN = _OLD_EVENT_TYPE_IN + ",'routing_decision'"

# events_audit_log action_taken CHECK — old and new IN-lists.
_OLD_ACTION_IN = "'masked','tokenized','blocked','logged','throttled','warned'"
_NEW_ACTION_IN = _OLD_ACTION_IN + ",'routed','failed_over'"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 1. tenant_routing_policy table (0004 template).
    # ------------------------------------------------------------------
    op.create_table(
        "tenant_routing_policy",
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("allowed_providers", sa.String(64), nullable=False),
        sa.Column("fallback_order", sa.String(128), nullable=False),
        sa.Column("cost_ceiling_cents", sa.Numeric(precision=20, scale=6), nullable=True),
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
        sa.CheckConstraint(
            "length(trim(allowed_providers)) > 0",
            name="ck_trp_allowed_providers_nonempty",
        ),
    )
    op.create_index("ix_trp_tenant_id", "tenant_routing_policy", ["tenant_id"])

    # ------------------------------------------------------------------
    # 2. RLS: ENABLE + FORCE + tenant_isolation (NULLIF predicate).
    # ------------------------------------------------------------------
    conn.execute(sa.text("ALTER TABLE tenant_routing_policy ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE tenant_routing_policy FORCE ROW LEVEL SECURITY"))
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON tenant_routing_policy"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY tenant_isolation ON tenant_routing_policy
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
    # 3. GRANT SELECT, INSERT, UPDATE to sentinel_app (no DELETE).
    # ------------------------------------------------------------------
    conn.execute(
        sa.text("GRANT SELECT, INSERT, UPDATE ON tenant_routing_policy TO sentinel_app")
    )

    # ------------------------------------------------------------------
    # 4. events_audit_log routing_decision columns (nullable) + CHECKs.
    # ------------------------------------------------------------------
    op.add_column(
        "events_audit_log", sa.Column("selected_provider", sa.String(16), nullable=True)
    )
    op.add_column("events_audit_log", sa.Column("routing_reason", sa.String(64), nullable=True))
    op.add_column("events_audit_log", sa.Column("outcome", sa.String(32), nullable=True))
    op.add_column("events_audit_log", sa.Column("attempt_index", sa.BigInteger(), nullable=True))
    op.add_column(
        "events_audit_log", sa.Column("requested_model", sa.String(256), nullable=True)
    )
    op.create_check_constraint(
        "ck_eal_selected_provider",
        "events_audit_log",
        "selected_provider IS NULL OR "
        "selected_provider IN ('openai','anthropic','bedrock')",
    )
    op.create_check_constraint(
        "ck_eal_outcome",
        "events_audit_log",
        "outcome IS NULL OR outcome IN ("
        "'selected','allowlist_denied','cost_blocked','fallback_attempted','exhausted')",
    )
    op.create_check_constraint(
        "ck_eal_attempt_index",
        "events_audit_log",
        "attempt_index IS NULL OR (attempt_index >= 0 AND attempt_index <= 16)",
    )

    # ------------------------------------------------------------------
    # 5. Extend the two named CHECKs (drop + recreate).
    # ------------------------------------------------------------------
    op.drop_constraint("ck_eal_event_type", "events_audit_log", type_="check")
    op.create_check_constraint(
        "ck_eal_event_type",
        "events_audit_log",
        f"event_type IN ({_NEW_EVENT_TYPE_IN})",
    )
    op.drop_constraint("ck_eal_action_taken", "events_audit_log", type_="check")
    op.create_check_constraint(
        "ck_eal_action_taken",
        "events_audit_log",
        f"action_taken IS NULL OR action_taken IN ({_NEW_ACTION_IN})",
    )


def downgrade() -> None:
    conn = op.get_bind()

    # 5. Restore the two named CHECKs to their pre-F-006 form.
    op.drop_constraint("ck_eal_action_taken", "events_audit_log", type_="check")
    op.create_check_constraint(
        "ck_eal_action_taken",
        "events_audit_log",
        f"action_taken IS NULL OR action_taken IN ({_OLD_ACTION_IN})",
    )
    op.drop_constraint("ck_eal_event_type", "events_audit_log", type_="check")
    op.create_check_constraint(
        "ck_eal_event_type",
        "events_audit_log",
        f"event_type IN ({_OLD_EVENT_TYPE_IN})",
    )

    # 4. Drop the routing_decision CHECKs + columns.
    op.drop_constraint("ck_eal_attempt_index", "events_audit_log", type_="check")
    op.drop_constraint("ck_eal_outcome", "events_audit_log", type_="check")
    op.drop_constraint("ck_eal_selected_provider", "events_audit_log", type_="check")
    op.drop_column("events_audit_log", "requested_model")
    op.drop_column("events_audit_log", "attempt_index")
    op.drop_column("events_audit_log", "outcome")
    op.drop_column("events_audit_log", "routing_reason")
    op.drop_column("events_audit_log", "selected_provider")

    # 3. Revoke grants.
    conn.execute(
        sa.text("REVOKE SELECT, INSERT, UPDATE ON tenant_routing_policy FROM sentinel_app")
    )

    # 2. Drop RLS policy.
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON tenant_routing_policy"))
    conn.execute(sa.text("ALTER TABLE tenant_routing_policy DISABLE ROW LEVEL SECURITY"))

    # 1. Drop the table.
    op.drop_index("ix_trp_tenant_id", table_name="tenant_routing_policy")
    op.drop_table("tenant_routing_policy")
