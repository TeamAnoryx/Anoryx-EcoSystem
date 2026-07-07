"""Delta kill-switch: agent allow-list, kill state, publish outbox (D-006).

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-07

The D-006 kill-switch is an instantaneous, per-transaction emergency brake, independent
of and complementary to the D-005 budget engine: it reacts to an unauthorized agent
identity or an anomalously large single transaction cost, without waiting for any period
accumulation. This migration adds the three tables it needs (ADR-0006 §5):

1. ``agent_authorizations`` — a tenant-wide, opt-in agent allow-list. While a tenant has
   zero rows, the unauthorized-agent trigger is inert for it (never a silent new
   restriction on an existing tenant).

2. ``kill_switch_state`` — per (tenant, team, project, agent) edge state (``clear``/
   ``killed``), the SAME granularity as Sentinel's ``BudgetScope.AGENT``. No period bucket
   (unlike D-005's ``budget_enforcement_state``): the kill-switch is not period-based, so a
   scope's row and its ``policy_id`` persist for the scope's lifetime.

3. ``kill_switch_outbox`` — the durable kill/clear DECISION + delivery status, identical
   shape to ``budget_publish_outbox``. Reuses ``delta.policy.sign`` and
   ``delta.budget_engine.publisher`` unchanged (no new signing/publish surface).

Mutable-within-tenant (state transitions, delivery status, allow-list membership):
``delta_app`` is granted ``SELECT, INSERT, UPDATE`` on all three, plus ``DELETE`` on
``agent_authorizations`` only (``revoke_agent``); the two decision tables never delete,
matching D-005. Same strict fail-closed NULLIF RLS predicate as D-003/D-005.

DOWN: reverses every object in dependency order. Retains the ``delta`` schema and never
touches D-001..D-005 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls_no_delete(table: str) -> None:
    """ENABLE + FORCE RLS with tenant SELECT/INSERT/UPDATE policies (no DELETE policy;
    matches D-005's mutable-but-append/update-only tables)."""
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_select ON {_SCHEMA}.{table} "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    op.execute(
        f"CREATE POLICY {table}_tenant_insert ON {_SCHEMA}.{table} "
        f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
    )
    op.execute(
        f"CREATE POLICY {table}_tenant_update ON {_SCHEMA}.{table} "
        f"FOR UPDATE USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")

    # --------------------------------------------------------- agent_authorizations
    op.create_table(
        "agent_authorizations",
        sa.Column("tenant_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("agent_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )
    # Fast "is this tenant gated at all" existence check.
    op.create_index(
        "ix_aa_tenant",
        "agent_authorizations",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    # ---------------------------------------------------------- kill_switch_state
    op.create_table(
        "kill_switch_state",
        sa.Column("kill_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="clear"),
        # Last trigger reason ('unauthorized_agent' | 'anomalous_single_tx'); retained
        # across a clear (audit trail), not reset to NULL by try_transition_to_clear.
        sa.Column("reason", sa.String(32), nullable=True),
        sa.Column("last_published_version", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('clear','killed')", name="ck_kss_state"),
        sa.CheckConstraint(
            "reason IS NULL OR reason IN ('unauthorized_agent','anomalous_single_tx')",
            name="ck_kss_reason",
        ),
        # Same-tenant FK target: lets the outbox bind (kill_id, tenant_id) so a row can
        # never reference another tenant's kill-switch scope (mirrors D-005 fk_bes_budget).
        sa.UniqueConstraint("kill_id", "tenant_id", name="uq_kss_kill_tenant"),
        schema=_SCHEMA,
    )
    # One state row per (tenant, team, project, agent) — the conditional-transition key.
    op.create_index(
        "ux_kss_key",
        "kill_switch_state",
        ["tenant_id", "team_id", "project_id", "agent_id"],
        schema=_SCHEMA,
        unique=True,
    )
    # The un-kill recovery path looks up every killed scope for a (tenant, agent_id).
    op.create_index(
        "ix_kss_tenant_agent",
        "kill_switch_state",
        ["tenant_id", "agent_id", "state"],
        schema=_SCHEMA,
    )

    # -------------------------------------------------------- kill_switch_outbox
    op.create_table(
        "kill_switch_outbox",
        sa.Column("outbox_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("kill_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.BigInteger, nullable=False),
        # 'kill' = clear->killed (publish the zero cap); 'clear' = killed->clear (un-kill).
        sa.Column("transition", sa.String(16), nullable=False),
        sa.Column("policy_payload", postgresql.JSONB, nullable=False),
        sa.Column("distribution_id", sa.String(64), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("transition IN ('kill','clear')", name="ck_kso_transition"),
        sa.CheckConstraint("state IN ('pending','distributed','failed')", name="ck_kso_state"),
        sa.CheckConstraint("policy_version >= 1", name="ck_kso_version_pos"),
        sa.ForeignKeyConstraint(
            ["kill_id", "tenant_id"],
            [
                f"{_SCHEMA}.kill_switch_state.kill_id",
                f"{_SCHEMA}.kill_switch_state.tenant_id",
            ],
            name="fk_kso_kill",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ux_kso_policy_version",
        "kill_switch_outbox",
        ["tenant_id", "policy_id", "policy_version"],
        schema=_SCHEMA,
        unique=True,
    )
    op.create_index(
        "ix_kso_pending",
        "kill_switch_outbox",
        ["state", "next_attempt_at"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_SCHEMA}.agent_authorizations " f"TO {_APP_ROLE}"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.kill_switch_state TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.kill_switch_outbox TO {_APP_ROLE}")

    _enable_rls_no_delete("agent_authorizations")
    op.execute(
        f"CREATE POLICY agent_authorizations_tenant_delete ON {_SCHEMA}.agent_authorizations "
        f"FOR DELETE USING ({_TENANT_PREDICATE})"
    )
    _enable_rls_no_delete("kill_switch_state")
    _enable_rls_no_delete("kill_switch_outbox")


def downgrade() -> None:
    for table in ("kill_switch_outbox", "kill_switch_state", "agent_authorizations"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
    op.execute(
        f"DROP POLICY IF EXISTS agent_authorizations_tenant_delete "
        f"ON {_SCHEMA}.agent_authorizations"
    )

    for table in ("agent_authorizations", "kill_switch_state", "kill_switch_outbox"):
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_kso_pending", table_name="kill_switch_outbox", schema=_SCHEMA)
    op.drop_index("ux_kso_policy_version", table_name="kill_switch_outbox", schema=_SCHEMA)
    op.drop_table("kill_switch_outbox", schema=_SCHEMA)

    op.drop_index("ix_kss_tenant_agent", table_name="kill_switch_state", schema=_SCHEMA)
    op.drop_index("ux_kss_key", table_name="kill_switch_state", schema=_SCHEMA)
    op.drop_table("kill_switch_state", schema=_SCHEMA)

    op.drop_index("ix_aa_tenant", table_name="agent_authorizations", schema=_SCHEMA)
    op.drop_table("agent_authorizations", schema=_SCHEMA)
