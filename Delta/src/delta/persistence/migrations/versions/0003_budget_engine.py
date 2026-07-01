"""Delta budget engine: budget definitions, enforcement state, publish outbox (D-005).

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-01

The D-005 budget engine derives authoritative cumulative spend from the D-003 ledger
and, when spend crosses a hard cap, publishes a signed ``budget_limit`` policy to the
O-004 distribution seam so Sentinel F-008 blocks the scope. This migration adds the
three tables the engine needs (ADR-0005 §7):

1. ``budget_definitions`` — the caps to evaluate (one row per Sentinel ``policy_id``).
   Mirrors ``delta.budget.BudgetConcept`` (the locked ``budget_limit`` shape): four
   stable IDs + scope + period + integer-cent / token limits. ``anyOf`` (at least one
   limit) is enforced by a CHECK. Money is BIGINT integer cents (no float / NUMERIC).

2. ``budget_enforcement_state`` — per (budget, period window) edge state
   (``under``/``enforced``) for idempotent, edge-triggered publishing. The conditional
   transition ``UPDATE ... WHERE state='under'`` gates the publish so concurrent appends
   crossing the cap publish exactly once (ADR-0005 §3.3, vector 5).

3. ``budget_publish_outbox`` — the durable enforcement DECISION + delivery status. The
   signed policy is committed here in the SAME transaction as the state flip, BEFORE any
   network call, so a decision is never lost if O-004 is down or the process dies
   (vector 11). The UNIQUE (tenant, policy_id, policy_version) makes a re-evaluated
   crossing a no-op insert (defence-in-depth on top of the conditional transition). The
   ``failed`` state is the dead-letter (the outbox doubles as the DLQ, like D-004).

Unlike the append-only ledger (0001), these tables are MUTABLE within a tenant (state
transitions, delivery status), so ``delta_app`` is granted SELECT, INSERT, UPDATE (never
DELETE) and RLS allows tenant SELECT/INSERT/UPDATE. Same strict fail-closed NULLIF
predicate as D-003; an unset/empty GUC collapses to zero rows (never a widen).

DOWN: reverses every object in dependency order. It deliberately does NOT drop the
``delta`` schema (it houses ``alembic_version``) and never touches D-003/D-004 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

# The strict fail-closed RLS predicate — identical in shape to D-003 / F-003b Option α.
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# The largest monetary value any wire contract carries (D-001 MAX_MONEY_MINOR_UNITS / the
# locked BudgetLimitPolicy max_cost_cents_per_period bound).
_MAX_COST_CENTS = 100_000_000_000  # 1e11
# The locked BudgetLimitPolicy max_tokens_per_period bound.
_MAX_TOKENS = 1_000_000_000_000  # 1e12

_D005_TABLES = ("budget_definitions", "budget_enforcement_state", "budget_publish_outbox")


def _enable_mutable_rls(table: str) -> None:
    """ENABLE + FORCE RLS with tenant SELECT/INSERT/UPDATE policies (no DELETE).

    These tables are mutable within a tenant (unlike the append-only ledger). UPDATE is
    tenant-scoped on BOTH the visible row (USING) and the post-image (WITH CHECK) so a
    row can never be moved to another tenant. DELETE has no policy and the role has no
    DELETE grant, so rows are never removed.
    """
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
    # The delta schema already exists (0001). CREATE IF NOT EXISTS keeps this idempotent.
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")

    # --------------------------------------------------------- budget_definitions
    op.create_table(
        "budget_definitions",
        sa.Column("budget_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(8), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("period", sa.String(8), nullable=False),
        # Money: BIGINT integer cents only. No float / NUMERIC in the money path.
        sa.Column("limit_tokens", sa.BigInteger, nullable=True),
        sa.Column("limit_cost_cents", sa.BigInteger, nullable=True),
        sa.Column("currency", sa.String(3), nullable=False),
        # The stable Sentinel policy_id this budget publishes under. Versioning bumps
        # the version, never this id.
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("scope IN ('tenant','team','project','agent')", name="ck_bd_scope"),
        sa.CheckConstraint("period IN ('hourly','daily','monthly')", name="ck_bd_period"),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_bd_currency"),
        # anyOf: a budget that limits neither tokens nor cost is invalid (locked schema).
        sa.CheckConstraint(
            "limit_tokens IS NOT NULL OR limit_cost_cents IS NOT NULL",
            name="ck_bd_at_least_one_limit",
        ),
        sa.CheckConstraint(
            f"limit_tokens IS NULL OR (limit_tokens >= 0 AND limit_tokens <= {_MAX_TOKENS})",
            name="ck_bd_tokens_bounds",
        ),
        sa.CheckConstraint(
            "limit_cost_cents IS NULL OR "
            f"(limit_cost_cents >= 0 AND limit_cost_cents <= {_MAX_COST_CENTS})",
            name="ck_bd_cost_bounds",
        ),
        # Same-tenant FK target: lets the state + outbox tables bind (budget_id, tenant_id)
        # so a row can never reference another tenant's budget (review LOW; D-003 HIGH#2 shape).
        sa.UniqueConstraint("budget_id", "tenant_id", name="uq_bd_budget_tenant"),
        schema=_SCHEMA,
    )
    # One budget definition per (tenant, policy_id) — the natural key for versioned publish.
    op.create_index(
        "ux_bd_tenant_policy",
        "budget_definitions",
        ["tenant_id", "policy_id"],
        schema=_SCHEMA,
        unique=True,
    )
    # Evaluation looks budgets up by the scope key the affected event touches.
    op.create_index(
        "ix_bd_scope_key",
        "budget_definitions",
        ["tenant_id", "scope", "team_id", "project_id", "agent_id", "period"],
        schema=_SCHEMA,
    )

    # ---------------------------------------------------- budget_enforcement_state
    op.create_table(
        "budget_enforcement_state",
        sa.Column("state_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("budget_id", sa.String(64), nullable=False),
        # Denormalized period window key (e.g. '2026-07-01T00:00:00Z'); a new window
        # starts 'under' (a fresh budget period), so it is part of the uniqueness key.
        sa.Column("period_bucket", sa.String(32), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="under"),
        # The policy version currently enforcing (NULL while 'under').
        sa.Column("enforced_policy_version", sa.BigInteger, nullable=True),
        # Monotonic high-water mark of published versions (Sentinel rejects replay).
        sa.Column("last_published_version", sa.BigInteger, nullable=False, server_default="0"),
        # Highest soft-threshold % already warned this period (edge-dedup for advisory
        # warnings; ADR-0005 §3.6). Advisory only — never gates enforcement.
        sa.Column("last_warned_pct", sa.Integer, nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('under','enforced')", name="ck_bes_state"),
        sa.ForeignKeyConstraint(
            ["budget_id", "tenant_id"],
            [
                f"{_SCHEMA}.budget_definitions.budget_id",
                f"{_SCHEMA}.budget_definitions.tenant_id",
            ],
            name="fk_bes_budget",
        ),
        schema=_SCHEMA,
    )
    # One state row per (tenant, budget, period window) — the conditional-transition key.
    op.create_index(
        "ux_bes_key",
        "budget_enforcement_state",
        ["tenant_id", "budget_id", "period_bucket"],
        schema=_SCHEMA,
        unique=True,
    )

    # -------------------------------------------------------- budget_publish_outbox
    op.create_table(
        "budget_publish_outbox",
        sa.Column("outbox_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("budget_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.BigInteger, nullable=False),
        # 'enforce' = under->over (publish the cap); 'refresh' = budget raised / un-enforce.
        sa.Column("transition", sa.String(16), nullable=False),
        # The deterministic policy PAYLOAD (the emit output; the immutable enforcement
        # decision). Signed fresh at drain time, so a momentarily-missing signing key is a
        # delivery failure (retry + alert), never a lost decision (ADR-0005 §3.4/§3.5).
        sa.Column("policy_payload", postgresql.JSONB, nullable=False),
        sa.Column("distribution_id", sa.String(64), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("transition IN ('enforce','refresh')", name="ck_bpo_transition"),
        sa.CheckConstraint("state IN ('pending','distributed','failed')", name="ck_bpo_state"),
        sa.CheckConstraint("policy_version >= 1", name="ck_bpo_version_pos"),
        sa.ForeignKeyConstraint(
            ["budget_id", "tenant_id"],
            [
                f"{_SCHEMA}.budget_definitions.budget_id",
                f"{_SCHEMA}.budget_definitions.tenant_id",
            ],
            name="fk_bpo_budget",
        ),
        schema=_SCHEMA,
    )
    # Idempotent decision: exactly one outbox row per (tenant, policy, version). A
    # re-evaluated crossing that slips past the conditional transition still cannot
    # double-publish (vector 5 defence-in-depth).
    op.create_index(
        "ux_bpo_policy_version",
        "budget_publish_outbox",
        ["tenant_id", "policy_id", "policy_version"],
        schema=_SCHEMA,
        unique=True,
    )
    # The drainer scans pending rows due for (re)delivery.
    op.create_index(
        "ix_bpo_pending",
        "budget_publish_outbox",
        ["state", "next_attempt_at"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    # delta_app already exists (0001). Grant SELECT/INSERT/UPDATE (never DELETE) on the
    # mutable D-005 tables.
    for table in _D005_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.{table} TO {_APP_ROLE}")
    for table in _D005_TABLES:
        _enable_mutable_rls(table)


def downgrade() -> None:
    # Reverse dependency order. The `delta` schema is intentionally retained (it houses
    # alembic_version). Never touches D-003/D-004 data.
    for table in _D005_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
    for table in _D005_TABLES:
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_bpo_pending", table_name="budget_publish_outbox", schema=_SCHEMA)
    op.drop_index("ux_bpo_policy_version", table_name="budget_publish_outbox", schema=_SCHEMA)
    op.drop_table("budget_publish_outbox", schema=_SCHEMA)

    op.drop_index("ux_bes_key", table_name="budget_enforcement_state", schema=_SCHEMA)
    op.drop_table("budget_enforcement_state", schema=_SCHEMA)

    op.drop_index("ix_bd_scope_key", table_name="budget_definitions", schema=_SCHEMA)
    op.drop_index("ux_bd_tenant_policy", table_name="budget_definitions", schema=_SCHEMA)
    op.drop_table("budget_definitions", schema=_SCHEMA)
