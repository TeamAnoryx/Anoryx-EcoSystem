"""Delta budget allocation admin: allocations, targets, change history (D-007).

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-07

Turns the internal-only ``budget_engine.definitions.create_budget`` seam (D-005) into
an authenticated, auditable admin workflow (ADR-0007 §5). This migration adds three
tables:

1. ``allocations`` — a proposed distribution of a tenant total across scope targets
   (the D-001 ``delta.allocation.Allocation`` shape, made durable). ``status`` starts
   'requested' and only an explicit admin decision moves it to 'approved' or
   'rejected'; a budget cap is NEVER created as a side effect of the propose step.

2. ``allocation_targets`` — one row per target. ``budget_id`` is NULL until approval
   materializes the target into a real ``budget_definitions`` row (D-005's
   ``create_budget``), FK-scoped to its parent allocation + tenant so a row can never
   reference another tenant's allocation (mirrors D-006's kill_switch_outbox FK).

3. ``change_history`` — a plain APPEND-ONLY log of every lifecycle transition
   (requested/approved/rejected). NOT hash-chained: the tamper-evident chain for
   Delta's financial workflows is D-009, applied ecosystem-wide; this is its
   un-hash-chained precursor (an honest scope boundary, not a shortcut pretending to
   be that later guarantee).

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on ``allocations`` and
``allocation_targets`` (status/decision/budget_id transitions; never DELETE — matches
D-005/D-006's mutable-but-append/update-only tables). ``change_history`` gets ONLY
SELECT, INSERT (no UPDATE, no DELETE — the log itself is immutable at the grant
layer, not just by convention). Same strict fail-closed NULLIF RLS predicate as
D-003/D-005/D-006.

DOWN: reverses every object in dependency order. Retains the ``delta`` schema and
never touches D-001..D-006 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str, *, insert: bool, update: bool) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_select ON {_SCHEMA}.{table} "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    if insert:
        op.execute(
            f"CREATE POLICY {table}_tenant_insert ON {_SCHEMA}.{table} "
            f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
        )
    if update:
        op.execute(
            f"CREATE POLICY {table}_tenant_update ON {_SCHEMA}.{table} "
            f"FOR UPDATE USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
        )


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")

    # ------------------------------------------------------------------ allocations
    op.create_table(
        "allocations",
        sa.Column("allocation_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("total_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("period", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="requested"),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("total_minor_units >= 0", name="ck_alloc_total_nonneg"),
        sa.CheckConstraint("status IN ('requested','approved','rejected')", name="ck_alloc_status"),
        sa.CheckConstraint(
            "(status = 'requested') = (decided_by IS NULL AND decided_at IS NULL)",
            name="ck_alloc_decision_consistency",
        ),
        sa.UniqueConstraint("allocation_id", "tenant_id", name="uq_alloc_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_alloc_tenant_status",
        "allocations",
        ["tenant_id", "status"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------------- allocation_targets
    op.create_table(
        "allocation_targets",
        sa.Column("target_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("allocation_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(8), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("budget_id", sa.String(64), nullable=True),
        sa.CheckConstraint("amount_minor_units >= 0", name="ck_alloctgt_amount_nonneg"),
        sa.CheckConstraint(
            "scope IN ('tenant','team','project','agent')", name="ck_alloctgt_scope"
        ),
        sa.ForeignKeyConstraint(
            ["allocation_id", "tenant_id"],
            [f"{_SCHEMA}.allocations.allocation_id", f"{_SCHEMA}.allocations.tenant_id"],
            name="fk_alloctgt_allocation",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_alloctgt_allocation",
        "allocation_targets",
        ["allocation_id"],
        schema=_SCHEMA,
    )

    # -------------------------------------------------------------- change_history
    op.create_table(
        "change_history",
        sa.Column("history_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("note", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_history_tenant_entity",
        "change_history",
        ["tenant_id", "entity_type", "entity_id", "created_at"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.allocations TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.allocation_targets TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.change_history TO {_APP_ROLE}")

    _enable_rls("allocations", insert=True, update=True)
    _enable_rls("allocation_targets", insert=True, update=True)
    _enable_rls("change_history", insert=True, update=False)


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS change_history_tenant_insert ON {_SCHEMA}.change_history")
    op.execute(f"DROP POLICY IF EXISTS change_history_tenant_select ON {_SCHEMA}.change_history")

    for table in ("allocation_targets", "allocations"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")

    for table in ("allocations", "allocation_targets", "change_history"):
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_history_tenant_entity", table_name="change_history", schema=_SCHEMA)
    op.drop_table("change_history", schema=_SCHEMA)

    op.drop_index("ix_alloctgt_allocation", table_name="allocation_targets", schema=_SCHEMA)
    op.drop_table("allocation_targets", schema=_SCHEMA)

    op.drop_index("ix_alloc_tenant_status", table_name="allocations", schema=_SCHEMA)
    op.drop_table("allocations", schema=_SCHEMA)
