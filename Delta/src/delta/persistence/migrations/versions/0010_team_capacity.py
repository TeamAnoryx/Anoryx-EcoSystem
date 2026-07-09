"""Delta team capacity management: teams, task-to-team assignment (D-016).

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-09

The roadmap's literal text for D-016 is: "Squad performance, capacity tracking,
automated resource allocation, real-time utilization to prevent burnout + optimize
throughput." This migration scopes that down to a deliberately bounded vertical slice
(ADR-0016): teams with an operator-declared per-sprint story-point capacity, task-to-
team assignment, a deterministic utilization report, and an advisory (never automatic)
rebalancing suggestion — not real-time push updates, not individual-level capacity/
PTO/burnout tracking (no such data exists anywhere in Delta), not a trained/validated
ML allocation model, and no automatic task reassignment (a suggestion is surfaced;
an operator applies it explicitly via the existing assign-team endpoint).

Two changes:

1. ``teams`` (NEW table) — one row per squad, ``capacity_points_per_sprint`` is a
   plain operator-entered integer (mirrors D-015's ``story_points`` discipline:
   ``reject_non_integer`` at the schema layer, a DB ``CHECK >= 0`` as a second,
   independent layer).
2. ``tasks.team_id`` (NEW nullable column on the D-015 ``tasks`` table) — additive,
   backward-compatible (existing D-015 rows get NULL, meaning "unassigned to a
   team"). Mirrors migration 0006's own precedent of extending an earlier task's
   table (``change_history``) with new nullable columns after the fact. delta.pm's
   own code (schemas/store/service/router) is NOT modified by this migration or by
   D-016 at all — only delta.capacity reads/writes this column.

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on ``teams`` (capacity is
updatable, mirrors ``sprints``/``tasks`` themselves) — no DELETE, matching every
prior Delta migration's convention. Same strict fail-closed NULLIF RLS predicate as
every prior migration.

DOWN: drops the ``team_id`` column and its FK/index first, then the ``teams`` table.
Retains the ``delta`` schema and never touches D-001..D-015 data otherwise.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
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
    # ------------------------------------------------------------------------- teams
    op.create_table(
        "teams",
        sa.Column("team_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("capacity_points_per_sprint", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "capacity_points_per_sprint >= 0", name="ck_team_capacity_nonneg"
        ),
        sa.UniqueConstraint("team_id", "tenant_id", name="uq_team_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_teams_tenant", "teams", ["tenant_id"], schema=_SCHEMA)

    # ------------------------------------------------------- tasks.team_id (additive)
    op.add_column(
        "tasks", sa.Column("team_id", sa.String(64), nullable=True), schema=_SCHEMA
    )
    op.create_foreign_key(
        "fk_task_team",
        "tasks",
        "teams",
        ["team_id", "tenant_id"],
        ["team_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_tasks_tenant_team", "tasks", ["tenant_id", "team_id"], schema=_SCHEMA)

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.teams TO {_APP_ROLE}")
    _enable_rls("teams", insert=True, update=True)


def downgrade() -> None:
    op.drop_index("ix_tasks_tenant_team", table_name="tasks", schema=_SCHEMA)
    op.drop_constraint("fk_task_team", "tasks", schema=_SCHEMA, type_="foreignkey")
    op.drop_column("tasks", "team_id", schema=_SCHEMA)

    op.execute(f"DROP POLICY IF EXISTS teams_tenant_update ON {_SCHEMA}.teams")
    op.execute(f"DROP POLICY IF EXISTS teams_tenant_insert ON {_SCHEMA}.teams")
    op.execute(f"DROP POLICY IF EXISTS teams_tenant_select ON {_SCHEMA}.teams")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.teams FROM {_APP_ROLE}")

    op.drop_index("ix_teams_tenant", table_name="teams", schema=_SCHEMA)
    op.drop_table("teams", schema=_SCHEMA)
