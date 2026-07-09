"""Delta project management: sprints, tasks, task_dependencies (D-015).

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-09

The roadmap's literal text for D-015 is: "Sprint-velocity tracking, dependency
mapping, execution-bottleneck prediction. Real-time, integrates with client/team-set
project parameters." This migration scopes that down to a deliberately bounded
vertical slice (ADR-0015): sprints, tasks, and a task-dependency graph, with velocity
computed as a bounded aggregate and "bottleneck prediction" as a deterministic
blocking-fan-out heuristic — not real-time push updates, not integration with an
external issue tracker, not a trained/validated ML prediction model.

Three tables:

1. ``sprints`` — a time-boxed period for one ``project_id`` (the SAME opaque
   client/team-set scope id D-007/D-008 already use — not a new "project" entity with
   its own identity; a sprint just carries the scope id it belongs to).
2. ``tasks`` — one row per unit of work, optionally assigned to a sprint (``sprint_id``
   NULL means backlog). ``completed_at`` is stamped/cleared alongside ``status``
   transitioning to/from 'done' — task status is NOT forward-only (a task can be
   reopened), unlike D-013's deal stages or D-014's asset lifecycle.
3. ``task_dependencies`` — a directed edge (``blocking_task_id`` must finish before
   ``blocked_task_id`` can proceed). Cycle-freedom is enforced at the service layer
   (a bounded graph traversal before insert), not by the database — Postgres has no
   native "no cycles in this edge table" constraint.

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on ``sprints``/``tasks`` (status/
assignment edits), and only SELECT, INSERT on ``task_dependencies`` (an edge, once
created, is not "updated" — mirrors ``interactions``'/``change_history``'s INSERT-only
grant). No table gets DELETE, matching every prior Delta migration's convention — an
operator cannot remove a mis-entered dependency edge in this version; named as a real
scope limitation in ADR-0015 §3, not a silent gap. Same strict fail-closed NULLIF RLS
predicate as every prior migration.

DOWN: reverses every object in dependency order. Retains the ``delta`` schema and never
touches D-001..D-014 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
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
    # --------------------------------------------------------------------------- sprints
    op.create_table(
        "sprints",
        sa.Column("sprint_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("start_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="planned"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("end_date > start_date", name="ck_sprint_end_after_start"),
        sa.CheckConstraint("status IN ('planned','active','completed')", name="ck_sprint_status"),
        sa.UniqueConstraint("sprint_id", "tenant_id", name="uq_sprint_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_sprints_tenant_project", "sprints", ["tenant_id", "project_id"], schema=_SCHEMA
    )

    # ----------------------------------------------------------------------------- tasks
    op.create_table(
        "tasks",
        sa.Column("task_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("sprint_id", sa.String(64), nullable=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="todo"),
        sa.Column("story_points", sa.Integer, nullable=True),
        sa.Column("assignee", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('todo','in_progress','done','blocked')", name="ck_task_status"
        ),
        sa.CheckConstraint(
            "story_points IS NULL OR story_points >= 0", name="ck_task_story_points_nonneg"
        ),
        sa.CheckConstraint(
            "(status = 'done') = (completed_at IS NOT NULL)", name="ck_task_completed_consistency"
        ),
        sa.ForeignKeyConstraint(
            ["sprint_id", "tenant_id"],
            [f"{_SCHEMA}.sprints.sprint_id", f"{_SCHEMA}.sprints.tenant_id"],
            name="fk_task_sprint",
        ),
        sa.UniqueConstraint("task_id", "tenant_id", name="uq_task_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_tasks_tenant_sprint", "tasks", ["tenant_id", "sprint_id"], schema=_SCHEMA)
    op.create_index(
        "ix_tasks_tenant_project_status",
        "tasks",
        ["tenant_id", "project_id", "status"],
        schema=_SCHEMA,
    )

    # ------------------------------------------------------------------ task_dependencies
    op.create_table(
        "task_dependencies",
        sa.Column("dependency_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("blocking_task_id", sa.String(64), nullable=False),
        sa.Column("blocked_task_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "blocking_task_id <> blocked_task_id", name="ck_dependency_no_self_reference"
        ),
        sa.ForeignKeyConstraint(
            ["blocking_task_id", "tenant_id"],
            [f"{_SCHEMA}.tasks.task_id", f"{_SCHEMA}.tasks.tenant_id"],
            name="fk_dependency_blocking_task",
        ),
        sa.ForeignKeyConstraint(
            ["blocked_task_id", "tenant_id"],
            [f"{_SCHEMA}.tasks.task_id", f"{_SCHEMA}.tasks.tenant_id"],
            name="fk_dependency_blocked_task",
        ),
        sa.UniqueConstraint("blocking_task_id", "blocked_task_id", name="uq_dependency_edge"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_dependencies_blocking", "task_dependencies", ["blocking_task_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_dependencies_blocked", "task_dependencies", ["blocked_task_id"], schema=_SCHEMA
    )
    op.create_index("ix_dependencies_tenant", "task_dependencies", ["tenant_id"], schema=_SCHEMA)

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.sprints TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.tasks TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.task_dependencies TO {_APP_ROLE}")

    _enable_rls("sprints", insert=True, update=True)
    _enable_rls("tasks", insert=True, update=True)
    _enable_rls("task_dependencies", insert=True, update=False)


def downgrade() -> None:
    for table in ("task_dependencies", "tasks", "sprints"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_dependencies_tenant", table_name="task_dependencies", schema=_SCHEMA)
    op.drop_index("ix_dependencies_blocked", table_name="task_dependencies", schema=_SCHEMA)
    op.drop_index("ix_dependencies_blocking", table_name="task_dependencies", schema=_SCHEMA)
    op.drop_table("task_dependencies", schema=_SCHEMA)

    op.drop_index("ix_tasks_tenant_project_status", table_name="tasks", schema=_SCHEMA)
    op.drop_index("ix_tasks_tenant_sprint", table_name="tasks", schema=_SCHEMA)
    op.drop_table("tasks", schema=_SCHEMA)

    op.drop_index("ix_sprints_tenant_project", table_name="sprints", schema=_SCHEMA)
    op.drop_table("sprints", schema=_SCHEMA)
