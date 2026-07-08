"""Rendly R-011 group huddles: huddles.callee_id becomes nullable + huddle_participants.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-08

The FIFTH Rendly DDL. Lifts the "1-on-1 ONLY" lock ADR-0007/R-009 deliberately built into the
``huddles`` persistence shape (ADR-0011, Fork F):

1. ``huddles.callee_id`` — ALTERED from ``NOT NULL`` to ``NULLABLE``. ``caller_id`` stays NOT
   NULL (there is always exactly one inviter, even for a group session). ``callee_id`` keeps its
   EXACT historical meaning for an archived session that had exactly 2 participants; it is NULL
   for a genuine 3+-participant session (there is no single "the other one" to name).

2. ``huddle_participants`` (new RLS table) — the AUTHORITATIVE full participant list for every
   huddle archived from this migration forward, 1-on-1 sessions included (a 2-row entry for
   those too, for a uniform read path). PK (tenant_id, huddle_id, user_id); FK to both
   ``huddles`` and ``users`` (the per-row DB-level "must be a real same-tenant user" proof, the
   per-participant analog of ``huddles``' own caller/callee FKs). APPEND-ONLY by grant
   (SELECT,INSERT only — same posture as ``huddles``/``messages``).

HONESTY BOUNDARY (verbatim, non-removable): no backfill of historical rows into
``huddle_participants`` — every huddle archived BEFORE this migration has caller_id/callee_id on
``huddles`` (its only participant record) but no corresponding ``huddle_participants`` rows.
Coverage starts at this migration boundary, disclosed, not silently implied as retroactive
(mirrors ADR-0009's own "chain coverage boundary" precedent for the message/huddle hash chains).
This migration does NOT rehash any existing ``huddles`` row — the hash-chain LINKAGE
(``prev_record_hash`` -> prior ``content_hash``) is untouched; only a FUTURE recomputation of a
pre-R-011 row's ``content_hash`` from raw fields must account for the old (caller_id, callee_id)
canonical field list (``persistence/hash_chain.py`` ``HUDDLE_CANONICAL_FIELDS``) instead of the
new ``participant_ids`` field — no chain-walking/verification surface exists yet either way.

DOWN: reverses child->parent. Never touches ``huddles`` rows or the ``rendly_app`` role.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "rendly"
_APP_ROLE = "rendly_app"

# The strict fail-closed RLS predicate — IDENTICAL to 0001/0002/0003/0004.
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")
    op.execute(
        f"CREATE POLICY {table}_tenant ON {_SCHEMA}.{table} "
        f"FOR ALL USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    # ----------------------------------------------------------------- huddles.callee_id
    op.alter_column("huddles", "callee_id", nullable=True, schema=_SCHEMA)

    # ------------------------------------------------------------- huddle_participants
    op.create_table(
        "huddle_participants",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("huddle_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "huddle_id", "user_id", name="pk_huddle_participants"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "huddle_id"],
            [f"{_SCHEMA}.huddles.tenant_id", f"{_SCHEMA}.huddles.huddle_id"],
            name="fk_huddle_participants_huddle",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_huddle_participants_user",
        ),
        schema=_SCHEMA,
    )

    # APPEND-ONLY by grant — same posture as huddles/messages.
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.huddle_participants TO {_APP_ROLE}")

    _enable_rls("huddle_participants")


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS huddle_participants_tenant ON {_SCHEMA}.huddle_participants")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.huddle_participants FROM {_APP_ROLE}")
    op.drop_table("huddle_participants", schema=_SCHEMA)

    op.alter_column("huddles", "callee_id", nullable=False, schema=_SCHEMA)
