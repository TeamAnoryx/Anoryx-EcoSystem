"""Rendly R-009 immutable archiving: message chain tip + huddle session records + chain.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-07

The FOURTH Rendly DDL. Turns the two DEFINE-ONLY archival fields R-001 reserved
(``prev_record_hash``/``content_hash``, ``contracts/messages.schema.json`` ``ArchivalMeta``)
into a real, SHA-256-based, tamper-evident hash chain (``persistence/hash_chain.py`` — the
Sentinel F-003 audit pattern, reused per-scope instead of globally):

1. ``channels.last_row_hash`` (new column) — the per-channel message-chain TIP (the last
   inserted message's ``content_hash``, or NULL before that channel's first message). Read and
   written under the SAME ``SELECT ... FOR UPDATE`` row lock migration 0002's FORK C already
   takes for ``next_seq`` assignment, so the chain link and the seq assignment stay consistent
   with no additional lock. ``messages.prev_record_hash``/``content_hash`` themselves need NO
   migration — 0002 already created them (always NULL until now); only the WRITER
   (``chat_repo.insert_message``) changes, in application code.

2. ``huddles`` (new RLS table) — the session record for a huddle's terminal ``ended`` state,
   which ADR-0007 (R-007) deliberately left ephemeral/in-memory with "R-009 owns... persisting
   the session record" as its own stated follow-up. PK (tenant_id, huddle_id). APPEND-ONLY by
   grant (SELECT,INSERT only — same posture as ``messages``). A ``declined`` ring is NEVER
   archived here (no session content to archive — matches the wire's own "archival is present
   once the huddle reaches ended").

3. ``huddle_chain_state`` (new RLS table) — the huddle analog of ``channels`` acting as its own
   lock+tip holder: one row per tenant (lazily upserted on that tenant's first archived
   huddle), locked via ``SELECT ... FOR UPDATE`` to serialize concurrent huddle-archive writes
   for the SAME tenant and read/advance the chain tip under that lock. Huddles chain per
   TENANT (not per channel — a huddle has no channel), matching ``ArchivalMeta.seq``'s own
   documented scope ("...per-tenant (huddles) ordering sequence").

HONESTY BOUNDARY (verbatim, non-removable): chain coverage starts at this migration boundary.
Any ``messages`` row inserted before R-009 shipped has ``prev_record_hash``/``content_hash``
NULL forever (there was no chain yet for it to link into) — a chain walk/verifier starts from
the first row carrying a real hash, not from the channel's first-ever message. This is
disclosed, not silently glossed over (ADR-0009).

DOWN: reverses every object child->parent. Never touches ``channels``/``messages`` rows or the
``rendly_app`` role (0001/0002 own the role; this migration only adds a column + two tables).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "rendly"
_APP_ROLE = "rendly_app"

# The strict fail-closed RLS predicate — IDENTICAL to 0001/0002/0003.
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

_NEW_RLS_TABLES = ("huddles", "huddle_chain_state")


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")
    op.execute(
        f"CREATE POLICY {table}_tenant ON {_SCHEMA}.{table} "
        f"FOR ALL USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    # ------------------------------------------------------------- channels.last_row_hash
    op.add_column(
        "channels",
        sa.Column("last_row_hash", sa.String(64), nullable=True),
        schema=_SCHEMA,
    )
    op.create_check_constraint(
        "ck_channels_last_row_hash_hex",
        "channels",
        "last_row_hash IS NULL OR last_row_hash ~ '^[0-9a-f]{64}$'",
        schema=_SCHEMA,
    )

    # --------------------------------------------------------------------------- huddles
    op.create_table(
        "huddles",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("huddle_id", sa.String(64), nullable=False),
        sa.Column("caller_id", sa.String(64), nullable=False),
        sa.Column("callee_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        # archival.seq — monotonic per-TENANT (not per-channel; a huddle has no channel).
        sa.Column("seq", sa.BigInteger, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=False),
        # Real hash-chain columns from the first row on (no RESERVED/NULL period — unlike
        # messages, this table did not exist before R-009, so there is nothing to migrate).
        sa.Column("prev_record_hash", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "huddle_id", name="pk_huddles"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{_SCHEMA}.tenants.tenant_id"], name="fk_huddles_tenant"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "caller_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_huddles_caller",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "callee_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_huddles_callee",
        ),
        # Per-tenant ordering: no two archived huddles for a tenant share a seq.
        sa.UniqueConstraint("tenant_id", "seq", name="uq_huddles_tenant_seq"),
        sa.CheckConstraint("seq >= 0", name="ck_huddles_seq_nonneg"),
        # Only a durable terminal state is ever archived (never ringing/accepted/active/busy;
        # never declined — see the module docstring).
        sa.CheckConstraint("state = 'ended'", name="ck_huddles_state"),
        sa.CheckConstraint("prev_record_hash ~ '^[0-9a-f]{64}$'", name="ck_huddles_prev_hash_hex"),
        sa.CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="ck_huddles_content_hash_hex"),
        schema=_SCHEMA,
    )

    # ------------------------------------------------------------------ huddle_chain_state
    op.create_table(
        "huddle_chain_state",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("next_seq", sa.BigInteger, nullable=False, server_default=sa.text("0")),
        sa.Column("last_row_hash", sa.String(64), nullable=True),
        sa.PrimaryKeyConstraint("tenant_id", name="pk_huddle_chain_state"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{_SCHEMA}.tenants.tenant_id"], name="fk_huddle_chain_state_tenant"
        ),
        sa.CheckConstraint("next_seq >= 0", name="ck_huddle_chain_state_next_seq_nonneg"),
        sa.CheckConstraint(
            "last_row_hash IS NULL OR last_row_hash ~ '^[0-9a-f]{64}$'",
            name="ck_huddle_chain_state_last_row_hash_hex",
        ),
        schema=_SCHEMA,
    )

    # ----------------------------------------------------------------- rendly_app grants
    # huddles: read + insert ONLY — APPEND-ONLY by grant, same posture as messages.
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.huddles TO {_APP_ROLE}")
    # huddle_chain_state: read + insert (the lazy first-archive upsert) + update (the locked
    # tip advance) — mirrors the channels grant (which also needs UPDATE for next_seq).
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.huddle_chain_state TO {_APP_ROLE}")

    # ------------------------------------------------------------------------------- RLS
    for table in _NEW_RLS_TABLES:
        _enable_rls(table)


def downgrade() -> None:
    for table in _NEW_RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")

    op.execute(f"REVOKE ALL ON {_SCHEMA}.huddles FROM {_APP_ROLE}")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.huddle_chain_state FROM {_APP_ROLE}")

    op.drop_table("huddle_chain_state", schema=_SCHEMA)
    op.drop_table("huddles", schema=_SCHEMA)

    op.drop_constraint("ck_channels_last_row_hash_hex", "channels", schema=_SCHEMA)
    op.drop_column("channels", "last_row_hash", schema=_SCHEMA)
