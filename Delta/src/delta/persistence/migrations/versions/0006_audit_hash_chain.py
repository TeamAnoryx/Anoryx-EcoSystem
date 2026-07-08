"""Delta financial audit hash chain: upgrade change_history to be tamper-evident (D-009).

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-08

Turns D-007's plain-append-only-by-grant ``change_history`` table into a hash-chained,
tamper-evident audit log — the exact upgrade ADR-0007 §2 Fork 5 named this table for
("the change-history log gives D-009 a ready-made table to extend with a hash chain
rather than retrofitting one from nothing"). See ADR-0009 for the full design
(``delta.persistence.audit_log`` is the algorithm's single source of truth; this
migration imports it directly for the backfill step so the backfilled hashes are
byte-identical to what a live ``append_history`` call would have produced).

Steps (safe on both an EMPTY table — the fresh-DB/CI case — and a table with existing
D-007 rows from an already-deployed environment):

1. Add ``sequence_number``/``prev_hash``/``row_hash`` as NULLABLE columns first (an
   ALTER ADD COLUMN NOT NULL with no default would fail outright on any existing row).
2. Backfill ``sequence_number`` deterministically, ordered by ``(created_at,
   history_id)`` — NOT by physical row order, which Postgres does not guarantee matches
   insertion order.
3. Create the sequence for FUTURE inserts, seeded past the backfilled maximum, and wire
   it as the column's default (``BIGSERIAL``-equivalent, added explicitly rather than
   via ``ADD COLUMN ... BIGSERIAL`` so step 2's deterministic backfill order is the one
   that actually lands, not whatever physical order Postgres would have picked).
4. Backfill the hash chain itself, per tenant, in ``sequence_number`` order, using
   ``delta.persistence.audit_log.compute_row_hash`` — the SAME function
   ``append_history`` uses, so a backfilled row and a freshly-appended row are
   indistinguishable to ``verify_chain``.
5. Set all three columns NOT NULL, add CHECK/UNIQUE constraints, and the append-only
   trigger backstop (reusing ``delta.deny_ledger_modification()``, already defined by
   migration 0001 — the SAME function the D-003 ledger's own append-only guard uses).

DOWN: reverses every object in dependency order, drops the three columns and the
sequence. Retains the ``delta`` schema and never touches D-001..D-008 data otherwise.
"""

from __future__ import annotations

from datetime import timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from delta.persistence.audit_log import GENESIS_HASH, compute_row_hash

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"
_TABLE = "change_history"
_SEQ = "change_history_sequence_number_seq"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------- 1. nullable columns
    op.add_column(
        _TABLE, sa.Column("sequence_number", sa.BigInteger, nullable=True), schema=_SCHEMA
    )
    op.add_column(_TABLE, sa.Column("prev_hash", sa.String(64), nullable=True), schema=_SCHEMA)
    op.add_column(_TABLE, sa.Column("row_hash", sa.String(64), nullable=True), schema=_SCHEMA)

    # ------------------------------------------------- 2. backfill sequence_number
    op.execute(f"""
        WITH ordered AS (
            SELECT history_id, ROW_NUMBER() OVER (ORDER BY created_at, history_id) AS rn
            FROM {_SCHEMA}.{_TABLE}
        )
        UPDATE {_SCHEMA}.{_TABLE} ch
        SET sequence_number = ordered.rn
        FROM ordered
        WHERE ch.history_id = ordered.history_id
        """)

    # ------------------------------------------------- 3. sequence for future inserts
    op.execute(
        f"CREATE SEQUENCE IF NOT EXISTS {_SCHEMA}.{_SEQ} "
        f"OWNED BY {_SCHEMA}.{_TABLE}.sequence_number"
    )
    op.execute(
        f"SELECT setval('{_SCHEMA}.{_SEQ}', "
        f"COALESCE((SELECT MAX(sequence_number) FROM {_SCHEMA}.{_TABLE}), 0) + 1, false)"
    )
    op.execute(
        f"ALTER TABLE {_SCHEMA}.{_TABLE} "
        f"ALTER COLUMN sequence_number SET DEFAULT nextval('{_SCHEMA}.{_SEQ}')"
    )
    # nextval() on INSERT requires USAGE on the sequence itself — a table-level
    # grant does NOT cover it (the exact gap that broke every delta_app insert
    # path on first fresh-DB run; caught by the full suite, not by this
    # migration in isolation, since every enforcement/allocation test posts a
    # history row). Mirrors Sentinel's own migration 0006 (F-003b) granting
    # USAGE, SELECT on its audit sequence to sentinel_app.
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE {_SCHEMA}.{_SEQ} TO {_APP_ROLE}")

    # ------------------------------------------------- 4. backfill the hash chain
    # Python, not raw SQL: the hash is SHA-256 over canonical JSON, computed by the
    # SAME function (delta.persistence.audit_log.compute_row_hash) a live append uses.
    rows = (
        conn.execute(
            sa.text(
                f"SELECT history_id, tenant_id, entity_type, entity_id, action, actor, note, "
                f"created_at, sequence_number FROM {_SCHEMA}.{_TABLE} "
                f"ORDER BY tenant_id, sequence_number"
            )
        )
        .mappings()
        .all()
    )

    tip_by_tenant: dict[str, str] = {}
    for row in rows:
        prev_hash = tip_by_tenant.get(row["tenant_id"], GENESIS_HASH)
        row_hash = compute_row_hash(
            {
                "tenant_id": row["tenant_id"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "action": row["action"],
                "actor": row["actor"],
                "note": row["note"],
                # Normalize to UTC before hashing: this migration runs on the sync
                # driver, which returns TIMESTAMPTZ in the connection's session
                # TimeZone (not necessarily UTC), while the live append/verify path
                # runs on asyncpg, which always returns UTC. Hashing an un-normalized
                # offset here would desync a backfilled row's hash from what
                # verify_chain (delta.persistence.audit_log, which normalizes the
                # same way) recomputes later — a false "tampered" positive on
                # legitimately migrated data. See ADR-0009 §5 vector 1-adjacent.
                "created_at": row["created_at"].astimezone(timezone.utc).isoformat(),
                "prev_hash": prev_hash,
            }
        )
        conn.execute(
            sa.text(
                f"UPDATE {_SCHEMA}.{_TABLE} SET prev_hash = :prev, row_hash = :rh "
                f"WHERE history_id = :hid"
            ),
            {"prev": prev_hash, "rh": row_hash, "hid": row["history_id"]},
        )
        tip_by_tenant[row["tenant_id"]] = row_hash

    # ------------------------------------------------- 5. lock it down
    op.alter_column(_TABLE, "sequence_number", nullable=False, schema=_SCHEMA)
    op.alter_column(_TABLE, "prev_hash", nullable=False, schema=_SCHEMA)
    op.alter_column(_TABLE, "row_hash", nullable=False, schema=_SCHEMA)

    op.create_unique_constraint(
        "uq_history_sequence_number", _TABLE, ["sequence_number"], schema=_SCHEMA
    )
    op.create_unique_constraint("uq_history_row_hash", _TABLE, ["row_hash"], schema=_SCHEMA)
    op.create_check_constraint(
        "ck_history_row_hash_len", _TABLE, "length(row_hash) = 64", schema=_SCHEMA
    )
    op.create_check_constraint(
        "ck_history_prev_hash_len", _TABLE, "length(prev_hash) = 64", schema=_SCHEMA
    )
    op.create_index(
        "ix_history_tenant_seq", _TABLE, ["tenant_id", "sequence_number"], schema=_SCHEMA
    )

    # Append-only backstop: reuse the SAME trigger function the D-003 ledger's own
    # append-only guard uses (migration 0001) — no new function, no drift risk between
    # two near-identical "you can't touch this table" implementations.
    op.execute(f"""
        CREATE TRIGGER trg_{_TABLE}_deny_update
        BEFORE UPDATE ON {_SCHEMA}.{_TABLE}
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_ledger_modification();
        """)
    op.execute(f"""
        CREATE TRIGGER trg_{_TABLE}_deny_delete
        BEFORE DELETE ON {_SCHEMA}.{_TABLE}
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_ledger_modification();
        """)


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS trg_{_TABLE}_deny_delete ON {_SCHEMA}.{_TABLE}")
    op.execute(f"DROP TRIGGER IF EXISTS trg_{_TABLE}_deny_update ON {_SCHEMA}.{_TABLE}")

    op.drop_index("ix_history_tenant_seq", table_name=_TABLE, schema=_SCHEMA)
    op.drop_constraint("ck_history_prev_hash_len", _TABLE, schema=_SCHEMA, type_="check")
    op.drop_constraint("ck_history_row_hash_len", _TABLE, schema=_SCHEMA, type_="check")
    op.drop_constraint("uq_history_row_hash", _TABLE, schema=_SCHEMA, type_="unique")
    op.drop_constraint("uq_history_sequence_number", _TABLE, schema=_SCHEMA, type_="unique")

    op.drop_column(_TABLE, "row_hash", schema=_SCHEMA)
    op.drop_column(_TABLE, "prev_hash", schema=_SCHEMA)
    op.execute(f"ALTER TABLE {_SCHEMA}.{_TABLE} ALTER COLUMN sequence_number DROP DEFAULT")
    op.drop_column(_TABLE, "sequence_number", schema=_SCHEMA)
    op.execute(f"REVOKE ALL ON SEQUENCE {_SCHEMA}.{_SEQ} FROM {_APP_ROLE}")
    op.execute(f"DROP SEQUENCE IF EXISTS {_SCHEMA}.{_SEQ}")
