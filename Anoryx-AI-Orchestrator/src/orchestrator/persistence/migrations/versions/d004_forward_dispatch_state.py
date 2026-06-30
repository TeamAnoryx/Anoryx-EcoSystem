"""forward_outbox dispatch-state columns (D-004, Orchestrator->Delta consume seam).

Revision ID: d004_forward_dispatch_state
Revises: 0001
Create Date: 2026-06-30

Adds the per-row delivery bookkeeping the D-004 push dispatcher needs to drain
forward_outbox 'usage' rows to Delta's inbound seam: an attempt counter (bounded retry),
the last attempt timestamp, and a short last-error string.

STRING REVISION ID (deliberate): this revision is named "d004_forward_dispatch_state"
rather than "0002" on purpose. A concurrent O-004 task may add its own migration off
"0001"; a sequential "0002" id would collide. A string-named revision off "0001" avoids
the id clash, and any resulting multi-head is resolved with `alembic merge` at integration
(both branch off the single 0001 baseline).

STATUS DOMAIN WIDENED: 0001 created forward_outbox with `CHECK (status IN ('pending'))`
(O-003 only ever recorded forward-INTENT, status='pending'; O-005 was to transition it).
The D-004 dispatcher transitions rows to 'forwarded' / 'failed' / 'skipped', so this
migration drops and re-creates ck_fo_status to admit those terminal values. Without this
the dispatcher's UPDATE would be rejected by the original single-value CHECK. The
downgrade restores the original `status IN ('pending')` domain (clean on a fresh/empty
table).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d004_forward_dispatch_state"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The status values the D-004 dispatcher may write, plus the original 'pending'.
_DISPATCH_STATUSES = "'pending','forwarded','failed','skipped'"


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # 1. Dispatch-state columns (attempt counter + last-attempt + last-error).
    # ------------------------------------------------------------------ #
    op.add_column(
        "forward_outbox",
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "forward_outbox",
        sa.Column("last_attempt_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "forward_outbox",
        sa.Column("last_error", sa.String(500), nullable=True),
    )
    op.create_check_constraint(
        "ck_forward_outbox_attempt_nonneg", "forward_outbox", "attempt_count >= 0"
    )

    # ------------------------------------------------------------------ #
    # 2. Widen ck_fo_status so the dispatcher can transition rows out of 'pending'.
    # ------------------------------------------------------------------ #
    op.drop_constraint("ck_fo_status", "forward_outbox", type_="check")
    op.create_check_constraint(
        "ck_fo_status", "forward_outbox", f"status IN ({_DISPATCH_STATUSES})"
    )


def downgrade() -> None:
    # Reverse of upgrade. Restore the original single-value status domain first (clean on a
    # fresh/empty table — any non-'pending' row would block the narrowing, by design), then
    # drop the constraint + the three columns in reverse order.
    op.drop_constraint("ck_fo_status", "forward_outbox", type_="check")
    op.create_check_constraint("ck_fo_status", "forward_outbox", "status IN ('pending')")

    op.drop_constraint("ck_forward_outbox_attempt_nonneg", "forward_outbox", type_="check")
    op.drop_column("forward_outbox", "last_error")
    op.drop_column("forward_outbox", "last_attempt_at")
    op.drop_column("forward_outbox", "attempt_count")
