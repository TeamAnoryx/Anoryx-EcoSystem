"""merge O-004 distribution and D-004 forward-dispatch heads

Revision ID: 0003_merge_o004_d004
Revises: 0002, d004_forward_dispatch_state
Create Date: 2026-06-30 14:37:04.897319+00:00

A no-op merge revision unifying the two migration heads that branch off 0001:
``0002`` (O-004 policy distribution) and ``d004_forward_dispatch_state`` (D-004
forward dispatch). Both landed on main independently; this merge restores a
single Orchestrator alembic head. No schema changes.
"""

from __future__ import annotations

from typing import Sequence, Union

revision: str = "0003_merge_o004_d004"
down_revision: Union[str, Sequence[str], None] = ("0002", "d004_forward_dispatch_state")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
