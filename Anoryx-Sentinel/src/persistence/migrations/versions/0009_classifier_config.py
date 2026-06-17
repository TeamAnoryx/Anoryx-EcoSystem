"""Add classifier config columns to tenant_routing_policy (F-007, ADR-0010 §7).

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-18

Adds the F-007 LLM-as-judge classifier config to tenant_routing_policy:
  - classifier_model_id VARCHAR(64) NULL          — judge preset, or NULL = unconfigured
  - audit_mode VARCHAR(16) NOT NULL DEFAULT 'full' — 'full' | 'redacted' (R10)

plus two CHECK constraints (audit_mode enum; classifier_model_id allow-list with
NULL permitted). NO new table (R2). F-003b RLS on tenant_routing_policy already
applies — no new policy needed (R13).

Round-trips cleanly: downgrade drops both constraints + columns. The columns are
additive and nullable / defaulted, so no existing row is invalidated.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "tenant_routing_policy"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("classifier_model_id", sa.String(64), nullable=True))
    op.add_column(
        _TABLE,
        sa.Column("audit_mode", sa.String(16), nullable=False, server_default="full"),
    )
    op.create_check_constraint("ck_trp_audit_mode", _TABLE, "audit_mode IN ('full','redacted')")
    op.create_check_constraint(
        "ck_trp_classifier_model_id",
        _TABLE,
        "classifier_model_id IS NULL OR classifier_model_id IN "
        "('anthropic:claude-haiku-4-5','openai:gpt-4o-mini')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_trp_classifier_model_id", _TABLE, type_="check")
    op.drop_constraint("ck_trp_audit_mode", _TABLE, type_="check")
    op.drop_column(_TABLE, "audit_mode")
    op.drop_column(_TABLE, "classifier_model_id")
