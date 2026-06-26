"""Add per-tenant classifier threshold columns to tenant_routing_policy (ADR-0025).

Revision ID: 0032
Revises: 0031
Create Date: 2026-06-26

F-007 enhancement (ADR-0025): makes the LLM-as-judge band + confidence floor
per-tenant instead of global. Adds three nullable threshold columns to
tenant_routing_policy:

  - classifier_confidence_threshold NUMERIC(4,3) NULL  — judge verdict ignored
        when its confidence < this. NULL = code default 0.5.
  - classifier_skip_threshold       NUMERIC(4,3) NULL  — judge skipped (obvious
        attack) when regex_score >= this. NULL = code default 0.9.
  - classifier_floor_threshold      NUMERIC(4,3) NULL  — judge skipped (obvious
        clean) when regex_score < this. NULL = code default 0.0.

plus four CHECK constraints: each threshold in [0,1] (or NULL), and a band-sanity
constraint floor <= skip (when both set). NO new table (config rides in the
existing F-006/F-007 home). F-003b RLS on tenant_routing_policy already applies —
no new policy. policy.schema.json (LOCKED) and events.schema.json are untouched —
thresholds are config, not emitted.

Round-trips cleanly: downgrade drops the four constraints + three columns. The
columns are additive + nullable, so no existing row is invalidated; a NULL column
resolves to today's constant, so behavior is byte-identical until an operator sets
a value.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: Union[str, None] = "0031"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "tenant_routing_policy"

# (column name, CHECK name) for the three [0,1]-or-NULL threshold columns.
_THRESHOLDS = [
    ("classifier_confidence_threshold", "ck_trp_classifier_confidence"),
    ("classifier_skip_threshold", "ck_trp_classifier_skip"),
    ("classifier_floor_threshold", "ck_trp_classifier_floor"),
]


def upgrade() -> None:
    for name, _ in _THRESHOLDS:
        op.add_column(_TABLE, sa.Column(name, sa.Numeric(precision=4, scale=3), nullable=True))
    for name, ck in _THRESHOLDS:
        op.create_check_constraint(ck, _TABLE, f"{name} IS NULL OR ({name} >= 0 AND {name} <= 1)")
    # Band sanity: the uncertain band [floor, skip) must be non-inverted when both set.
    op.create_check_constraint(
        "ck_trp_classifier_band",
        _TABLE,
        "classifier_floor_threshold IS NULL OR classifier_skip_threshold IS NULL "
        "OR classifier_floor_threshold <= classifier_skip_threshold",
    )


def downgrade() -> None:
    op.drop_constraint("ck_trp_classifier_band", _TABLE, type_="check")
    for _name, ck in reversed(_THRESHOLDS):
        op.drop_constraint(ck, _TABLE, type_="check")
    for name, _ck in reversed(_THRESHOLDS):
        op.drop_column(_TABLE, name)
