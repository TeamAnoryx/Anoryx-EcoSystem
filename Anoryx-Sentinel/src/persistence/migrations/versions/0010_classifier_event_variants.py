"""Add F-007 ML-classifier event variant columns + widen ck_eal_event_type.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-18

F-007 (ADR-0010 §8) adds seven event variants (prompt_injection_detected_ml,
classifier_unconfigured, classifier_degraded, classifier_invocation_failed,
shadow_ai_detected_outbound, recursive_injection_attempt, judge_billing_event).

Mirroring the F-006 routing_decision precedent (migration 0007), this adds the
eight new nullable variant columns to events_audit_log + their CHECK constraints,
and widens ck_eal_event_type with the seven new types (DROP+ADD, the 0008 pattern).
The new variants reuse the existing action_taken enum ('blocked'/'logged'), so
ck_eal_action_taken is UNCHANGED. judge_provider reuses selected_provider;
prompt/completion tokens reuse tokens_in/tokens_out; cost/latency reuse the usage
columns; the shadow outbound variant reuses the shadow_ai columns + selected_provider.

Round-trips cleanly: downgrade narrows the enum, drops the constraints, drops the
columns. The columns are additive + nullable, so no existing row is invalidated.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-008 (migration 0008's expanded list).
_THROUGH_F008 = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected','routing_decision',"
    "'policy_intake_accepted','policy_intake_rejected_signature',"
    "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
    "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny'"
)
# F-007 adds the seven ML-classifier / shadow-AI-egress variants.
_WITH_F007 = (
    _THROUGH_F008 + ","
    "'prompt_injection_detected_ml','classifier_unconfigured','classifier_degraded',"
    "'classifier_invocation_failed','shadow_ai_detected_outbound',"
    "'recursive_injection_attempt','judge_billing_event'"
)

# (column name, SQLAlchemy type) for the eight new nullable columns.
_NEW_COLUMNS = [
    ("judge_score", sa.Numeric(precision=4, scale=3)),
    ("judge_confidence", sa.Numeric(precision=4, scale=3)),
    ("final_score", sa.Numeric(precision=4, scale=3)),
    ("judge_model", sa.String(64)),
    ("judge_preset", sa.String(64)),
    ("judge_outcome", sa.String(16)),
    ("audit_mode", sa.String(16)),
    ("classifier_reason", sa.String(64)),
]


def _set_event_type_check(values: str) -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    for name, col_type in _NEW_COLUMNS:
        op.add_column(_TABLE, sa.Column(name, col_type, nullable=True))
    op.create_check_constraint(
        "ck_eal_judge_score",
        _TABLE,
        "judge_score IS NULL OR (judge_score >= 0 AND judge_score <= 1)",
    )
    op.create_check_constraint(
        "ck_eal_judge_confidence",
        _TABLE,
        "judge_confidence IS NULL OR (judge_confidence >= 0 AND judge_confidence <= 1)",
    )
    op.create_check_constraint(
        "ck_eal_final_score",
        _TABLE,
        "final_score IS NULL OR (final_score >= 0 AND final_score <= 1)",
    )
    op.create_check_constraint(
        "ck_eal_audit_mode", _TABLE, "audit_mode IS NULL OR audit_mode IN ('full','redacted')"
    )
    op.create_check_constraint(
        "ck_eal_judge_outcome",
        _TABLE,
        "judge_outcome IS NULL OR judge_outcome IN ('verdict','degraded','failed','policy_denied')",
    )
    _set_event_type_check(_WITH_F007)


def downgrade() -> None:
    _set_event_type_check(_THROUGH_F008)
    for name in (
        "ck_eal_judge_outcome",
        "ck_eal_audit_mode",
        "ck_eal_final_score",
        "ck_eal_judge_confidence",
        "ck_eal_judge_score",
    ):
        op.drop_constraint(name, _TABLE, type_="check")
    for name, _ in reversed(_NEW_COLUMNS):
        op.drop_column(_TABLE, name)
