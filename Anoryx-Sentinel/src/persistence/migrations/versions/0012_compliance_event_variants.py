"""Add F-011 compliance evidence event variants.

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-20

F-011 (ADR-0013 §9 D8) adds two compliance evidence event variants
(compliance_evidence_generated, compliance_pack_exported), both with
action_taken='logged' only. No new columns are added to events_audit_log —
the two variants reuse existing columns. ck_eal_action_taken is UNCHANGED.

Fully reversible: downgrade() narrows ck_eal_event_type back to _THROUGH_F009
(the 0011 set). Loss-free — no pre-F-011 row uses the two new values.

Round-trip: upgrade head -> downgrade -1 -> upgrade head verified at STEP 6.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-009 / migration 0011 (the _WITH_F009 constant from 0011
# verbatim — this is the set we revert TO on downgrade).
_THROUGH_F009 = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected','routing_decision',"
    "'policy_intake_accepted','policy_intake_rejected_signature',"
    "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
    "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny',"
    "'prompt_injection_detected_ml','classifier_unconfigured','classifier_degraded',"
    "'classifier_invocation_failed','shadow_ai_detected_outbound',"
    "'recursive_injection_attempt','judge_billing_event',"
    "'rate_limit_degraded','rate_limit_recovered','rate_limit_redis_error'"
)

# F-011 widens the set with the two compliance evidence variants.
_WITH_F011 = _THROUGH_F009 + ",'compliance_evidence_generated','compliance_pack_exported'"


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the 0008/0010/0011 widening pattern."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # Widen ck_eal_event_type with the two new compliance evidence variants.
    _set_event_type_check(_WITH_F011)


def downgrade() -> None:
    # Narrow ck_eal_event_type back to the F-009 set.
    _set_event_type_check(_THROUGH_F009)
