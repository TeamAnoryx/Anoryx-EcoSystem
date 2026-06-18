"""Add F-009 rate-limit observability event variants + team_rpm_limit column.

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-18

F-009 (ADR-0011 §7/§8) adds three rate-limit observability event variants
(rate_limit_degraded, rate_limit_recovered, rate_limit_redis_error), all with
action_taken='logged'. No new columns are added to events_audit_log — the three
variants reuse existing columns; redis_error_class is carried only in the
Redis-Streams event JSON and the OTel span event, never in an audit-log column
(ADR-0011 §7 / §10 alternatives-considered). ck_eal_action_taken is UNCHANGED.

F-009 also adds the team_rpm_limit nullable INTEGER column to tenant_routing_policy
for the three-tier rate limiter (key < team < tenant). NULL = team tier disabled
(default behavior is byte-identical to F-004). A CHECK ensures the value is > 0
when set (0 would silently block all team traffic).

R7 deviation note (ADR-0011 §8): R7 originally read "only widens the CHECK
constraint." The team-tier refinement (Affu-authorized) requires one nullable
column on the existing tenant_routing_policy table. No new tables. Fully
reversible: downgrade() drops ck_trp_team_rpm_limit + team_rpm_limit, then
narrows ck_eal_event_type back to _THROUGH_F007. No pre-existing row is
invalidated (CHECK only widens an allowed set; new column is nullable).

Round-trip: upgrade head -> downgrade -1 -> upgrade head verified at STEP 10.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-007 / migration 0010 (the _WITH_F007 constant from 0010
# verbatim — this is the set we revert TO on downgrade).
_THROUGH_F007 = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected','routing_decision',"
    "'policy_intake_accepted','policy_intake_rejected_signature',"
    "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
    "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny',"
    "'prompt_injection_detected_ml','classifier_unconfigured','classifier_degraded',"
    "'classifier_invocation_failed','shadow_ai_detected_outbound',"
    "'recursive_injection_attempt','judge_billing_event'"
)

# F-009 widens the set with the three rate-limit observability variants.
_WITH_F009 = (
    _THROUGH_F007 + ",'rate_limit_degraded','rate_limit_recovered','rate_limit_redis_error'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the 0008/0010 widening pattern."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # 1. Widen ck_eal_event_type with the three new rate-limit observability variants.
    _set_event_type_check(_WITH_F009)

    # 2. Add the opt-in team-tier RPM ceiling column to tenant_routing_policy.
    op.add_column(
        "tenant_routing_policy",
        sa.Column("team_rpm_limit", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "ck_trp_team_rpm_limit",
        "tenant_routing_policy",
        "team_rpm_limit IS NULL OR team_rpm_limit > 0",
    )


def downgrade() -> None:
    # Reverse in the opposite order: drop tenant_routing_policy additions first,
    # then narrow ck_eal_event_type back to the F-007 set.
    op.drop_constraint("ck_trp_team_rpm_limit", "tenant_routing_policy", type_="check")
    op.drop_column("tenant_routing_policy", "team_rpm_limit")
    _set_event_type_check(_THROUGH_F007)
