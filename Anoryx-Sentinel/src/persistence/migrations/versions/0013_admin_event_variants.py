"""Add F-012 admin console action event variants.

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-20

F-012 (ADR-0014 §8/§10 D7/D9) adds six admin console action event variants:
admin_tenant_created, admin_tenant_deactivated, admin_key_minted,
admin_key_revoked, admin_config_updated, admin_audit_accessed — all with
action_taken='logged' only. No new columns are added to events_audit_log; the
variants reuse existing columns. ck_eal_action_taken is UNCHANGED.

Honest attribution (R6): admin events carry agent_id='admin-console' and the
TARGET tenant_id; tenant-level events use team_id=project_id=WILDCARD_UUID. This
migration only governs the event_type CHECK; attribution is enforced at the
application layer (src/admin/audit.py) and in contracts/events.schema.json.

Fully reversible: downgrade() narrows ck_eal_event_type back to _THROUGH_F011
(the 0012 set). Loss-free — no pre-F-012 row uses the six new values.

Round-trip: upgrade head -> downgrade 0012 -> upgrade head verified at STEP 10.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-011 / migration 0012 (the _WITH_F011 set from 0012
# verbatim — this is the set we revert TO on downgrade).
_THROUGH_F011 = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected','routing_decision',"
    "'policy_intake_accepted','policy_intake_rejected_signature',"
    "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
    "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny',"
    "'prompt_injection_detected_ml','classifier_unconfigured','classifier_degraded',"
    "'classifier_invocation_failed','shadow_ai_detected_outbound',"
    "'recursive_injection_attempt','judge_billing_event',"
    "'rate_limit_degraded','rate_limit_recovered','rate_limit_redis_error',"
    "'compliance_evidence_generated','compliance_pack_exported'"
)

# F-012 widens the set with the six admin console action variants.
_WITH_F012 = (
    _THROUGH_F011 + ",'admin_tenant_created','admin_tenant_deactivated',"
    "'admin_key_minted','admin_key_revoked',"
    "'admin_config_updated','admin_audit_accessed'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the 0008/0010/0011/0012 widening pattern."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # Widen ck_eal_event_type with the six new admin console action variants.
    _set_event_type_check(_WITH_F012)


def downgrade() -> None:
    # Narrow ck_eal_event_type back to the F-011 set.
    _set_event_type_check(_THROUGH_F011)
