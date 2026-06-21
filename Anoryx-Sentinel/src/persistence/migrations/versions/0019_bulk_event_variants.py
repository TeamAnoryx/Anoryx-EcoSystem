"""Add F-015 bulk pipeline event variants (ADR-0018 §8 D7 / §9 D8).

Revision ID: 0019
Revises: 0018
Create Date: 2026-06-22

F-015 widens ck_eal_event_type with five bulk lifecycle/outcome variants:

  batch_submitted           — batch accepted at submit;      action_taken='logged'
  batch_file_processed      — a file completed (allow/redact); action_taken='logged'
  batch_file_blocked        — a file blocked by detector/policy; action_taken='blocked'
  batch_file_dead_lettered  — a file dead-lettered after retries; action_taken='logged'
  batch_completed           — all files reached terminal state; action_taken='logged'

NO new columns (the variants use the four stable IDs + action_taken). NO change to
ck_eal_action_taken — all five reuse 'logged'/'blocked', already allowed.

4-site consistency (ADR-0018 §8):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (STEP 8).

Fully reversible: downgrade() narrows ck_eal_event_type back to _WITH_F014 (the
0015 set). Loss-free — no pre-F-015 row uses the five new values.
Round-trip: 0017 -> 0018 -> 0019 -> 0018 -> 0017 verified at STEP 11.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-014 / migration 0015 (the set we revert TO on downgrade).
_WITH_F014 = (
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
    "'compliance_evidence_generated','compliance_pack_exported',"
    "'admin_tenant_created','admin_tenant_deactivated',"
    "'admin_key_minted','admin_key_revoked',"
    "'admin_config_updated','admin_audit_accessed',"
    "'operator_sso_login','operator_sso_denied',"
    "'admin_breakglass_used','idp_config_changed'"
)

# F-015 widens the set with the five bulk pipeline variants.
_WITH_F015 = (
    _WITH_F014 + ",'batch_submitted','batch_file_processed',"
    "'batch_file_blocked','batch_file_dead_lettered','batch_completed'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    _set_event_type_check(_WITH_F015)


def downgrade() -> None:
    _set_event_type_check(_WITH_F014)
