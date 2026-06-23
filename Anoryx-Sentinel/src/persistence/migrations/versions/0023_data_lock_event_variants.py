"""Add F-017 data-lock event variants (ADR-0020 §9).

Revision ID: 0023
Revises: 0022
Create Date: 2026-06-23

F-017 widens ck_eal_event_type with four data-lock post-response detector
variants:

  field_locked          — a field value was withheld (time-not-yet/generic). blocked
  field_unlocked        — a matched field's condition was met → released.     logged
  lock_condition_denied — a PERMISSION allow-list did not match the caller.   blocked
  data_lock_error       — fail-closed: ruleset unevaluable → response blocked. blocked
                          Never a field value, never a stack trace.

NO new columns (all four variants reuse the four stable IDs + action_taken +
the existing nullable pattern_name / violation_type / policy_id columns — never
the field value, CLAUDE.md rule 6).
NO change to ck_eal_action_taken — all four reuse 'logged'/'blocked', already
allowed by the existing constraint.

4-site consistency (ADR-0020 §9):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (separate step).

Fully reversible: downgrade() narrows ck_eal_event_type back to _WITH_F016
(the 0020 set). Loss-free — no pre-F-017 row uses the four new event_type values.

Round-trip: upgrade head -> downgrade 0022 -> upgrade head (verified at STEP 10).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-016 / migration 0020 (the set we revert TO on downgrade).
# 46 types total — must match _WITH_F016 in 0020.
_WITH_F016 = (
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
    "'admin_breakglass_used','idp_config_changed',"
    "'batch_submitted','batch_file_processed',"
    "'batch_file_blocked','batch_file_dead_lettered','batch_completed',"
    "'code_scan_passed','code_scan_warned','code_scan_blocked','code_scan_error'"
)

# F-017 widens the set with the four data-lock post-response detector variants.
# 46 + 4 = 50 types total.
_WITH_F017 = (
    _WITH_F016 + ",'field_locked','field_unlocked','lock_condition_denied','data_lock_error'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # Widen ck_eal_event_type with the four new F-017 data-lock event variants.
    _set_event_type_check(_WITH_F017)


def downgrade() -> None:
    # Narrow ck_eal_event_type back to the F-016 set (0022/0020 head).
    _set_event_type_check(_WITH_F016)
