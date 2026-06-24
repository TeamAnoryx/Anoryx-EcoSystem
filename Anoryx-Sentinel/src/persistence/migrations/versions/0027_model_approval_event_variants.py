"""Add F-019 model-approval operator-action audit event variants (ADR-0022 §5.4).

Revision ID: 0027
Revises: 0026
Create Date: 2026-06-24

F-019 widens ck_eal_event_type with three new operator-action variants:

  model_approved — an operator transitioned a model to 'approved'.  action_taken="logged"
  model_denied   — an operator transitioned a model to 'denied'.    action_taken="logged"
  model_adopted  — a model was registered into the inventory as 'pending'. action_taken="logged"

These are operator administrative decisions (inventory state transitions), NOT
runtime request blocks. Runtime use-denials (a request for a non-approved model)
are audited via the EXISTING policy_decision_deny event with reason
'model_not_approved' — exactly as F-008 allowlist/denylist denials are — so F-019
adds NO runtime event variant and double-logs nothing.

NO new columns: the model identifier rides in the existing `model` column (the
usage-variant String(256)); the decision is encoded by the event_type itself. NO
change to ck_eal_action_taken — 'logged' is already present.

4-site consistency (ADR-0022 §5.4):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE + inline ck_eal_event_type:
    events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (separate step).

Fully reversible: downgrade() narrows ck_eal_event_type back to _WITH_F018 (the
0024 set). Loss-free — no pre-F-019 row uses the new event_type values.

Round-trip: upgrade head -> downgrade 0024 -> upgrade head (verified at STEP 9).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-018 / migration 0024 (the set we revert TO on downgrade).
# 51 types total — must match _WITH_F018 in 0024 (0025/0026 did not touch this constraint).
_WITH_F018 = (
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
    "'code_scan_passed','code_scan_warned','code_scan_blocked','code_scan_error',"
    "'field_locked','field_unlocked','lock_condition_denied','data_lock_error',"
    "'shadow_ai_candidate_detected'"
)

# F-019 widens the set with three operator-action variants. 51 + 3 = 54 types total.
_WITH_F019 = _WITH_F018 + ",'model_approved','model_denied','model_adopted'"


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    _set_event_type_check(_WITH_F019)


def downgrade() -> None:
    _set_event_type_check(_WITH_F018)
