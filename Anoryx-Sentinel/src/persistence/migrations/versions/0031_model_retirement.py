"""Add F-021 model-retirement column + operator audit event variants. Head = 0031.

Revision ID: 0031
Revises: 0030
Create Date: 2026-06-25

F-021 (ADR-0024) adds backend-ENFORCED model retirement with a grace period on
top of F-019's approval engine. Two additive schema changes:

1. model_inventory.retire_at TIMESTAMPTZ NULL — the grace deadline after which an
   APPROVED model is denied at the gateway (src/policy/enforcement.py, fail-closed).
   NULL = not scheduled for retirement. A row with state='approved' and a non-NULL
   retire_at is "retiring": usable until this instant, then denied. The inventory
   `state` CHECK is DELIBERATELY UNCHANGED (states stay pending/approved/denied —
   "retiring" is a UI-derived presentation of approved+retire_at, not a stored
   state), so ck_model_inventory_state is not touched (ADR-0024 Fork 1=A).

2. ck_eal_event_type widened with two operator-action audit variants (action-only;
   the deadline itself lives on the model_inventory row, NOT in the event — so NO
   new hash-folded audit column, ADR-0024 audit-granularity decision):

     model_retirement_scheduled  — operator scheduled retirement of an approved
                                    model with a grace deadline. action_taken="logged".
     model_retirement_cancelled  — operator cancelled a scheduled retirement.
                                    action_taken="logged".

   Both use action_taken='logged' (already in ck_eal_action_taken — UNCHANGED).
   The model identifier rides in the existing `model` column (no new column).

4-site consistency (ADR-0024):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE / inline ck_eal_event_type
    mirror: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (ModelRetirementScheduledEvent,
    ModelRetirementCancelledEvent $defs present + registered in the oneOf union).
  - ADMIN_EVENT_TYPES + emit calls: src/admin/audit.py + src/admin/model_approval.py.

Fully reversible (mirrors 0030's pattern):
  downgrade() narrows ck_eal_event_type back to _WITH_F020 (the 0030 set) and drops
  the retire_at column. Loss-free — no pre-F-021 row uses the new event_type values
  or the retire_at column.

Round-trip: upgrade head -> downgrade 0030 -> upgrade head.

Head ends at 0031.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_EAL_TABLE = "events_audit_log"
_EVENT_TYPE_CONSTRAINT = "ck_eal_event_type"
_INVENTORY_TABLE = "model_inventory"

# ---------------------------------------------------------------------------
# Event-type value sets
# ---------------------------------------------------------------------------

# Event-type set through F-019 / migration 0027 (54 types).
_WITH_F019 = (
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
    "'shadow_ai_candidate_detected',"
    "'model_approved','model_denied','model_adopted'"
)

# F-020 (migration 0030) added three webhook variants. 54 + 3 = 57 types.
_WITH_F020 = _WITH_F019 + ",'webhook_delivered','webhook_delivery_failed','webhook_config_updated'"

# F-021 (this migration) adds two model-retirement operator variants. 57 + 2 = 59 types.
_WITH_F021 = _WITH_F020 + ",'model_retirement_scheduled','model_retirement_cancelled'"


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_EVENT_TYPE_CONSTRAINT, _EAL_TABLE, type_="check")
    op.create_check_constraint(_EVENT_TYPE_CONSTRAINT, _EAL_TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # 1. Add the nullable grace-deadline column to the inventory. No state CHECK
    #    change — "retiring" is a UI-derived view of approved+retire_at (ADR-0024).
    op.add_column(
        _INVENTORY_TABLE, sa.Column("retire_at", sa.DateTime(timezone=True), nullable=True)
    )

    # 2. Widen ck_eal_event_type with the two F-021 operator-action variants.
    _set_event_type_check(_WITH_F021)


def downgrade() -> None:
    # 1. Narrow ck_eal_event_type back to the F-020 set (0030 head).
    _set_event_type_check(_WITH_F020)

    # 2. Drop the retire_at column.
    op.drop_column(_INVENTORY_TABLE, "retire_at")
