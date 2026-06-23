"""Add F-018 shadow-AI candidate detection audit event variant (ADR-0021 §7).

Revision ID: 0024
Revises: 0023
Create Date: 2026-06-24

F-018 widens ck_eal_event_type with one new shadow-AI candidate detection variant:

  shadow_ai_candidate_detected — a candidate shadow-AI endpoint was detected and
                                  recorded for review.  action_taken="logged"
                                  (detection-only; no blocking at this stage).

NO change to ck_eal_action_taken — 'logged' is already present in the existing
CHECK constraint.

Three new nullable columns carry F-018-specific signal metadata:
  confidence_band  VARCHAR(16)  — 'low' | 'medium' | 'high' (or NULL)
  fired_signals    VARCHAR(128) — comma-separated signal identifiers (or NULL)
  candidate_key    VARCHAR(64)  — stable dedup key for the candidate (or NULL)

Existing columns reused for the candidate payload (no new columns added for those):
  detected_endpoint   — the suspected shadow-AI endpoint URL
  traffic_volume      — observed request count
  first_seen_at       — RFC3339 timestamp of first observed traffic
  selected_provider   — provider label if identifiable

New constraints:
  ck_eal_confidence_band — confidence_band IS NULL OR confidence_band IN
                           ('low','medium','high')

New indexes:
  ix_eal_candidate_key  — (tenant_id, candidate_key) for dedup lookups

4-site consistency (ADR-0021 §7):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (separate step).

Fully reversible: downgrade() narrows ck_eal_event_type back to _WITH_F017
(the 0023 set), drops the three new columns, drops ck_eal_confidence_band, and
drops ix_eal_candidate_key. Loss-free — no pre-F-018 row uses the new event_type
value or the new columns.

Round-trip: upgrade head -> downgrade 0023 -> upgrade head.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"
_CONFIDENCE_CONSTRAINT = "ck_eal_confidence_band"
_CANDIDATE_INDEX = "ix_eal_candidate_key"

# Event-type set through F-017 / migration 0023 (the set we revert TO on downgrade).
# 50 types total — must match _WITH_F017 in 0023.
_WITH_F017 = (
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
    "'field_locked','field_unlocked','lock_condition_denied','data_lock_error'"
)

# F-018 widens the set with the one new shadow-AI candidate detection variant.
# 50 + 1 = 51 types total.
_WITH_F018 = _WITH_F017 + ",'shadow_ai_candidate_detected'"


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # 1. Widen ck_eal_event_type with the new F-018 shadow-AI candidate variant.
    _set_event_type_check(_WITH_F018)

    # 2. Add three new nullable columns for F-018 signal metadata.
    op.add_column(_TABLE, sa.Column("confidence_band", sa.String(16), nullable=True))
    op.add_column(_TABLE, sa.Column("fired_signals", sa.String(128), nullable=True))
    op.add_column(_TABLE, sa.Column("candidate_key", sa.String(64), nullable=True))

    # 3. Add CHECK constraint on confidence_band.
    op.create_check_constraint(
        _CONFIDENCE_CONSTRAINT,
        _TABLE,
        "confidence_band IS NULL OR confidence_band IN ('low','medium','high')",
    )

    # 4. Add composite index for dedup lookups on (tenant_id, candidate_key).
    op.create_index(_CANDIDATE_INDEX, _TABLE, ["tenant_id", "candidate_key"])


def downgrade() -> None:
    # 1. Drop the dedup index.
    op.drop_index(_CANDIDATE_INDEX, table_name=_TABLE)

    # 2. Drop the confidence_band CHECK constraint.
    op.drop_constraint(_CONFIDENCE_CONSTRAINT, _TABLE, type_="check")

    # 3. Drop the three new columns.
    op.drop_column(_TABLE, "candidate_key")
    op.drop_column(_TABLE, "fired_signals")
    op.drop_column(_TABLE, "confidence_band")

    # 4. Narrow ck_eal_event_type back to the F-017 set (0023 head).
    _set_event_type_check(_WITH_F017)
