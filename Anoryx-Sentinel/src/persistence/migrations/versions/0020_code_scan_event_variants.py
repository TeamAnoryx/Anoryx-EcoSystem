"""Add F-016 code-scan event variants (ADR-0019 §10).

Revision ID: 0020
Revises: 0019
Create Date: 2026-06-22

F-016 widens ck_eal_event_type with four code-scan post-response detector
variants:

  code_scan_passed  — PASS verdict (clean code block);          action_taken='logged'
  code_scan_warned  — WARN verdict (audit-only; also covers     action_taken='logged'
                      would-BLOCK-on-stream cases with
                      block_suppressed_by_streaming=true in payload)
  code_scan_blocked — BLOCK verdict (non-streamed only;         action_taken='blocked'
                      response rejected via policy_blocked 403)
  code_scan_error   — scanner error/timeout → fail-safe WARN;  action_taken='logged'
                      never the scanner stack trace, never code.

NO new columns (all four variants use the four stable IDs + action_taken).
NO change to ck_eal_action_taken — all four reuse 'logged'/'blocked',
already allowed by the existing constraint.

4-site consistency (ADR-0019 §10):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (separate step).

Fully reversible: downgrade() narrows ck_eal_event_type back to _WITH_F015
(the 0019 set). Loss-free — no pre-F-016 row uses the four new event_type
values.

Round-trip: upgrade head -> downgrade 0019 -> upgrade head verified at STEP 11.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-015 / migration 0019 (the set we revert TO on downgrade).
# 42 types total — copied verbatim from _WITH_F015 in 0019.
_WITH_F015 = (
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
    "'batch_file_blocked','batch_file_dead_lettered','batch_completed'"
)

# F-016 widens the set with the four code-scan post-response detector variants.
# 42 + 4 = 46 types total.
_WITH_F016 = (
    _WITH_F015 + ",'code_scan_passed','code_scan_warned'," "'code_scan_blocked','code_scan_error'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # Widen ck_eal_event_type with the four new F-016 code-scan event variants.
    _set_event_type_check(_WITH_F016)


def downgrade() -> None:
    # Narrow ck_eal_event_type back to the F-015 set (0019 head).
    _set_event_type_check(_WITH_F015)
