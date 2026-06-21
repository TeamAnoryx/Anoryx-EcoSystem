"""Add F-014 SSO event variants + actor_id attribution column.

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-21

F-014 (ADR-0017 §10/§11 D9/D10) adds four SSO + break-glass audit event
variants and one nullable attribution column:

  operator_sso_login    — SSO login succeeds;            action_taken='logged'
  operator_sso_denied   — assertion valid, no role/user; action_taken='blocked'
  admin_breakglass_used — env-token break-glass used;    action_taken='logged'
  idp_config_changed    — operator creates/updates IdP;  action_taken='logged'

  actor_id VARCHAR(64) NULL — the internal admin_users.id UUID (opaque, NOT PII,
  NOT the raw IdP subject/email). Nullable because not all events have a resolved
  operator (e.g. pre-binding denials, break-glass). No default; no sentinel_app
  GRANT needed — actor_id rides the existing events_audit_log grants, and only
  the privileged session writes to events_audit_log (append path).

4-site consistency:
  - contracts/events.schema.json: DONE by api-architect (4 new variants + actor_id $def).
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: DONE in events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - actor_id column ADD: THIS migration.

Fully reversible:
  downgrade() narrows ck_eal_event_type back to _THROUGH_F012 (the 0013 set)
  and drops the actor_id column. Loss-free — no pre-F-014 row uses the four new
  event_type values, and actor_id contains no data at downgrade time.

Round-trip: upgrade head -> downgrade 0014 -> upgrade head verified at STEP 11.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_CONSTRAINT = "ck_eal_event_type"

# Event-type set through F-012 / migration 0013 (the _WITH_F012 set from 0013
# verbatim — this is the set we revert TO on downgrade).
_THROUGH_F012 = (
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
    "'admin_config_updated','admin_audit_accessed'"
)

# F-014 widens the set with the four SSO + break-glass event variants.
_WITH_F014 = (
    _THROUGH_F012 + ",'operator_sso_login','operator_sso_denied',"
    "'admin_breakglass_used','idp_config_changed'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    # Widen ck_eal_event_type with the four new F-014 SSO event variants.
    _set_event_type_check(_WITH_F014)

    # Add the nullable actor_id attribution column (VARCHAR(64), no default).
    # Nullable: not all events have a resolved operator (pre-binding denials,
    # break-glass). The privileged session controls all writes; no new GRANT needed.
    op.add_column(
        _TABLE,
        sa.Column("actor_id", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    # Drop actor_id column (pre-F-014 rows never had it; loss-free).
    op.drop_column(_TABLE, "actor_id")

    # Narrow ck_eal_event_type back to the F-012 set.
    _set_event_type_check(_THROUGH_F012)
