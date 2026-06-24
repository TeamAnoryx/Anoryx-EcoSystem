"""Add F-020 webhook audit event variants (ADR-0023 §5.2/§5.4). Head = 0030.

Revision ID: 0030
Revises: 0029
Create Date: 2026-06-24

F-020 widens ck_eal_event_type with three new outbound-webhook audit variants:

  webhook_delivered        — dispatcher delivered a webhook successfully.
                             action_taken="delivered"   (NEW — added to ck_eal_action_taken)
  webhook_delivery_failed  — dispatcher failed (guard rejected, transport, http_error,
                             or dead-lettered after bounded retries).
                             action_taken="failed"      (NEW — added to ck_eal_action_taken)
  webhook_config_updated   — admin CRUD on a tenant's webhook configuration.
                             action_taken="logged"      (already present)

Four new nullable signal columns carry F-020-specific metadata (ADR-0023 §5.2):
  webhook_provider    VARCHAR(16)  — 'slack' | 'jira' | 'splunk' (or NULL for
                                     non-webhook events). Bounded provider label ONLY —
                                     NEVER a target URL, NEVER a credential.
  delivery_attempts   SMALLINT     — attempt count forwarded from webhook_delivery
                                     (or NULL for non-delivery events). Bounded ≤ 100.
  failure_class       VARCHAR(32)  — terminal failure classification on
                                     webhook_delivery_failed events (contracts/events.schema.json
                                     WebhookDeliveryFailedEvent.failure_class). NULL for all
                                     non-failure events. Bounded enum — see ck_eal_failure_class.
  config_action       VARCHAR(16)  — CRUD verb on webhook_config_updated events
                                     (contracts/events.schema.json
                                     WebhookConfigUpdatedEvent.config_action). NULL for all
                                     non-config events. Bounded enum — see ck_eal_config_action.

ck_eal_action_taken is widened to admit 'delivered' and 'failed' (previously absent).
Both are specific to F-020 delivery events; no existing variant uses them.

4-site consistency (ADR-0023 §5.4):
  - VALID_EVENT_TYPES / ACTION_TAKEN_BY_EVENT_TYPE: events_audit_log.py (this PR).
  - ck_eal_event_type CHECK widen: THIS migration.
  - contracts/events.schema.json: api-architect (already landed — WebhookDeliveredEvent,
    WebhookDeliveryFailedEvent, WebhookConfigUpdatedEvent $defs present).
  - Emit primitive + tests: webhook-dispatcher builder (separate).

Fully reversible (mirrors 0024_shadow_ai_candidate_variant.py pattern):
  downgrade() narrows ck_eal_event_type back to _WITH_F019 (the 0027 set),
  narrows ck_eal_action_taken back to the pre-F-020 set, and drops the four new
  signal columns. Loss-free — no pre-F-020 row uses the new event_type values or
  the new columns.

Round-trip: upgrade head -> downgrade 0027 -> upgrade head.

Head ends at 0030.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "events_audit_log"
_EVENT_TYPE_CONSTRAINT = "ck_eal_event_type"
_ACTION_TAKEN_CONSTRAINT = "ck_eal_action_taken"

# ---------------------------------------------------------------------------
# Event-type value sets
# ---------------------------------------------------------------------------

# Event-type set through F-019 / migration 0027 (the set we revert TO on downgrade).
# 54 types total — must match _WITH_F019 in 0027.
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

# F-020 widens the set with three webhook audit variants. 54 + 3 = 57 types total.
_WITH_F020 = _WITH_F019 + ",'webhook_delivered','webhook_delivery_failed','webhook_config_updated'"

# ---------------------------------------------------------------------------
# action_taken value sets
# ---------------------------------------------------------------------------

# action_taken set through F-019 (pre-F-020). 'delivered' and 'failed' are absent.
_ACTION_TAKEN_PRE_F020 = (
    "'masked','tokenized','blocked','logged','throttled','warned','routed','failed_over'"
)

# F-020 adds 'delivered' (webhook_delivered) and 'failed' (webhook_delivery_failed).
_ACTION_TAKEN_WITH_F020 = (
    "'masked','tokenized','blocked','logged','throttled','warned','routed','failed_over',"
    "'delivered','failed'"
)


def _set_event_type_check(values: str) -> None:
    """DROP + ADD ck_eal_event_type — the established widening pattern (0008+)."""
    op.drop_constraint(_EVENT_TYPE_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_EVENT_TYPE_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def _set_action_taken_check(values: str) -> None:
    """DROP + ADD ck_eal_action_taken — same pattern as ck_eal_event_type."""
    op.drop_constraint(_ACTION_TAKEN_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(
        _ACTION_TAKEN_CONSTRAINT,
        _TABLE,
        f"action_taken IS NULL OR action_taken IN ({values})",
    )


def upgrade() -> None:
    # 1. Widen ck_eal_event_type with the three new F-020 webhook audit variants.
    _set_event_type_check(_WITH_F020)

    # 2. Widen ck_eal_action_taken to admit 'delivered' and 'failed'.
    _set_action_taken_check(_ACTION_TAKEN_WITH_F020)

    # 3. Add the four nullable F-020 signal columns (ADR-0023 §5.2).
    #    webhook_provider: bounded provider label — NEVER a target URL or credential.
    op.add_column(_TABLE, sa.Column("webhook_provider", sa.String(16), nullable=True))
    #    delivery_attempts: bounded attempt count from webhook_delivery — SMALLINT ≤ 100.
    op.add_column(_TABLE, sa.Column("delivery_attempts", sa.SmallInteger(), nullable=True))
    #    failure_class: terminal failure classification on webhook_delivery_failed events.
    #    Matches WebhookDeliveryFailedEvent.failure_class in contracts/events.schema.json.
    op.add_column(_TABLE, sa.Column("failure_class", sa.String(32), nullable=True))
    #    config_action: CRUD verb on webhook_config_updated events.
    #    Matches WebhookConfigUpdatedEvent.config_action in contracts/events.schema.json.
    op.add_column(_TABLE, sa.Column("config_action", sa.String(16), nullable=True))

    # 4. Add CHECK constraints for the four new columns.
    op.create_check_constraint(
        "ck_eal_webhook_provider",
        _TABLE,
        "webhook_provider IS NULL OR webhook_provider IN ('slack', 'jira', 'splunk')",
    )
    op.create_check_constraint(
        "ck_eal_delivery_attempts",
        _TABLE,
        "delivery_attempts IS NULL OR (delivery_attempts >= 1 AND delivery_attempts <= 100)",
    )
    op.create_check_constraint(
        "ck_eal_failure_class",
        _TABLE,
        "failure_class IS NULL OR failure_class IN ("
        "'url_guard_rejected','transport_error','http_error','dead_lettered')",
    )
    op.create_check_constraint(
        "ck_eal_config_action",
        _TABLE,
        "config_action IS NULL OR config_action IN ('created','updated','deleted')",
    )


def downgrade() -> None:
    # 1. Drop CHECK constraints on the new columns.
    op.drop_constraint("ck_eal_config_action", _TABLE, type_="check")
    op.drop_constraint("ck_eal_failure_class", _TABLE, type_="check")
    op.drop_constraint("ck_eal_delivery_attempts", _TABLE, type_="check")
    op.drop_constraint("ck_eal_webhook_provider", _TABLE, type_="check")

    # 2. Drop the four new signal columns.
    op.drop_column(_TABLE, "config_action")
    op.drop_column(_TABLE, "failure_class")
    op.drop_column(_TABLE, "delivery_attempts")
    op.drop_column(_TABLE, "webhook_provider")

    # 3. Narrow ck_eal_action_taken back to the pre-F-020 set.
    _set_action_taken_check(_ACTION_TAKEN_PRE_F020)

    # 4. Narrow ck_eal_event_type back to the F-019 set (0027 head).
    _set_event_type_check(_WITH_F019)
