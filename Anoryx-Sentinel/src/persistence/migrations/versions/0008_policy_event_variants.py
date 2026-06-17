"""Expand events_audit_log.ck_eal_event_type for the F-008 policy event variants.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-17

This is the ONLY new migration F-008 introduces (ADR-0009 §7). It adds the seven
policy intake/enforcement event types to the ck_eal_event_type CHECK constraint
via DROP + ADD. NO new tables, columns, indexes, or other constraints: the new
variants reuse existing audit columns (policy_id, action_taken, violation_type,
requested_model) and the existing ck_eal_action_taken enum values
('logged' / 'blocked'), so neither ck_eal_action_taken nor the hash-chain
CANONICAL_FIELDS change.

Round-trips cleanly: downgrade restores the prior (F-006) enum. The change only
WIDENS the allowed set, so no existing row can violate it.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CONSTRAINT = "ck_eal_event_type"
_TABLE = "events_audit_log"

# Pre-F-008 (through F-006) event-type set.
_OLD_EVENT_TYPES = (
    "'usage','pii_blocked','injection_detected',"
    "'secret_leaked','policy_violated','compliance_checked',"
    "'shadow_ai_detected','routing_decision'"
)

# F-008 adds the seven policy intake/enforcement variants.
_NEW_EVENT_TYPES = (
    _OLD_EVENT_TYPES + ","
    "'policy_intake_accepted','policy_intake_rejected_signature',"
    "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
    "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny'"
)


def _set_event_type_check(values: str) -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, f"event_type IN ({values})")


def upgrade() -> None:
    _set_event_type_check(_NEW_EVENT_TYPES)


def downgrade() -> None:
    _set_event_type_check(_OLD_EVENT_TYPES)
