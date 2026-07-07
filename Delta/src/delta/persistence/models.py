"""SQLAlchemy Core table definitions for the Delta ledger (D-003).

Core (not ORM) `Table` objects schema-qualified into ``delta``. The store and the
balance read primitives build statements against these; the authoritative DDL is the
Alembic migration (``versions/0001_ledger_schema.py``) — these definitions only
describe the columns the query layer references and are kept in lock-step with it.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from . import DELTA_SCHEMA

metadata = sa.MetaData(schema=DELTA_SCHEMA)

accounts = sa.Table(
    "accounts",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("type", sa.String(16), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
)

transactions = sa.Table(
    "transactions",
    metadata,
    sa.Column("txn_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    sa.Column("description", sa.String(512), nullable=False, server_default=""),
    sa.Column("reversal_of", sa.String(64), nullable=True),
    sa.Column("idempotency_key", sa.String(255), nullable=True),
)

ledger_entries = sa.Table(
    "ledger_entries",
    metadata,
    sa.Column("entry_id", sa.String(64), primary_key=True),
    sa.Column("txn_id", sa.String(64), nullable=False),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("direction", sa.String(8), nullable=False),
    sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("team_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("agent_id", sa.String(64), nullable=False),
    sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
)

# D-004 event-ingest dead-letter sink (migration 0002). Unmappable events land here
# rather than being dropped. tenant_id is NULL for unknown-tenant rows (written via
# the privileged session, RLS-invisible to delta_app). INSERT-only at the grant layer.
ingest_dead_letter = sa.Table(
    "ingest_dead_letter",
    metadata,
    sa.Column("dlq_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=True),
    sa.Column("source_event_id", sa.String(64), nullable=True),
    sa.Column("event_type", sa.String(64), nullable=True),
    sa.Column("reason", sa.String(32), nullable=False),
    sa.Column("original_payload", postgresql.JSONB, nullable=False),
    sa.Column("attempt_count", sa.Integer, nullable=False),
    sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
)

# --- D-005 budget engine (migration 0003) -----------------------------------------
# The caps to evaluate. Mirrors delta.budget.BudgetConcept (the locked budget_limit
# shape): four stable IDs + scope + period + integer-cent / token limits.
budget_definitions = sa.Table(
    "budget_definitions",
    metadata,
    sa.Column("budget_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("scope", sa.String(8), nullable=False),
    sa.Column("team_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("agent_id", sa.String(64), nullable=False),
    sa.Column("period", sa.String(8), nullable=False),
    sa.Column("limit_tokens", sa.BigInteger, nullable=True),
    sa.Column("limit_cost_cents", sa.BigInteger, nullable=True),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("policy_id", sa.String(64), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

# Per (budget, period window) edge state for idempotent, edge-triggered publishing. The
# conditional transition UPDATE ... WHERE state='under' gates the publish so concurrent
# appends crossing the cap publish exactly once.
budget_enforcement_state = sa.Table(
    "budget_enforcement_state",
    metadata,
    sa.Column("state_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("budget_id", sa.String(64), nullable=False),
    sa.Column("period_bucket", sa.String(32), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("enforced_policy_version", sa.BigInteger, nullable=True),
    sa.Column("last_published_version", sa.BigInteger, nullable=False),
    sa.Column("last_warned_pct", sa.Integer, nullable=True),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# The durable enforcement DECISION + delivery status. The signed policy is committed
# here in the SAME transaction as the state flip, BEFORE any network call, so a decision
# is never lost. The 'failed' state is the dead-letter.
budget_publish_outbox = sa.Table(
    "budget_publish_outbox",
    metadata,
    sa.Column("outbox_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("budget_id", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(64), nullable=False),
    sa.Column("policy_version", sa.BigInteger, nullable=False),
    sa.Column("transition", sa.String(16), nullable=False),
    sa.Column("policy_payload", postgresql.JSONB, nullable=False),
    sa.Column("distribution_id", sa.String(64), nullable=True),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("attempts", sa.Integer, nullable=False),
    sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_error", sa.String(512), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

# --- D-006 kill-switch (migration 0004) -------------------------------------------
# Tenant-wide identity allow-list (opt-in). While a tenant has zero rows here, the
# unauthorized-agent trigger is inert for it (ADR-0006 §2 fork 2, §3.6).
agent_authorizations = sa.Table(
    "agent_authorizations",
    metadata,
    sa.Column("tenant_id", sa.String(64), primary_key=True),
    sa.Column("agent_id", sa.String(64), primary_key=True),
    sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
)

# Per (tenant, team, project, agent) edge state — the SAME granularity as Sentinel's
# BudgetScope.AGENT (exact team+project+agent match; no wildcard for budget policies).
# One row per scope ever observed to offend; no period bucket (unlike D-005, the
# kill-switch is not period-based).
kill_switch_state = sa.Table(
    "kill_switch_state",
    metadata,
    sa.Column("kill_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("team_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("agent_id", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(64), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("reason", sa.String(32), nullable=True),
    sa.Column("last_published_version", sa.BigInteger, nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# The durable kill/clear DECISION + delivery state (mirrors budget_publish_outbox
# exactly). Reuses delta.policy.sign + delta.budget_engine.publisher unchanged.
kill_switch_outbox = sa.Table(
    "kill_switch_outbox",
    metadata,
    sa.Column("outbox_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("kill_id", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(64), nullable=False),
    sa.Column("policy_version", sa.BigInteger, nullable=False),
    sa.Column("transition", sa.String(16), nullable=False),
    sa.Column("policy_payload", postgresql.JSONB, nullable=False),
    sa.Column("distribution_id", sa.String(64), nullable=True),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("attempts", sa.Integer, nullable=False),
    sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_error", sa.String(512), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)
