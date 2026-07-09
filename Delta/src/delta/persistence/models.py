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

# --- D-007 budget allocation admin (migration 0005) --------------------------------
# A proposed distribution of a tenant total across scope targets — the D-001
# `delta.allocation.Allocation` shape, made durable and given an approval workflow.
# Never auto-applied: `status` starts 'requested' and only an explicit admin decision
# moves it to 'approved' (materializing each target as a budget_definitions row via
# the existing D-005 create_budget seam) or 'rejected' (no side effects).
allocations = sa.Table(
    "allocations",
    metadata,
    sa.Column("allocation_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("total_minor_units", sa.BigInteger, nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("period", sa.String(8), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("requested_by", sa.String(128), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("decided_by", sa.String(128), nullable=True),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
)

# One row per AllocationTarget. `budget_id` is NULL until the target is materialized
# (set at approval time); it names the budget_definitions row this target became.
allocation_targets = sa.Table(
    "allocation_targets",
    metadata,
    sa.Column("target_id", sa.String(64), primary_key=True),
    sa.Column("allocation_id", sa.String(64), nullable=False),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("scope", sa.String(8), nullable=False),
    sa.Column("team_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("agent_id", sa.String(64), nullable=False),
    sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
    sa.Column("budget_id", sa.String(64), nullable=True),
)

# Plain append-only change-history log for allocation lifecycle transitions. NOT
# hash-chained (that tamper-evident layer is D-009, applied ecosystem-wide to Delta's
# financial workflows) — this is its un-hash-chained precursor, honestly scoped.
change_history = sa.Table(
    "change_history",
    metadata,
    sa.Column("history_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("entity_type", sa.String(32), nullable=False),
    sa.Column("entity_id", sa.String(64), nullable=False),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("actor", sa.String(128), nullable=False),
    sa.Column("note", sa.String(1024), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    # --- D-009 hash chain (migration 0006) ---------------------------------
    # sequence_number is the per-table monotonic chain-order key (a global
    # BIGSERIAL; a tenant's own rows read via RLS are still exactly ordered
    # relative to each other even though the sequence has gaps from other
    # tenants' rows). prev_hash/row_hash are never NULL once migration 0006
    # completes; see delta.persistence.audit_log for the hash algorithm.
    sa.Column("sequence_number", sa.BigInteger, nullable=False),
    sa.Column("prev_hash", sa.String(64), nullable=False),
    sa.Column("row_hash", sa.String(64), nullable=False),
)

# --- D-013 unified CRM (migration 0007) --------------------------------------------
# A deliberately scoped vertical slice, not full enterprise-CRM parity — see
# docs/adr/0013-delta-unified-crm.md §3 for the named deferrals. Four tables: a client
# record, its deal pipeline, its stakeholder roster, and its interaction history.
# "Relationship scoring" and stakeholder engagement are computed live from these rows
# (delta.crm.scoring/store) — nothing here stores a score.
clients = sa.Table(
    "clients",
    metadata,
    sa.Column("client_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("primary_contact_name", sa.String(256), nullable=True),
    sa.Column("primary_contact_email", sa.String(320), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# One row per pipeline opportunity for a client. `stage` starts 'lead'; 'won'/'lost'
# are terminal (enforced by delta.crm.service, mirroring D-007's allocation decision
# idempotency guard, not by a DB constraint — a future stage could still need to
# reopen a lost deal, which a hard DB CHECK would foreclose).
deals = sa.Table(
    "deals",
    metadata,
    sa.Column("deal_id", sa.String(64), primary_key=True),
    sa.Column("client_id", sa.String(64), nullable=False),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("stage", sa.String(16), nullable=False),
    sa.Column("value_minor_units", sa.BigInteger, nullable=True),
    sa.Column("currency", sa.String(3), nullable=True),
    sa.Column("expected_close_date", sa.DateTime(timezone=True), nullable=True),
    sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# Stakeholder roster per client (optionally scoped to one deal). Structured data
# entered explicitly, not free-text-extracted — see docs/adr/0013-delta-unified-crm.md
# Fork 3 for why NLP-style extraction is a named deferral, not a silent gap.
stakeholders = sa.Table(
    "stakeholders",
    metadata,
    sa.Column("stakeholder_id", sa.String(64), primary_key=True),
    sa.Column("client_id", sa.String(64), nullable=False),
    sa.Column("deal_id", sa.String(64), nullable=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("role", sa.String(16), nullable=False),
    sa.Column("email", sa.String(320), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# Client interaction history (calls/emails/meetings/notes). Append-only from the API's
# perspective (no update/delete route) — the log itself IS the interaction record.
# `stakeholder_id` is the "automated" half of stakeholder mapping (ADR-0013 Fork 3):
# tagging an interaction to a stakeholder lets engagement (interaction_count/
# last_interaction_at) be computed live by a plain GROUP BY, never by fragile
# name-matching or NLP-style extraction from `summary`.
interactions = sa.Table(
    "interactions",
    metadata,
    sa.Column("interaction_id", sa.String(64), primary_key=True),
    sa.Column("client_id", sa.String(64), nullable=False),
    sa.Column("deal_id", sa.String(64), nullable=True),
    sa.Column("stakeholder_id", sa.String(64), nullable=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("interaction_type", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("summary", sa.String(2048), nullable=False),
    sa.Column("created_by", sa.String(128), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

# --- D-014 ERP: asset register + vendor/purchase-order procurement (migration 0008) ---
# A deliberately scoped vertical slice of the roadmap's "real-time sync of supply
# chain, payroll, HR, and physical assets" — see docs/adr/0014-delta-erp-assets-procurement.md
# §3 for why payroll/HR are named deferrals (sensitive PII/compliance domains with no
# precedent anywhere in this codebase) and why "real-time SYNC" with external ERPs is
# D-019's job (this task builds the internal record-keeping those integrations would
# sync into, not the integrations themselves).
vendors = sa.Table(
    "vendors",
    metadata,
    sa.Column("vendor_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("contact_email", sa.String(320), nullable=True),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# Physical/software asset register. `status` moves forward only:
# active -> retired -> disposed (enforced by delta.erp.service, mirrors D-013's
# deal-stage terminality guard — not a DB CHECK, since the linear vocabulary could
# still grow without needing a migration).
assets = sa.Table(
    "assets",
    metadata,
    sa.Column("asset_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("category", sa.String(32), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("acquisition_cost_minor_units", sa.BigInteger, nullable=True),
    sa.Column("currency", sa.String(3), nullable=True),
    sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("assigned_team_id", sa.String(64), nullable=True),
    sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# A procurement commitment against a vendor, optionally tied to the asset it
# purchases. `status` starts 'requested'; only an explicit admin decision moves it to
# 'approved'/'rejected' (identical shape to D-007's allocations propose/decide
# workflow) — wired into D-009's hash-chained audit log on decision (a purchase
# commitment IS a financial event, unlike D-013's CRM edits).
purchase_orders = sa.Table(
    "purchase_orders",
    metadata,
    sa.Column("po_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("vendor_id", sa.String(64), nullable=False),
    sa.Column("asset_id", sa.String(64), nullable=True),
    sa.Column("description", sa.String(512), nullable=False),
    sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("requested_by", sa.String(128), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("decided_by", sa.String(128), nullable=True),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
)

# --- D-015 project management: sprints, tasks, dependency mapping (migration 0009) ---
# A deliberately scoped vertical slice of the roadmap's "sprint-velocity tracking,
# dependency mapping, execution-bottleneck prediction" — see
# docs/adr/0015-delta-pm-sprints-dependencies.md §3 for what's deferred (real-time
# updates, external issue-tracker integration, trained ML bottleneck prediction).
sprints = sa.Table(
    "sprints",
    metadata,
    sa.Column("sprint_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("start_date", sa.DateTime(timezone=True), nullable=False),
    sa.Column("end_date", sa.DateTime(timezone=True), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

# `sprint_id` is nullable — an unassigned task lives in the backlog. `story_points` is
# the velocity unit; `completed_at` is set exactly when `status` becomes 'done'.
# `team_id` (nullable, added by migration 0010/D-016) is an additive extension —
# mirrors migration 0006's own precedent of extending an earlier task's table
# (`change_history`) with new nullable columns. delta.pm's own code never reads or
# writes this column; only delta.capacity does.
tasks = sa.Table(
    "tasks",
    metadata,
    sa.Column("task_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("sprint_id", sa.String(64), nullable=True),
    sa.Column("title", sa.String(256), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("story_points", sa.Integer, nullable=True),
    sa.Column("assignee", sa.String(128), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("team_id", sa.String(64), nullable=True),
)

# A directed edge: `blocking_task_id` must complete before `blocked_task_id` can
# proceed. Cycle-freedom is enforced at the service layer (a graph traversal before
# insert), not by the database — see delta.pm.service._would_create_cycle.
task_dependencies = sa.Table(
    "task_dependencies",
    metadata,
    sa.Column("dependency_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("blocking_task_id", sa.String(64), nullable=False),
    sa.Column("blocked_task_id", sa.String(64), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

# --- D-016 team capacity management (migration 0010) ---
# `capacity_points_per_sprint` is an operator-declared, deterministic figure — not
# inferred from calendars, PTO, or working hours (Delta has no such data anywhere).
# See docs/adr/0016-delta-team-capacity-management.md §3 for what's deferred
# (individual-level capacity/PTO, burnout/wellbeing signals, automatic reassignment).
teams = sa.Table(
    "teams",
    metadata,
    sa.Column("team_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("capacity_points_per_sprint", sa.Integer, nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)
