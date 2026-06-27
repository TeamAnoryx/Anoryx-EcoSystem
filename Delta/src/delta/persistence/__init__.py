"""Delta ledger persistence (D-003).

Makes the D-001 financial domain model REAL as durable, append-only, double-entry
Postgres persistence: the database (not the application) enforces the balanced-entry
invariant, RLS isolates tenants, and entries are immutable (reversal = a new
compensating transaction). See ``Delta/docs/adr/0003-delta-double-entry-ledger.md``.

Honesty boundary: this package is ledger persistence + read primitives ONLY. Event
ingest is D-004, the budget engine is D-005, dashboards are D-008, and the
hash-chained financial audit trail is D-009 (append-only is its foundation, not its
hash-chain).
"""

from __future__ import annotations

# The GUC that carries the tenant context into RLS predicates (shared name with the
# Sentinel pattern so the isolation boundary is identical in shape).
TENANT_GUC: str = "app.current_tenant_id"

# The non-privileged application login role (NOBYPASSRLS). Any session connecting as
# this role is governed by RLS and cannot perform UPDATE/DELETE on the ledger.
DELTA_APP_ROLE: str = "delta_app"

# The Postgres schema that houses every ledger object (Fork 4 — separate schema in a
# shared-or-own Postgres). All DDL is schema-qualified into here.
DELTA_SCHEMA: str = "delta"
