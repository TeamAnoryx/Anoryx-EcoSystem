# ADR-0009 — Immutable Hash-Chained Audit Trails for Delta's Financial Workflows

- **Status:** Proposed (awaiting human approval — STEP 1 gate)
- **Date:** 2026-07-08
- **Task:** D-009 (Immutable audit trails for automated financial workflows) · Builder: persistence
- **Builds on:** D-003 (`change_history`'s ancestor table conventions, `deny_ledger_modification()`
  trigger), D-007 (`allocations.change_history` — the plain, un-hash-chained precursor this task
  upgrades), D-005 (budget-engine enforcement decisions), D-006 (kill-switch kill/clear decisions)
- **Mirrors:** Anoryx-Sentinel F-003 (`Anoryx-Sentinel/src/persistence/hash_chain.py` +
  `audit_log_repository.py`) — the ecosystem's canonical hash-chain design, applied here to Delta's
  financial actions per the roadmap line: *"the Sentinel F-003 audit pattern applied to Delta's
  financial actions."*
- **Delta ADR head is 0008; this is 0009.**

---

## 1. Context

D-007 (ADR-0007 fork 5) deliberately shipped `change_history` as append-only-BY-GRANT only — no
hash chain — and named the gap explicitly: *"the tamper-evident, hash-chained financial-workflow
audit trail is a separate, later, ecosystem-wide task — D-009."* This ADR is that task: it upgrades
the existing `change_history` table (rather than building a parallel one) into a cryptographically
linked, tamper-evident log, and wires every automated financial workflow the roadmap names —
allocation lifecycle (D-007), budget-engine enforcement (D-005), kill-switch kill/clear (D-006),
and allocation-reconciliation failures — to append to it.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — per-tenant chains, not Sentinel's global chain** | Each `tenant_id` has its own hash chain (`prev_hash`/`row_hash` link only within that tenant's rows, ordered by a shared `sequence_number`). Sentinel's chain is global across all tenants. | Sentinel's audit log correlates cross-tenant security events by design (its own threat model needs a single ordered timeline). Every other Delta financial table is already RLS-tenant-siloed; a per-tenant chain lets an audit append happen in the SAME transaction as the business write it records — the append and the write commit or roll back together, a strictly stronger guarantee than Sentinel's own decoupled privileged-session audit write (see fork 2). Verifying one tenant's chain also never requires touching another tenant's rows, which mirrors how every other Delta read already works under RLS. |
| **2 — audit append is same-transaction, not privileged-session-deferred** | `append_history` runs on the SAME `AsyncSession` the caller is already using for the business write (`delta_app`, tenant-scoped, RLS-enforced), in the SAME transaction. It does not commit itself — the caller's own `session.commit()` covers both. | Sentinel's F-003 writes happen in a separate, later, privileged-session transaction (`sentinel_app` itself cannot even INSERT — only SELECT). That design exists because Sentinel's chain is global and needs privileged-session serialization. Delta's per-tenant chain has no such need: `delta_app` IS granted INSERT (scoped by RLS to its own tenant, same as every other Delta write), so the append can — and should — live in the same atomic unit as the write it documents. This closes a class of bug Sentinel's design structurally cannot close: "the business write committed but its audit row didn't" is impossible here, not just unlikely. |
| **3 — reuse `change_history`, don't fork a new table** | Migration 0006 ALTERs the existing D-007 `change_history` table (adds `sequence_number`/`prev_hash`/`row_hash`, backfills, locks down) instead of creating a second audit table. | ADR-0007 fork 5 named this exact upgrade path: *"the change-history log gives D-009 a ready-made table to extend with a hash chain rather than retrofitting one from nothing."* A parallel table would duplicate every row D-007 already writes and fork the read API (`GET /v1/admin/history`) that already serves it. |
| **4 — hash recipe mirrors Sentinel byte-for-byte in shape, diverges only in the domain string** | `GENESIS_HASH = SHA256("anoryx-delta:financial-audit:genesis:v1")`; `row_hash = SHA256(canonical_json({tenant_id, entity_type, entity_id, action, actor, created_at, prev_hash, [note if not None]}))`; canonical JSON = `json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=False)`. | Reusing Sentinel's exact canonicalization rules (sorted keys, no whitespace, opt-in-when-present optional fields) means a future engineer who has read Sentinel's `hash_chain.py` can read Delta's `audit_log.py` with zero new mental model — only the field set and the domain-separated genesis string differ, both necessarily (Delta's rows have no `payload`/no KMS envelope encryption — see §6). |
| **5 — no envelope encryption on the audit row itself** | Unlike nothing in Sentinel's F-003 either, actually — confirmed by research: Sentinel's audit table has NO KMS/envelope encryption on its rows. Delta's chain follows the same precedent: plaintext `action`/`actor`/`note` fields, hashed but not encrypted. | The hash chain's job is tamper-EVIDENCE, not confidentiality. Delta's `change_history` rows already carry no more sensitive data than D-007 shipped (actor names, free-text notes, entity references) — RLS is the confidentiality control, same as every other Delta table. Adding envelope encryption Sentinel itself doesn't have would be scope creep past what D-009 or F-003 actually deliver. |
| **6 — concurrency via a per-tenant advisory lock, not `SELECT ... FOR UPDATE`** | `append_history` takes `pg_advisory_xact_lock(hashtext(tenant_id))` before reading the tip and inserting. Sentinel uses one GLOBAL advisory-lock constant; Delta scopes the lock key to the tenant via `hashtext()`. | A single global lock constant (Sentinel's choice) would serialize EVERY Delta tenant's appends through one lock, which is unacceptable given Delta's own D-005/D-006 already run concurrent per-tenant enforcement paths. `hashtext(tenant_id)` gives each tenant its own (near-certainly-unique) lock key; two tenants can append concurrently, while two appends for the SAME tenant correctly serialize the tip-read -> insert critical section. A `SELECT ... FOR UPDATE` on the tip row was considered and rejected: it requires a row to lock (fails on a tenant's very first append, which has no prior row), where the advisory lock has no such bootstrap problem. |
| **7 — append-only enforced at TWO layers, reusing D-003's existing trigger function** | `delta_app` has no UPDATE/DELETE grant on `change_history` (unchanged from D-007's grant-layer guard) AND two new triggers (`trg_change_history_deny_update`/`_deny_delete`) call the SAME `delta.deny_ledger_modification()` function migration 0001 defined for the D-003 ledger's own append-only guard. | Dual-layer defense: the grant layer stops `delta_app` (the only role application code runs as); the trigger layer stops even the privileged/owner role (used for migrations and admin work), which DOES hold UPDATE/DELETE rights at the grant level. Reusing `deny_ledger_modification()` instead of writing a near-duplicate function avoids two independently-maintained "you can't touch this table" implementations that could silently drift apart. |
| **8 — tamper detection is a read-time cryptographic walk, not a write-time-only guarantee** | New `verify_chain(session, tenant_id)` walks a tenant's rows in `sequence_number` order, recomputes every `row_hash`, and reports the first mismatch. Exposed at `GET /v1/admin/audit/verify`. | The append-only triggers only stop UPDATE/DELETE on an EXISTING row — they cannot stop a forged INSERT from a compromised write path that bypasses `append_history` entirely (e.g., a direct SQL client with the `delta_app` credential). `verify_chain` is the actual backstop for that case: a forged row's `row_hash` won't match its own recomputed hash, or its `prev_hash` won't match the real prior row's `row_hash` — either way, `verify_chain` catches it on the next read, without needing to trust the write path that produced it. |
| **9 — reconciliation FAILURES are audited too, not just successful writes** | `allocation_admin.service.create_allocation_request` now writes an `entity_type="allocation_reconciliation", action="rejected"` history row (with the validation error truncated into `note`) BEFORE raising `AllocationReconciliationError`, in the same transaction. | The roadmap line names "reconciliations" as one of the three financial-workflow classes to audit, alongside allocations and enforcement actions. A rejected/failed reconciliation is itself a financial-integrity-relevant event (someone attempted to propose an allocation that didn't sum to its total) — auditing only the successes would silently drop half the story. |
| **10 — automated decisions are attributed to reserved system-actor slugs, not left blank** | `budget_engine.evaluator._enqueue` writes `actor="budget-engine"`; `kill_switch.evaluator._kill` and `kill_switch.authorizations._clear_scope` write `actor="kill-switch"` — reserved slugs, never a real operator identity, since no human is behind these decisions. | Mirrors Sentinel's own reserved-principal-slug convention (e.g. `admin-console`). Leaving `actor` NULL or empty for automated decisions would look like a data-quality bug rather than the honest fact that no operator triggered this transition; a named system actor is queryable and self-documenting in `list_history`/`verify_chain` output. |

## 3. Architecture

### 3.1 `Delta/src/delta/persistence/audit_log.py` — single source of truth

```
GENESIS_HASH          module-level constant, computed once at import
compute_row_hash()    canonical-JSON SHA-256; requires prev_hash + created_at
append_history()      advisory lock -> tip read -> hash -> INSERT .returning(sequence_number);
                       does NOT commit (caller's transaction, per fork 2)
list_history()         unchanged D-007 read semantics, now returns hash-chain fields too
verify_chain()          walks one tenant's chain, recomputes every hash, reports first mismatch
```

`allocation_admin/store.py`'s D-007 `record_history`/`list_history` functions are REMOVED (not
deprecated-in-place) — every caller now imports directly from `persistence/audit_log.py`, which is
the single implementation the migration's backfill step also imports (fork 3's "one table" and
fork 4's "one algorithm" would both be undermined by leaving a second copy behind).

### 3.2 Migration 0006 — upgrade, not replace

Adds `sequence_number`/`prev_hash`/`row_hash` as nullable columns first, backfills
`sequence_number` deterministically via `ROW_NUMBER() OVER (ORDER BY created_at, history_id)`
(NOT physical row order, which Postgres does not guarantee), creates the BIGSERIAL-equivalent
sequence for future inserts (with the `GRANT USAGE, SELECT ON SEQUENCE ... TO delta_app` that
`nextval()` requires — a table-level `GRANT INSERT` alone does not cover it, the exact gap that
broke every enforcement/allocation test on first run and was caught by the full suite, not the
migration in isolation), backfills the hash chain per tenant using the SAME `compute_row_hash`
a live `append_history` call uses, then locks everything down with NOT NULL, uniqueness, length
CHECK constraints, and the two append-only triggers. Safe on both an empty table (fresh CI/local)
and a table carrying real D-007 production rows.

### 3.3 Wiring — every automated financial workflow the roadmap names

| Workflow | Call site | `entity_type` | `action`(s) |
|---|---|---|---|
| Allocation lifecycle | `allocation_admin/service.py` | `allocation` | `requested`, `approved`, `rejected` |
| Allocation reconciliation failure | `allocation_admin/service.py` (fork 9) | `allocation_reconciliation` | `rejected` |
| Budget enforcement | `budget_engine/evaluator.py::_enqueue` | `budget_enforcement` | `enforce`, `refresh` |
| Kill-switch kill | `kill_switch/evaluator.py::_kill` | `kill_switch_enforcement` | `kill` |
| Kill-switch clear | `kill_switch/authorizations.py::_clear_scope` | `kill_switch_enforcement` | `clear` |

Every call site appends in the SAME transaction as its outbox/state write (fork 2) — a rollback of
the business decision also rolls back its audit row; there is no window where one commits without
the other.

### 3.4 New endpoint

`GET /v1/admin/audit/verify?tenant_id=...` (same `require_admin` bearer + per-tenant session as
every other D-007 route) runs `verify_chain` and returns `{is_valid, rows_checked,
first_mismatch_sequence, error_detail}`.

## 4. Tenant isolation

`verify_chain` and `list_history` both run on the caller's tenant-scoped `delta_app` session — RLS
confines the walk to exactly the rows an operator is authorized to see, which is also exactly the
chain's own scope (per-tenant, fork 1). No privileged session is needed for verification, unlike
Sentinel's global-chain design, which requires a privileged read to see the full cross-tenant
picture.

## 5. Threat model (vectors -> tests)

| # | Vector | Mitigation | Test |
|---|---|---|---|
| 1 | A compromised write path forges an INSERT with a self-inconsistent `row_hash` | `verify_chain` recomputes every row's hash from its own content and flags a mismatch | `test_verify_chain_detects_forged_row_hash` |
| 2 | A forged row claims a fabricated `prev_hash` (internally self-consistent, but doesn't link to the real prior tip) | `verify_chain`'s link check compares each row's `prev_hash` against the PRECEDING row's actual stored `row_hash`, not just recomputing the forged row's own hash | `test_verify_chain_detects_broken_prev_hash_link` |
| 3 | Application-role (`delta_app`) UPDATE/DELETE on an existing row | No UPDATE/DELETE grant at all — Postgres denies before any trigger runs | `test_deny_update_denied_by_grant_for_app_role`, `test_deny_delete_denied_by_grant_for_app_role` |
| 4 | Privileged/owner-role UPDATE/DELETE (bypasses the grant-layer check above) | `deny_ledger_modification()` trigger fires regardless of role/privilege — triggers, unlike RLS, are not skipped by `BYPASSRLS` | `test_deny_update_trigger_blocks_modification`, `test_deny_delete_trigger_blocks_deletion` |
| 5 | Two concurrent appends for the SAME tenant race the tip-read -> insert critical section, producing a fork `verify_chain` would need to catch | `pg_advisory_xact_lock(hashtext(tenant_id))` serializes the critical section per tenant before either racer reads the tip | `test_concurrent_appends_produce_an_unbroken_chain` (8 concurrent appends, chain verifies clean) |
| 6 | Cross-tenant chain visibility/interference | RLS FORCE on `change_history` (unchanged from D-007) confines both appends and `verify_chain` reads to the caller's own tenant | `test_cross_tenant_chain_is_isolated`, `test_audit_verify_is_isolated_per_tenant` (HTTP) |
| 7 | A reconciliation failure is silently unaudited (only successes tracked) | `create_allocation_request` writes the `allocation_reconciliation`/`rejected` row BEFORE raising, same transaction | `test_unreconciled_targets_rejected` |
| 8 | An automated enforcement decision (no human operator) is left with an ambiguous/blank actor | Reserved system-actor slugs (`budget-engine`, `kill-switch`) attributed at every automated call site | `test_over_cap_publishes_exactly_once`, `test_authorize_clears_all_scopes_for_agent` (actor assertions) |
| 9 | `nextval()` on the new sequence silently fails for `delta_app` in production despite tests passing against a role that already had broader grants | Explicit `GRANT USAGE, SELECT ON SEQUENCE ... TO delta_app` in the migration, verified by running the FULL existing 453+-test suite (not just new D-009 tests) fresh, which is exactly how this bug was originally caught | Full suite run (475 tests) on a fresh migrated DB |
| 10 | A legitimately migrated (backfilled) row permanently fails `verify_chain` due to timestamp representation divergence between the migration's sync-driver connection (returns `TIMESTAMPTZ` in the session's own `TimeZone`) and the live asyncpg path (always returns UTC) — a false "tampered" positive on real data, not a real tamper (found in independent security review) | `_row_hash_data` (called by both `append_history` and `verify_chain`) and the migration's backfill both normalize `created_at.astimezone(timezone.utc)` before hashing, so write/backfill and verify always agree regardless of which driver produced the Python `datetime` | `test_created_at_hash_is_timezone_representation_invariant` |

## 6. Honesty boundary (what D-009 is NOT)

- **Not** a global cross-tenant audit timeline — each tenant's chain is independently verifiable and
  independently forgeable-from-genesis by anyone who could forge an entire tenant's worth of rows
  from scratch (the same limitation Sentinel's own hash chain has: a hash chain proves internal
  consistency and detects tampering of EXISTING rows, it does not prove the chain wasn't entirely
  regenerated by someone with full database access — that requires external anchoring, e.g.
  periodic hash publication to a separate system, which neither Sentinel's F-003 nor this task
  builds).
- **Not** encrypted at rest beyond whatever Postgres-level encryption the deployment already has —
  see fork 5; this mirrors Sentinel's own audit table, which also carries no envelope encryption.
- **Not** a real-time tamper ALERT — `verify_chain` is a pull-based check (an operator or a
  scheduled job must call it); there is no trigger-driven push notification on detected tampering.
  Wiring `GET /v1/admin/audit/verify` into a monitoring/alerting pipeline is future work, not part
  of this task's scope.
- **Not** a general append-only-log framework — the hash recipe, table shape, and trigger reuse are
  specific to `change_history`; a future Delta table needing the same guarantee would need its own
  migration and its own advisory-lock key, following this ADR as a template rather than a shared
  library (no such second table exists yet to generalize for).

## 7. Consequences

- **Positive:** every automated financial decision the roadmap names (allocations, enforcement
  actions, reconciliations) is now cryptographically tamper-evident, verifiable per-tenant without
  a privileged session, and the D-007 `change_history` table gains this guarantee without a second
  parallel table or read API. The per-tenant, same-transaction design is a strictly stronger
  atomicity guarantee than Sentinel's own F-003 (no window where a business write commits without
  its audit row).
- **Negative / accepted:** per-tenant chains mean there is no single global ordering across all of
  Delta's tenants the way Sentinel's chain provides for its own cross-tenant security-event
  correlation need — Delta doesn't have that need today (§6), but if a future task does, it would
  require a second, differently-scoped chain, not a trivial extension of this one. `verify_chain`
  is pull-based, not push-alerted (§6).
