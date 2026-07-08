# D-009 Security Audit — Immutable Hash-Chained Financial Audit Trails

- **Date:** 2026-07-08
- **Scope:** `Delta/src/delta/persistence/audit_log.py` (the hash-chain algorithm), migration
  `Delta/src/delta/persistence/migrations/versions/0006_audit_hash_chain.py`, and every wiring
  site: `Delta/src/delta/allocation_admin/service.py`, `.../router.py`, `.../schemas.py`,
  `Delta/src/delta/budget_engine/evaluator.py`, `Delta/src/delta/kill_switch/evaluator.py`,
  `Delta/src/delta/kill_switch/authorizations.py`, and the D-009 additions to `Delta/tests/`.
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per banked
  process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. One Medium finding, fixed on this branch
  before merge; one Low finding, fixed on this branch before merge.

## Note on tooling

Semgrep's registry rulesets (`p/python`, `p/security-audit`, `p/secrets`) could not be fetched in
the audit environment (the egress proxy denies `CONNECT` to `semgrep.dev`; confirmed via the proxy
status endpoint, no offline rule cache exists). Semgrep's local-rule engine ran and flagged nothing
on the changed files; the findings below come from manual adversarial review of the actual code
paths, per the same accepted pattern as `docs/audit/d-007-security-audit.md` and
`docs/audit/d-008-security-audit.md`'s identical tooling notes. `delta-ci.yml`'s `quality` job runs
the real Semgrep scan with registry access in CI, which is the authority of record for SAST on this
PR (banked rule #4 — CI is authoritative).

## What was actively tried and found sound

- **Cross-tenant isolation** — `delta_app` remains `NOBYPASSRLS`; `change_history` keeps RLS
  `FORCE` + the strict fail-closed `NULLIF` predicate unchanged from D-007. Both `append_history`'s
  write path and `verify_chain`'s read path run on the tenant-scoped session, so a caller cannot
  append to or verify another tenant's chain regardless of what `tenant_id` argument the Python
  call itself is given — RLS enforces it at the row level independent of the application code's own
  bookkeeping. Verified by `test_cross_tenant_chain_is_isolated` (DB) and
  `test_audit_verify_is_isolated_per_tenant` (HTTP).
- **Grants** — `delta_app` holds exactly `SELECT, INSERT` on `change_history` (no `UPDATE`,
  `DELETE`, or `TRUNCATE`); the new `change_history_sequence_number_seq` grants only `USAGE,
  SELECT` to `delta_app`, and the migration's `downgrade()` symmetrically `REVOKE`s it before
  dropping the sequence — no stale grant survives a rollback.
- **Append-only, both layers** — confirmed the grant-layer denial (`delta_app` has no UPDATE/DELETE
  grant at all) and the trigger-layer denial (`deny_ledger_modification()`, reused unchanged from
  D-003, fires `BEFORE UPDATE`/`BEFORE DELETE` regardless of role — triggers are not skipped by
  `BYPASSRLS` the way RLS itself is) are two genuinely independent controls, each exercised by its
  own test (`test_deny_{update,delete}_denied_by_grant_for_app_role` vs.
  `test_deny_{update,delete}_trigger_blocks_modification`).
- **Concurrency** — `pg_advisory_xact_lock(hashtext(tenant_id))` correctly spans the tip-read and
  the insert (both inside the same lock hold, released at commit), so two concurrent appends for
  the same tenant cannot both read the same tip and fork the chain. Verified with 8 concurrent
  appends in `test_concurrent_appends_produce_an_unbroken_chain`.
- **Canonical-JSON injectivity** — `sort_keys=True` + standard JSON string escaping means the
  field/value boundary is never ambiguous; two semantically different rows cannot produce the same
  canonical JSON (and thus the same hash) by construction. Forged rows (self-consistent-but-wrong
  `row_hash`, and self-consistent-but-wrong `prev_hash`) are both caught by `verify_chain`, proven
  via raw INSERTs that bypass `append_history` entirely.
- **`get_tenant_session` usage** — every D-009 call site (`append_history`/`verify_chain` calls in
  `service.py`, `evaluator.py`, `authorizations.py`) runs on a session the caller already opened;
  none of them wrap it in a second `session.begin()` (the F-007/F-009/F-018 bug class).
- **Reconciliation-failure audit ordering** — `create_allocation_request`'s `except ValidationError`
  branch calls `append_history` and `await session.commit()` BEFORE re-raising
  `AllocationReconciliationError` — the audit row is durably committed, not lost to whatever the
  caller's exception-handling does afterward.
- **`policy.schema.json`** — untouched by every D-009 commit (verified by grep across the full
  diff); this is a persistence-track feature with no legitimate reason to touch it, and it doesn't.
- **Money/floats** — not directly applicable to this feature (audit rows carry no monetary amount),
  and nothing in the diff introduces a `float` anywhere in a money-adjacent path.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Medium | `persistence/audit_log.py` `_row_hash_data`; migration `0006_audit_hash_chain.py` backfill loop | The migration's backfill hashes `created_at.isoformat()` under the SYNC driver, which returns `TIMESTAMPTZ` in the connection's session `TimeZone` (not necessarily UTC), while the live append/verify path runs on asyncpg, which always returns `TIMESTAMPTZ` as UTC. `compute_row_hash` binds the raw isoformat string into the SHA-256, so the SAME instant produces two different strings — and two different hashes — depending on which driver read it. On a deployment where the migration connection's session `TimeZone` isn't UTC, every backfilled row (real pre-existing D-007 data) would permanently fail `verify_chain` with a false "row_hash mismatch," defeating the feature's headline guarantee on exactly the data it exists to protect. Untested by the original suite (fresh/empty-table and fixed-UTC-constant fixtures never exercised this path). | **Fixed.** `_row_hash_data` now normalizes `created_at.astimezone(timezone.utc)` before `.isoformat()` — the single function both `append_history` and `verify_chain` call, so write and verify now always agree regardless of the reading driver's session timezone. The migration's own backfill dict construction (which does not go through `_row_hash_data`) got the identical normalization. New regression test `test_created_at_hash_is_timezone_representation_invariant` constructs two Python `datetime` objects for the exact same instant with different `tzinfo` offsets and asserts `compute_row_hash` agrees on both — directly proving the fix, independent of any DB driver. |
| 2 | Low | `persistence/audit_log.py` `_canonical_json` | No type coercion on the hashed fields (`entity_id`, `actor`, `action`, etc.). Every current call site already passes `str`, so this was latent, not presently exploitable — but if a future caller passed e.g. `entity_id=5` (an `int`), `append_history` would store `"5"` into the `String(64)` column but hash the JSON number `5` (unquoted); `verify_chain` always reads back a `str` from the DB and hashes `"5"` (quoted) — a permanent, unrecoverable false mismatch on that row from a type mismatch, not a real tamper. | **Fixed.** `_canonical_json` now `str()`-coerces every hashed field (`note` included, when present). A no-op for every existing caller (all already pass `str`), and closes the class of bug for any future caller. |

## Threat model cross-reference

See `docs/adr/0009-delta-financial-audit-chain.md` §5 for the full vectors-to-tests table this
audit validated against (forged `row_hash`, forged `prev_hash` link, grant-layer vs. trigger-layer
append-only enforcement, concurrent-append serialization, cross-tenant isolation, unaudited
reconciliation failures, unattributed automated decisions, and the sequence-grant gap the full test
suite caught during development).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-009 surface listed under Scope above. It does not re-audit the
unchanged D-003 `deny_ledger_modification()` trigger function itself (already audited at
`docs/audit/d-003-security-audit.md`, reused here unchanged rather than re-implemented), the
unchanged D-007 `require_admin`/RLS/`change_history` grant-layer primitives this task upgrades
(already audited at `docs/audit/d-007-security-audit.md`), or the unchanged D-005/D-006 enforcement
decision logic this task only adds an audit-append call to, not modifies (already audited at
`docs/audit/d-005-security-audit.md` and `docs/audit/d-006-security-audit.md`). Per ADR-0009 §6, a
hash chain proves internal consistency and catches tampering of EXISTING rows; it does not prove
the chain wasn't entirely regenerated by someone with full database access (no external anchoring
is built — the same limitation Sentinel's own F-003 audit log has).
