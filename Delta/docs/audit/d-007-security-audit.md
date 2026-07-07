# D-007 Security Audit — Delta Budget Allocation Admin (API + console)

- **Date:** 2026-07-07
- **Scope:** `Delta/src/delta/allocation_admin/`, the `allocations`/`allocation_targets`/
  `change_history` additions in `Delta/src/delta/persistence/models.py`, migration
  `0005_allocation_admin.py`, and `Delta/tests/allocation_admin/`.
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Two Low findings, both fixed on this
  branch before merge (see below).

## Note on tooling

Semgrep's registry rulesets (`p/python`, plus the ones this repo's CI pulls) could not be
fetched in the audit environment (an egress proxy returned 403 to `semgrep.dev`, and per proxy
policy the auditor did not route around it). This pass is therefore **manual analysis only**; the
`delta-ci.yml` `quality` job's `semgrep scan --config=p/python --severity=ERROR` step runs for
real in CI, where the registry is reachable, and is the authority of record for SAST on this PR
(banked rule #4 — CI is authoritative, not a local proxy-limited approximation).

## What was actively tried and found sound

- **AuthN/AuthZ** — `require_admin` is a router-level dependency on all five `/v1/admin/*`
  routes (verified none skip it); constant-time `hmac.compare_digest`; fail-closed on missing
  header, wrong scheme, or empty token; settings resolution itself is fail-loud at app
  construction. `/health` is intentionally unauthenticated and returns only `{"status":"ok"}`.
  No bypass or timing leak found.
- **Tenant isolation** — every route opens `get_tenant_session(tenant_id)` (the `delta_app`
  NOBYPASSRLS role), so `decide_allocation`'s pre-check read is already RLS-confined to the
  caller-supplied tenant; a foreign allocation id returns `None` -> 404. The
  `record.tenant_id != decision.tenant_id` check in `service.decide_allocation` is redundant
  belt-and-suspenders on top of RLS, not the actual isolation boundary. The FK
  `(allocation_id, tenant_id)` + `uq_alloc_id_tenant` prevents an `allocation_targets` row from
  ever referencing another tenant's allocation.
- **Double-decision race** — the conditional `UPDATE ... WHERE status='requested'` is the real
  gate (not the initial existence read): under READ COMMITTED, a losing concurrent decision's
  `UPDATE` re-evaluates the post-lock row, matches zero rows, and the caller gets 409 *before*
  any `create_budget` call runs. No TOCTOU window between the read and the transition.
- **Money/reconciliation** — every amount routes through `Money`/`bounded_count` (rejects
  float, `bool`, negative, and >1e11 overflow); the shared `delta.allocation.Allocation` model
  enforces "targets sum to total, same currency" before any write; a mismatch is a 422, not a
  partial write.
- **Post-commit return-value correctness** — `decide_allocation` deliberately does NOT re-query
  the database after `session.commit()`. Verified this is correct, not a shortcut: the tenant GUC
  set by `get_tenant_session` is `is_local=true` and clears on commit, so a naive re-query in the
  session's next (autobegun) transaction would see zero rows under the RLS NULLIF predicate —
  silently wrong, not merely slow. The actual fix (already in the code, not something this audit
  had to add): reconstruct the returned view from the exact values this same transaction just
  wrote (`dataclasses.replace`), reached only after a successful commit, so the returned view
  cannot report state that was not actually persisted.
- **Injection** — every runtime query is SQLAlchemy Core parameter-bound (no f-string SQL from
  request input anywhere in `allocation_admin/`); every migration `op.execute` f-string
  interpolates only fixed module constants (schema/role/table names), never user input — the same
  pattern already ruff-`S608`-exempted for every prior Delta migration.
- **Grants/RLS** — `change_history` is `SELECT, INSERT` only at the grant layer (no `UPDATE`, no
  `DELETE`, no UPDATE policy) — immutable by grant, not merely by convention.
  `allocations`/`allocation_targets` are `SELECT, INSERT, UPDATE` (no `DELETE`), matching the
  D-005/D-006 mutable-but-append/update-only precedent. All three tables `ENABLE + FORCE` RLS with
  the identical strict fail-closed NULLIF predicate as D-003/D-005/D-006. No `session.begin()`
  double-wrap of the autobegun tenant session anywhere in the new code (the F-007/F-009/F-018 bug
  class). No secret is ever logged (config raises on the env var *name*, never its value; the
  catch-all handler returns a generic 500, never internals).

## Findings (both fixed on this branch)

| # | Severity | Location | Issue | Fix |
|---|---|---|---|---|
| 1 | Low | `allocation_admin/store.py` (`list_allocations`, `list_history`) | No pagination — `change_history` is append-only and grows without bound; `GET /v1/admin/history?tenant_id=...` with no entity filter (or `GET /v1/admin/allocations` on a long-lived, high-volume tenant) materializes every row into memory in one response. Not a cross-tenant leak (RLS-scoped, requires the admin bearer) — a memory/latency pressure issue from an already-authorized caller, not a data-exposure one. | Added `DEFAULT_LIST_LIMIT=100` / `MAX_LIST_LIMIT=500` with a server-side `_clamp_limit` applied inside `store.list_allocations`/`store.list_history` regardless of what the router passes through — the router exposes an optional `limit` query param, but the store layer is the actual enforcement boundary (`test_list_allocations_respects_limit`, `test_clamp_limit_bounds_to_max`, `test_clamp_limit_bounds_below_one`). |
| 2 | Low | `allocation_admin/schemas.py` (`requested_by`, `actor`, `note`) | These free-text fields were length-bounded but accepted any character, including newlines and terminal control sequences. No injection is possible inside this service (values are parameter-bound into SQL and JSON-encoded on output) — the risk is realized only downstream, if a future consumer (D-009's hash-chain export, a plaintext audit sink, or a terminal viewer) ever renders `change_history.actor`/`note` raw, which would let a forged newline impersonate a second audit-log line. | Added `_reject_control_chars` (rejects `\x00`-`\x1f`, `\x7f`) as a `field_validator` on `requested_by`, `actor`, and `note` — ordinary free text (names, sentences) is unaffected; only control characters are rejected (`test_requested_by_rejects_embedded_newline`, `test_actor_rejects_control_character`, `test_note_rejects_control_character`, `test_ordinary_actor_and_note_accepted`). |

## Threat model cross-reference

See `docs/adr/0007-delta-budget-allocation-ui.md` §5 for the full vectors-to-tests table this
audit validated against (cross-tenant isolation, unreconciled-allocation rejection,
double-decision race, propose-never-materializes, missing/wrong bearer, post-commit read
correctness, change-history immutability at the grant layer).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-007 surface listed under Scope above. It does not re-audit the
unchanged D-005 `create_budget` seam this task calls into (already audited at
`docs/audit/d-005-security-audit.md`), the unchanged `get_tenant_session`/RLS primitive itself
(D-003, `docs/audit/d-003-security-audit.md`), or the not-yet-built `Delta/frontend/` console
(tracked separately — a frontend-specific pass, including the BFF `bff.ts` allow-list/CSRF
behavior and a build-time token-absence-in-bundle check, is applicable to that surface once it
lands on this PR).
