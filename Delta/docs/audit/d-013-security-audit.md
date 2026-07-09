# D-013 Security Audit — Unified CRM

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/crm/` (the entire new package), `Delta/src/delta/persistence/
  migrations/versions/0007_unified_crm.py` (new tables, RLS, grants), the additive-only
  changes to `Delta/src/delta/identifiers.py` and `Delta/src/delta/persistence/models.py`,
  the one new router mount in `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/crm/`,
  the new frontend surface (`Delta/frontend/src/app/(admin)/crm/`,
  `Delta/frontend/src/components/crm/`, and the additive changes to `types.ts`/
  `admin-client.ts`/`bff.ts`/`app-nav.tsx`), and `Delta/docs/adr/0013-delta-unified-crm.md`
  (the design record, cross-checked against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Two Low findings; both fixed on
  this branch before merge.

## Note on tooling

Semgrep's registry could not be fetched in the audit environment (the egress proxy denies
`CONNECT` to `semgrep.dev` — the same known limitation recorded in every prior audit this
session; see `docs/audit/d-012-security-audit.md`). This pass is manual dataflow analysis,
tracing every claim in the ADR back to the actual source, per the same accepted precedent.
`delta-ci.yml`'s `quality` job's Semgrep step runs for real in CI (registry reachable there)
and remains the authority of record for SAST on this PR.

## What was actively tried and found sound

- **Cross-tenant isolation.** Every FK across all four new tables is a genuine composite
  `(entity_id, tenant_id)` pair, each backed by a matching `UniqueConstraint` on the
  referenced table — structurally impossible for a deal/stakeholder/interaction to
  reference another tenant's parent row. RLS is `FORCE`d on every table with the same
  fail-closed `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')`
  predicate as every prior Delta migration. Grants are SELECT/INSERT/UPDATE on the three
  mutable tables, SELECT/INSERT ONLY on `interactions` (no table anywhere gets DELETE).
  Verified by `test_cross_tenant_isolation_clients_invisible_to_other_tenant`,
  `test_cross_tenant_client_list_isolated_over_http`.
- **Cross-CLIENT scoping within the same tenant.** `service._check_deal_scope`/
  `_check_stakeholder_scope` are wired on EVERY mutation that accepts a foreign id —
  `create_interaction` (both `deal_id` and `stakeholder_id`) and `create_stakeholder`
  (`deal_id`) — not just some of them. An FK alone only proves same-TENANT; these checks
  independently prove same-CLIENT. Verified by
  `test_interaction_tagged_to_deal_from_another_client_rejected`,
  `test_stakeholder_from_another_client_rejected_on_interaction`,
  `test_deal_scope_mismatch_returns_422`.
- **Deal-stage terminality.** `try_transition_deal_stage` is a single conditional
  `UPDATE ... WHERE stage NOT IN ('won','lost')` gated on `rowcount == 1` — race-safe
  under concurrent double-transition, the same shape as D-007's `try_decide_allocation`.
  `create_deal` unconditionally starts a new deal at `stage="lead"`; no other code path
  writes `stage`. Verified by
  `test_deal_stage_transition_succeeds_once_then_blocked_when_terminal`.
- **No reused-session-across-two-commits RLS footgun in production code.** Every router
  handler opens exactly one `get_tenant_session` per request; `service.py`'s mutating
  functions each commit exactly once, and no code path reads or writes on a session after
  a commit without re-entering `get_tenant_session`. (This exact bug pattern DID appear
  transiently while the implementer was first drafting `tests/crm/test_service_db.py` —
  confirmed fixed in the final test file, and confirmed absent from all production code.)
- **Resource amplification.** Stakeholder engagement (`interaction_count`/
  `last_interaction_at`) is one `LEFT JOIN ... GROUP BY` query per client request, never
  one query per stakeholder. Relationship-score inputs
  (`get_client_engagement_summary`) are two small aggregate queries (`COUNT ... FILTER` +
  `MAX`, and a separate deal-stage `COUNT`), never a scan of every interaction/deal row
  into Python. `get_client_detail` issues a small, constant number of queries (~6)
  regardless of row counts. Verified by
  `test_stakeholder_engagement_computed_via_interaction_join`; code review confirmed no
  N+1 loop anywhere in `delta/crm/store.py`.
- **Input validation.** Every free-text field (`name`, `summary`, `actor`, `created_by`)
  rejects control characters via `_reject_control_chars`; every caller-supplied timestamp
  goes through `require_aware_utc`; `extra="forbid"` on every schema rejects unexpected
  fields; deal value is bounded `[0, MAX_DEAL_VALUE_MINOR_UNITS]` at the Pydantic layer.
  Verified by the full `test_schemas.py` suite.
- **Auth.** `require_admin` (D-007's unmodified break-glass bearer dependency) is a
  router-level `dependencies=[Depends(require_admin)]` covering all 11 CRM routes — no
  per-route opt-out exists anywhere in `router.py`. Verified by
  `test_clients_endpoint_401_without_bearer`.
- **Money/float discipline.** `value_minor_units` is an `int` end-to-end on the backend;
  the frontend's `AddDealForm` converts a caller-typed dollar string to integer minor
  units via `Math.round(Number(valueDollars) * 100)`, never sending a float to the API.
  The only `float` anywhere in `delta.crm` is the informational `RelationshipScoreView.score`
  (bounded `[0, 100]`, provably so for all inputs since every component is a non-negative
  step function summing to at most 100) — never read by `budget_engine`, the ledger, or
  any enforcement/forecast path. Confirmed via grep: no `budget_engine`/`ledger` import
  anywhere under `delta/crm/`.
- **SQL injection.** Every query in `delta/crm/store.py` is a parameterized SQLAlchemy
  Core statement (`insert`/`select`/`update` against `Table` objects) — no raw
  string-interpolated SQL anywhere in the package.
- **Frontend token isolation.** `admin-client.ts` remains `server-only`; every new CRM
  client component (`add-deal-form.tsx`, etc.) calls a `"use server"` Server Action in
  `crm/actions.ts`, never `admin-client.ts` directly — the admin bearer token cannot reach
  the browser. `bff.ts`'s addition of `"crm"` to `ALLOWED_ROOTS` is guarded by the same
  pre-existing segment-traversal filter and fail-closed unauthenticated check as every
  other root; no new path-traversal or SSRF surface was introduced.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `crm/service.py` (`create_deal`) | ADR-0013 §4 claimed a deal's `value_minor_units`/`currency` "always travel together, never a currency-without-a-value or value-without-a-currency row." The shipped code only enforced ONE direction: `currency = req.currency if req.value_minor_units is not None else None`. Because `DealCreateRequest.currency` is typed `Currency \| None = DEFAULT_CURRENCY`, a caller could explicitly POST `{"value_minor_units": 1000, "currency": null}` and the service would persist a value-WITHOUT-currency row — the exact state the ADR claimed was impossible. No budget/ledger impact (CRM deal value never feeds any enforcement path), so this was a data-integrity/ADR-accuracy defect, not a tenant-isolation or auth break. | **Fixed.** `create_deal` now defaults a missing currency to `DEFAULT_CURRENCY` whenever a value is present: `currency = (req.currency or DEFAULT_CURRENCY) if req.value_minor_units is not None else None`. A new DB `CHECK ((value_minor_units IS NULL) = (currency IS NULL))` constraint (migration 0007) backs this as a second, independent layer that holds even if a future code path bypasses the service layer. Regression tests added: `test_create_deal_with_value_defaults_currency_when_null` (service-layer), `test_deal_value_without_currency_rejected_by_db_check` (DB-layer, calls `store.create_deal` directly to prove the CHECK constraint itself rejects the mismatched row). ADR-0013 §4 updated to describe both the fix and the DB-level backstop. |
| 2 | Low | `crm/schemas.py` (`StakeholderView` docstring) | The docstring claimed stakeholder engagement is "computed live from `interactions` by name" and that `last_interaction_at` is None "when the stakeholder's NAME has no matching interaction row" — contradicting both the actual (correct) implementation, which joins on `stakeholder_id` + `tenant_id`, and ADR-0013 Fork 3's own explicit claim that engagement is "never matched by fragile name-matching." No runtime exploit — the code was already correct — but a docstring asserting a weaker (name-based) matching scheme is exactly the kind of claim a future maintainer could mistake for intended behavior and rely on incorrectly. | **Fixed.** Docstring corrected to state engagement is matched by the explicit `stakeholder_id` tag on an interaction, never by name, never NLP-extracted. |

## Threat model cross-reference

See `docs/adr/0013-delta-unified-crm.md` §4 for the full vectors-to-mitigations-to-tests
table this audit validated against (cross-tenant isolation, cross-client scope checks,
deal-stage terminality, resource amplification, control-character/UTC-timestamp
validation, deal value bounds and the now-fixed currency pairing, auth coverage, and
money/float discipline).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-013 CRM surface listed under Scope above. It does not
re-audit `allocation_admin.auth.require_admin` (unchanged, already audited at
`docs/audit/d-007-security-audit.md`) or `delta.persistence.database.get_tenant_session`
(unchanged, already audited across every prior Delta task) — D-013 calls both unmodified
and this review confirmed it does so correctly, not that either is independently
re-verified here. Per ADR-0013 §1/§3, this is a deliberately bounded vertical slice of the
roadmap's "complete enterprise deal pipeline... automated stakeholder mapping" — this
review assessed the code as the bounded slice it claims to be (deterministic relationship
scoring, structured-tag-based stakeholder engagement), not against a full enterprise-CRM
or ML-based scoring bar the ADR explicitly declines to attempt.
