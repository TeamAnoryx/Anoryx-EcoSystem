# D-014 Security Audit — ERP: Asset Register + Vendor/Purchase-Order Procurement

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/erp/` (the entire new package), `Delta/src/delta/persistence/
  migrations/versions/0008_erp_assets_vendors_po.py` (new tables, RLS, grants, CHECK
  constraints), the additive-only changes to `Delta/src/delta/identifiers.py` and
  `Delta/src/delta/persistence/models.py`, the one new router mount in
  `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/erp/`, the new frontend
  surface (`Delta/frontend/src/app/(admin)/erp/`, `Delta/frontend/src/components/erp/`,
  and the additive changes to `types.ts`/`admin-client.ts`/`bff.ts`/`app-nav.tsx`), and
  `Delta/docs/adr/0014-delta-erp-assets-procurement.md` (the design record, cross-checked
  against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Two Low findings; both fixed on
  this branch before merge.

## Note on tooling

Semgrep's registry could not be fetched in the audit environment (the egress proxy denies
`CONNECT` to `semgrep.dev` — the same known limitation recorded in every prior audit this
session; see `docs/audit/d-013-security-audit.md`). This pass is manual dataflow analysis,
tracing every claim in the ADR back to the actual source, per the same accepted precedent.
`delta-ci.yml`'s `quality` job's Semgrep step runs for real in CI (registry reachable there)
and remains the authority of record for SAST on this PR.

## What was actively tried and found sound

- **Cross-tenant isolation.** Every read is RLS-confined via `get_tenant_session`; writes
  set `tenant_id` to the session's own tenant. `get_vendor`/`get_asset`/`get_purchase_order`
  filter by id only and rely on RLS to make a cross-tenant row invisible — 404s a
  cross-tenant lookup indistinguishably from a genuinely missing one.
- **Cross-tenant FK reference.** `fk_po_vendor`/`fk_po_asset` (migration
  0008:148-157) are genuine composite `(id, tenant_id)` FKs against
  `uq_vendor_id_tenant`/`uq_asset_id_tenant`. Because both FKs share the single
  `purchase_orders.tenant_id` column, a PO's vendor and asset are structurally forced
  into the PO's OWN tenant — cross-tenant reference is blocked at the database layer,
  independent of RLS or the app's own vendor/asset-existence checks.
- **Asset lifecycle (forward-only).** `REQUIRED_PRIOR_STATUS` + the conditional
  `UPDATE ... WHERE status = required_prior` (`store.py`) is forward-only, no-skip,
  no-reverse, and race-safe (row-level lock + `rowcount` check). A freshly-created asset
  always starts at exactly `active`; `active` is rejected as an invalid forward target
  by `service.py`.
- **Purchase-order decision idempotency + audit atomicity.** `try_decide_purchase_order`
  guards on `status = 'requested'`; `decide_purchase_order` commits the status change
  and the D-009 `append_history` audit write in ONE transaction — no separable-commit
  window where one could succeed without the other. No production code path reuses a
  session across two commits (the transaction-local RLS GUC footgun the implementer hit
  once while drafting tests, confirmed absent from all shipped service code).
- **Value/currency pairing (both tables).** Actively tried to produce a mismatched row
  on `assets` (optional cost) and `purchase_orders` (required amount): `service.py`
  defaults currency to `USD` whenever a cost is present and forces it to `None` when
  absent; the `Currency` regex forbids an empty string; a `$0.00` cost still pairs a
  currency. Backed by a DB `CHECK ((cost IS NULL) = (currency IS NULL))` on `assets`.
  A PO's amount is required with a required, defaulted currency — no path produces a
  mismatch on either table.
- **Validation.** `extra="forbid"` everywhere; every free-text field rejects control
  characters; `require_aware_utc` on `acquired_at`; Literal-typed category/status/action
  reject unknown values; `ge=0`/`le=MAX` plus DB CHECKs bound every money field;
  every query is a parameterized SQLAlchemy Core statement — no string-interpolated SQL
  anywhere in `delta.erp.store`.
- **Auth.** `require_admin` (D-007's unmodified break-glass bearer) is a router-level
  `dependencies=[Depends(require_admin)]` covering all 8 ERP routes — no per-route
  opt-out.
- **Frontend token isolation.** `admin-client.ts` remains `server-only`; every new ERP
  client component calls a `"use server"` Server Action in `erp/actions.ts`, never
  `admin-client.ts` directly. The `CreatePoForm`'s `useEffect` re-sync (fixed during the
  live smoke test, see ADR-0014 §5) only calls `setVendorId` when the current selection
  is invalid for the current `vendors` list — converges in one pass, confirmed no
  infinite-re-render risk.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `erp/schemas.py` (`AssetCreateRequest.acquisition_cost_minor_units`, `PurchaseOrderCreateRequest.amount_minor_units`) | Both fields were typed as plain `int = Field(ge=..., le=...)` rather than using `delta.money.reject_non_integer` as a `mode="before"` validator the way `Money` itself does. Pydantic v2's lax coercion accepts a JSON float with no fractional part (e.g. `100.0`) and silently coerces it to `int(100)`. No float ever reaches the database (the column is `BigInteger`) and neither ERP money field feeds any ledger/budget/forecast/enforcement calculation, so this was a validation-strictness consistency gap against `Money`'s own stricter discipline, not an exploitable security boundary — it matched the SAME pre-existing pattern already accepted in `allocation_admin.schemas.AllocationCreateRequest.total_minor_units`. | **Fixed.** Both fields now have a `mode="before"` validator delegating to `delta.money.reject_non_integer`, rejecting a float (or bool) outright rather than silently coercing it — matching `Money`'s own discipline. Regression tests added: `test_asset_create_rejects_float_cost`, `test_purchase_order_create_rejects_float_amount`. |
| 2 | Low | `tests/erp/test_store_db.py` | ADR-0014 §4 claimed two invariants as "verified by code review" only, with no test exercising them directly: (a) the cross-tenant composite-FK rejection at the DB layer (RLS-mediated 404s were tested, but not the FK's own independent enforcement), and (b) a true-concurrent double-decision/double-transition race (existing tests were sequential, not genuinely racing two coroutines). Neither is a live exploit — the FK and conditional-UPDATE guards are structurally correct — but a future refactor (e.g. dropping `tenant_id` from a composite FK, or loosening an `UPDATE ... WHERE` clause) would not have been caught by the pre-fix suite. | **Fixed.** Three tests added: `test_po_cannot_reference_vendor_from_different_tenant_at_db_level` (uses `get_privileged_session` — bypasses RLS entirely — to prove the composite FK itself, not just RLS, rejects a cross-tenant vendor reference), `test_concurrent_purchase_order_decisions_only_one_wins` and `test_concurrent_asset_status_transitions_only_one_wins` (both use `asyncio.gather` to race two genuinely concurrent coroutines against the same row, asserting exactly one wins). |

## Threat model cross-reference

See `docs/adr/0014-delta-erp-assets-procurement.md` §4 for the full vectors-to-mitigations-to-tests
table this audit validated against (cross-tenant isolation, cross-tenant FK enforcement,
forward-only asset lifecycle, PO decision idempotency and audit-chain atomicity,
value/currency pairing on both tables, input validation, auth coverage, and
money/float discipline).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-014 ERP surface listed under Scope above. It does not
re-audit `allocation_admin.auth.require_admin`, `delta.persistence.database.get_tenant_session`/
`get_privileged_session`, or `delta.persistence.audit_log.append_history` (all unchanged,
already audited across D-007/D-009's own audit records) — D-014 calls all three unmodified
and this review confirmed it does so correctly, not that any is independently re-verified
here. Per ADR-0014 §1/§3, this is a deliberately bounded vertical slice of the roadmap's
"real-time sync of supply chain, payroll, HR, and physical assets — the full ERP" — this
review assessed the code as the bounded slice it claims to be (asset register + vendor/PO
procurement), not against payroll/HR compliance requirements or external-ERP-integration
security this task explicitly declines to build.
