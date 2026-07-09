# ADR-0014 — ERP: Asset Register + Vendor/Purchase-Order Procurement

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-014 (Comprehensive ERP engine) · Builder: orchestration-hooks · Phase 3
  (post-investment vision) — the second task built past Delta's committed MVP
  (D-001→D-012), continuing directly after D-013 per the user's explicit instruction
  to keep going into the vision tier.
- **Depends on:** D-001 (identifier/domain-type conventions), D-003 (indirectly — new
  tables, not ledger-backed, but the tenant-RLS pattern D-003 established governs them
  identically), D-009 (the hash-chained audit log a purchase-order decision writes
  into — the one place D-014 genuinely needs D-009, unlike D-013's CRM which
  deliberately did not).
- **Builds on:** D-007's propose/decide workflow shape (`allocations` → reused
  verbatim for `purchase_orders`), D-013's forward-only lifecycle pattern (deal
  stages → reused for asset status) and its value/currency-pairing lesson (applied
  here proactively from the start, not post-audit).
- **Supersedes:** nothing. Adds a new `delta.erp` package, three new tables
  (migration 0008), and one new router mount to `allocation_admin/app.py`; does not
  alter any D-001…D-013 runtime behavior, contract, or persistence schema.

## 1. Context

The roadmap's literal text for D-014 is: *"Real-time sync of supply chain, payroll,
HR, and physical assets. The full ERP."* Four named domains, tagged `🏦
POST-INVESTMENT`, sized "28h+ (Heavy, multi-feature)." Taken literally this spans
payroll (tax/compliance-sensitive, no framework anywhere in this codebase), HR
(personnel records — a domain Delta's core competency, budget/FinOps policy, has no
precedent for), supply chain, and physical assets. Attempting all four in one
unattended pass would repeat the exact mistake D-013's ADR §1 already reasoned
through and declined for CRM: scope-widening under an ambiguous, deliberately-large
roadmap label. This ADR applies the same discipline — a bounded, honestly-scoped
vertical slice, not the label's full literal breadth.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — asset register + vendor/PO procurement; payroll and HR entirely out of scope** | D-014 implements two of the roadmap's four named domains: a physical/software **asset register** and a **vendor directory + purchase-order procurement workflow**. Payroll and HR are not touched at all — no employee/personnel table, no compensation data, no tax/compliance logic anywhere in this task. | Payroll and HR are categorically different from the rest of Delta's domain: they require tax/compliance frameworks, involve sensitive PII (SSNs, compensation, health data) with regulatory obligations (this session has zero precedent or review process for that), and have no existing data model anywhere in the Anoryx ecosystem to extend. Asset register and procurement, by contrast, are natural extensions of Delta's existing "track money and things tied to it" competency (D-001's domain model, D-007's propose/decide workflow) and can be built with the SAME security/RLS/audit rigor already proven across D-001…D-013. Building payroll/HR data models unreviewed, in one unattended pass, would be irresponsible in a way asset/procurement tracking is not. |
| **2 — "real-time sync" is D-019's job, not this task's** | D-014 builds the INTERNAL record-keeping (asset register, vendor directory, PO workflow) that a future external integration would sync data into or out of. It does not integrate with any real external ERP, accounting system, or procurement platform. | The roadmap's own dependency graph supports this split: D-019 ("Corporate ERP integrations — NetSuite/SAP, Coupa/Ariba, AWS/GCP/Azure... continuous ledger reconciliation; cloud cost sync; procurement") explicitly `Depends on: D-014`. D-019 is the future task that adds real external sync; D-014 is honestly scoped as the internal data model that sync would eventually target — not a simulated or stubbed integration pretending to be real-time sync today. |
| **3 — asset lifecycle is forward-only (active → retired → disposed), enforced at the app layer** | `assets.status` is a plain string column; forward-only transition is enforced by `delta.erp.store.try_transition_asset_status`'s conditional `UPDATE ... WHERE status = <required_prior>` (the exact conditional-UPDATE race-guard shape as D-007's `try_decide_allocation` and D-013's `try_transition_deal_stage`) — not a DB CHECK restricting the status vocabulary. | Mirrors D-013's ADR-0013 Fork 2 reasoning exactly: the actual invariant that matters (no backward transition, no skipping a step) is enforced structurally by the query's WHERE clause regardless of how many statuses exist, not by a closed DB-level vocabulary a future status addition would have to migrate around. |
| **4 — a purchase-order decision IS wired into D-009's hash-chained audit log** | Unlike D-013's CRM edits (deliberately NOT wired into D-009 — business-process data, not financial transactions), `delta.erp.service.create_purchase_order`/`decide_purchase_order` call `delta.persistence.audit_log.append_history` in the SAME transaction as the store write. | A purchase order is a genuine financial commitment (a promise to pay a vendor a specific amount) — squarely within D-009's own stated scope ("Delta's automated financial workflows"), and the roadmap explicitly lists D-009 as a dependency for this task. This is the correct application of the same boundary D-013 drew in the opposite direction: CRM edits are business-process data (excluded), PO decisions are financial commitments (included) — the line is drawn by what the event actually IS, not by which task happens to be building it. |
| **5 — value/currency pairing enforced from the start, both in app logic and a DB CHECK** | Both `assets.acquisition_cost_minor_units`/`currency` and (implicitly, since `purchase_orders.amount_minor_units` is NOT nullable) the PO amount/currency pair are guarded: `service.create_asset` defaults a missing currency to `DEFAULT_CURRENCY` whenever a cost is present, and migration 0008 adds `CHECK ((acquisition_cost_minor_units IS NULL) = (currency IS NULL))` on `assets`. A PO's amount is REQUIRED (not optional like a CRM deal's pipeline-estimate value), so it always carries both fields set by construction — no analogous CHECK is needed there. | D-013's own independent security review (ADR-0013 §4, finding #1) caught exactly this class of bug for CRM deals — a caller-supplied `currency: null` alongside a non-null value could persist a mismatched row. This task applies that lesson proactively from the first draft rather than needing its own audit to catch it, and reuses the exact `(X IS NULL) = (Y IS NULL)` CHECK shape. |
| **6 — no new vendor/asset "scope" check beyond tenant-level composite FKs** | Unlike D-013's CRM (which needed an explicit `_check_deal_scope`/`_check_stakeholder_scope` above the tenant-level FK, because interactions/stakeholders nest under a specific CLIENT), vendors and assets are both flat, tenant-level entities with no finer grouping to also enforce — the composite `(entity_id, tenant_id)` FK on `purchase_orders` fully proves both "this vendor/asset belongs to the caller's tenant," which is the only invariant that needs proving here. | Simpler correctly-scoped code: adding an unnecessary extra check that has no real invariant to protect would be complexity without a corresponding security benefit — the D-013 pattern only applies where a genuine finer-grained parent-child relationship exists. |
| **7 — mounted on the existing admin app, not a new process** | `GET/POST /v1/admin/erp/*` on the same D-007 admin app, same `require_admin` break-glass bearer auth (imported unchanged from `allocation_admin.auth`). | Same operators, same auth, same trust boundary — mirrors D-008/D-011/D-012/D-013's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No payroll.** No compensation data, no pay-run processing, no tax withholding/
  compliance logic anywhere in this task. A real payroll feature needs a dedicated
  compliance review this run cannot provide — named honestly as future work, not
  approximated.
- **No HR / personnel records.** No employee table, no headcount tracking, no
  org-chart data. `assets.assigned_team_id` is an opaque scope id (the same shape
  D-007's allocation targets already use) — it is NOT a personnel/employee reference.
- **No real-time external ERP/accounting sync.** D-014 is the internal data model;
  actual integration with NetSuite, SAP, Coupa, Ariba, or any cloud billing API is
  D-019's explicitly-dependent future task (Fork 2).
- **No depreciation schedule / accounting treatment.** An asset's
  `acquisition_cost_minor_units` is recorded once, at creation; there is no
  straight-line/declining-balance depreciation calculation, no book-value tracking
  over time, no fixed-asset accounting integration with a general ledger.
- **No multi-line purchase orders.** A PO is a single amount + description against
  one vendor (optionally tied to one asset) — not a line-item order with quantities,
  unit prices, and per-line tax. A real procurement system's line-item detail is
  real, valuable future work this task does not claim to deliver.
- **No receiving / fulfillment tracking.** A PO's lifecycle ends at
  approved/rejected; there is no "goods received," partial fulfillment, or
  three-way-match (PO/receipt/invoice) reconciliation — that overlaps with D-018's
  own explicitly separate roadmap scope ("Automated invoicing + vendor payment
  reconciliation").
- **No vendor-performance scoring, contract management, or multi-currency FX on a
  single PO.** A vendor record is bare identity + status; a PO's currency is fixed at
  creation with no conversion.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant vendor/asset/PO leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`; every table's RLS predicate is the same fail-closed `tenant_id = NULLIF(current_setting(...), '')` as every prior Delta migration; every FK is a composite `(entity_id, tenant_id)` pair | `test_cross_tenant_isolation_vendors_invisible_to_other_tenant`, `test_cross_tenant_vendor_list_isolated_over_http` |
| A PO references a vendor/asset from a DIFFERENT tenant | Structurally impossible: `fk_po_vendor`/`fk_po_asset` are composite `(id, tenant_id)` FKs against `vendors`/`assets`, which are themselves RLS-confined at write time | code review — same FK shape D-007/D-013 already establish and tested |
| An asset moves backward or skips a lifecycle step | `try_transition_asset_status`'s conditional `UPDATE ... WHERE status = required_prior` only matches the EXACT expected prior status — a skip (active→disposed) or reversal (retired→active) both affect zero rows | `test_asset_status_moves_forward_one_step_at_a_time`, `test_transition_asset_status_to_active_rejected`, `test_transition_asset_status_skipping_a_step_rejected`, `test_asset_status_skip_step_returns_409` |
| A PO decision is applied twice (double-approve, or approve-then-reject) | `try_decide_purchase_order`'s conditional `UPDATE ... WHERE status = 'requested'` — the exact same guard as D-007's `try_decide_allocation` — affects zero rows on a second attempt | `test_purchase_order_decision_succeeds_once_then_blocked`, `test_decide_purchase_order_already_decided_raises` |
| Asset cost/currency drift (a cost without a currency, or vice versa) | `service.create_asset` defaults a missing currency to `DEFAULT_CURRENCY` whenever a cost is present; DB `CHECK ((acquisition_cost_minor_units IS NULL) = (currency IS NULL))` is a second, independent layer — applied proactively, not post-audit (Fork 5) | `test_create_asset_with_cost_defaults_currency_when_null`, `test_asset_cost_without_currency_rejected_by_db_check` |
| PO amount overflow / negative amount | Pydantic `Field(ge=0, le=MAX_PO_AMOUNT_MINOR_UNITS)`; DB-level `CHECK (amount_minor_units >= 0)` as a second, independent layer | `test_purchase_order_create_rejects_negative_amount`, `test_purchase_order_create_rejects_amount_above_max`, `test_purchase_order_create_accepts_amount_at_max` |
| A PO decision silently fails to reach the audit trail | `append_history` runs in the SAME transaction as the store write (both commit together or neither does — D-009's own transactional guarantee, reused unmodified) | `test_purchase_order_decision_lands_in_d009_audit_chain` |
| Naive (non-UTC-aware) timestamps silently misinterpreted | `require_aware_utc` (D-001's own helper, reused unchanged) on `acquired_at` | `test_asset_create_rejects_naive_acquired_at` |
| Log-injection / control-character injection via free-text fields | Every free-text field (`name`, `description`, `actor`, `requested_by`, `note`) goes through the same `_reject_control_chars` discipline as D-007/D-013 | full `test_schemas.py` suite |
| Auth bypass on any of the 8 new endpoints | `require_admin` (D-007's break-glass bearer, unmodified) is the router-level `dependencies=[Depends(require_admin)]` on the whole `erp_router` — no per-route opt-out exists | `test_vendors_endpoint_401_without_bearer` |
| Money-as-float leaking into a decision path | `acquisition_cost_minor_units`/`amount_minor_units` are always `int`; no `float` anywhere in `delta.erp` | code review |
| SQL injection via any ERP identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.erp.store` | code review |

## 5. Verification

- `black --check` / `ruff check .` clean.
- New `tests/erp/` suite: 40 tests — 18 pure schema-validation tests
  (`test_schemas.py`), 6 DB-backed store tests (`test_store_db.py`), 8 DB-backed
  service tests (`test_service_db.py`, incl. the D-009 audit-chain wiring test), 5
  non-stubbed HTTP e2e tests (`test_router_e2e.py`, real ASGI app, real auth, real DB).
- Full existing Delta suite green (664 passed, 15 skipped) — zero regressions, zero
  changes to any D-001…D-013 file's runtime behavior (the only modification to
  existing code is one router mount in `allocation_admin/app.py`, and one new section
  each in `identifiers.py`/`persistence/models.py`, additive only).
- Migration 0008 verified round-trip (`alembic upgrade head` → `downgrade -1` →
  `upgrade head`) against a live local Postgres, `delta_app` role provisioned exactly
  as every prior migration's test harness does.
- Frontend: `npm run typecheck` clean, `npm run lint` clean (0 warnings/errors),
  `npm run build` succeeds (`/erp` registered as a dynamic route). Live browser smoke
  test performed against a real running backend with real data entered through the UI
  itself: created a vendor, created an asset with a dollar cost, created a PO linking
  both, approved the PO, and transitioned the asset lead→retired — all rendered
  correctly with live-computed state. The smoke test caught a real frontend bug fixed
  before merge: `CreatePoForm`'s vendor-select `useState` initializer only read the
  `vendors` prop once at mount, so newly-added vendors were invisible to the dropdown's
  underlying state (though visually the `<select>` still displayed the first option,
  masking the bug) until a full page reload — fixed with a `useEffect` that re-syncs
  the selection whenever the `vendors` prop changes and the current selection is no
  longer valid.

## 6. Alternatives considered

- **Building all four roadmap-named domains (supply chain, payroll, HR, physical
  assets) in one pass.** Rejected (Fork 1) for the same reason D-013's ADR declined
  full enterprise-CRM parity: an unattended, single-PR run without a dedicated review
  cycle for sensitive-PII/compliance domains (payroll, HR) is not a responsible way
  to introduce them, and doing so would be exactly the scope-widening-under-ambiguity
  this run's operating procedure is instructed to avoid.
- **Building a real external ERP/accounting-system integration now.** Rejected
  (Fork 2): the roadmap's own dependency graph names D-019 as the future task for
  this, explicitly depending on D-014 — building it now would be building on top of a
  foundation this same PR hasn't finished laying, and duplicating work D-019 is meant
  to do.
- **A DB CHECK constraint enumerating the full asset-status vocabulary.** Rejected
  (Fork 3) for the identical reason D-013 rejected it for deal stages: the real
  invariant (no backward/skipped transition) is enforced at the query layer, not by a
  closed DB-level set a future status addition would have to migrate around.
- **Leaving purchase orders out of D-009's audit chain (mirroring D-013's CRM
  choice).** Rejected (Fork 4): a purchase order is a genuine financial commitment,
  categorically different from CRM business-process data — the roadmap's own
  "Depends on: D-009" signal for this task supports wiring it in, and doing so is the
  correct application of the boundary D-013 drew, not an inconsistency with it.
