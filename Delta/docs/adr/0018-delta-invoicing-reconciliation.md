# ADR-0018 — Automated Invoicing + Vendor Payment Reconciliation: A PO-Backed Three-Way Match

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-018 (Automated invoicing + vendor payment reconciliation) · Builder:
  orchestration-hooks · Phase 3 (post-investment vision) — the sixth task built past
  Delta's committed MVP (D-001→D-012), continuing directly after D-017 per the user's
  standing "complete all post-investment tasks" instruction.
- **Depends on:** D-003 (the double-entry ledger — read for its money/reconciliation
  conventions, deliberately NOT integrated with; see Fork 5 and §3), D-014
  (`delta.erp` — vendors and purchase orders are this task's real, structural
  dependency: every invoice is submitted against an existing, approved PO).
- **Builds on:** D-015's `tasks` table (`status = 'done'`) as the roadmap's "project
  milestones/delivery metrics" proof leg, and D-009's hash-chained audit log (every
  invoice submission, decision, and payment is a genuine financial event, wired in
  exactly the way D-014's PO decisions already are).
- **Supersedes:** nothing. Adds a new `delta.invoicing` package, two new tables
  (`invoices`, `invoice_payments`) via migration 0012, one new router mount to
  `allocation_admin/app.py`. No existing D-007–D-017 file's runtime behavior is
  modified.

## 1. Context

The roadmap's literal text for D-018 is: *"Invoicing + vendor payment reconciliation
linked to project milestones/delivery metrics; continuous ERP ledger
reconciliation."* Tagged `🏦 POST-INVESTMENT`, sized "22-30h · Risk: High," depending
on D-003 and D-014. Taken at face value, "continuous ERP ledger reconciliation" could
mean wiring vendor payments directly into D-003's `ledger_entries`/`transactions`
tables. That reading does not survive contact with what those tables actually are:
every `ledger_entries` row is attributed to Sentinel's four AI-usage stable IDs
(`team_id`, `project_id`, `agent_id`, plus `tenant_id`) — the ledger exists to record
AI-agent SPEND, not accounts-payable settlement to a vendor. D-014 itself, when it
built the vendor/PO/asset procurement surface this task extends, never touched the
ledger for the identical reason (verified directly: no `ledger`/`Transaction`
reference anywhere in `delta.erp`). Forcing vendor payments into that schema would
misrepresent a vendor invoice payment as AI agent cost, corrupting the exact
attribution D-003 exists to keep clean. This ADR applies the same discipline every
prior D-013→D-017 ADR established: a bounded, honestly-scoped vertical slice — a
classic accounts-payable **three-way match** (purchase order commitment → invoice
billing claim → recorded payment settlement), reconciled entirely within Delta's own
procurement/billing records, with real external ledger/bank-feed reconciliation named
as D-019's explicit, already-roadmapped job ("Corporate ERP integrations... for
continuous ledger reconciliation... Depends on: D-014, D-018").

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — an invoice may only be submitted against an already-`approved` D-014 purchase order, and the running non-disputed-invoiced total for that PO may never exceed the PO's own committed amount — enforced by a `SELECT ... FOR UPDATE` row lock on the PO, not a bare read-then-check** | `invoicing.service.create_invoice` fetches the PO via `store.get_purchase_order_summary_for_update` (a `SELECT ... FOR UPDATE`, locking the PO row for the rest of the transaction), rejects if its `status != "approved"` (`PurchaseOrderNotApprovedError`) or its `vendor_id` doesn't match the invoice's claimed vendor (`PurchaseOrderVendorMismatchError`), then sums every non-disputed invoice already submitted against that PO (`sum_non_disputed_invoiced_for_po`) and rejects if `already_invoiced + this_amount > po.amount_minor_units` (`InvoiceExceedsPurchaseOrderError`). **Post-audit correction:** the first shipped version used a plain (unlocked) read here, which the independent security-auditor reproduced live as a TOCTOU race — 10 concurrent invoice submissions each claiming a full PO's ceiling all committed, a 10x over-commitment (`docs/audit/d-018-security-audit.md` Finding 1, High). The `FOR UPDATE` lock closes it: a second concurrent submission against the SAME PO blocks at the lock acquisition until the first commits or rolls back, so its own sum-check always sees the first's already-committed invoice. Verified live under 10-way concurrency post-fix (`test_concurrent_invoice_creation_never_exceeds_po_commitment`) — exactly 1 of 10 concurrent full-ceiling submissions now succeeds. | This is the "commitment" leg of the three-way match: an invoice is a billing CLAIM against money the business already agreed to spend (an approved PO), and the sum of claims can never exceed the commitment — mirrors `delta.reconciliation.reconcile_allocation`'s own "distributed <= total" philosophy, applied here as a ceiling rather than an exact-sum invariant (a PO can be partially invoiced across multiple deliveries). The row lock (rather than a per-PO advisory lock or `SERIALIZABLE`) was chosen because it's the standard, minimal-footprint Postgres primitive for "serialize writers against this one row" and composes cleanly with the rest of the transaction — no retry logic needed, unlike `SERIALIZABLE`'s abort-and-retry contract. |
| **2 — a `milestone_task_id`, when present, must reference a D-015 task already in `status = 'done'`** | `create_invoice` calls `store.get_task_status` (a direct read of the shared `tasks` table, mirroring D-016's `capacity.store` precedent of querying another task's table directly rather than importing its owning package's store module) and rejects with `MilestoneTaskNotFoundError`/`MilestoneTaskNotDoneError` if the task doesn't exist or isn't done. `milestone_task_id` itself is a plain nullable column, not an FK (`tasks` has no `UniqueConstraint(task_id, tenant_id)` for a composite FK to reference — migration 0009 never added one). | This is the roadmap's own "linked to project milestones/delivery metrics" requirement, made concrete and checked, not decorative: an invoice claiming to be for delivered work must point at a task the system itself has recorded as delivered. The application-layer check (vs. a DB FK) mirrors migration 0010's identical choice for a comparable no-precedent-table situation. |
| **3 — invoice currency must exactly match its PO's currency** | `create_invoice` rejects with `CurrencyMismatchError` if `req.currency != po.currency`. | D-001's no-FX rule: summing amounts across currencies is meaningless. This also keeps the reconciliation report's per-vendor sums (Fork 6) single-currency by construction, not by a runtime filter alone. |
| **4 — payment recording is a SINGLE atomic conditional UPDATE with a computed WHERE guard, not a read-then-write; and a payment's currency must exactly match its invoice's currency** | `store.try_record_payment` issues one `UPDATE invoices SET amount_paid_minor_units = amount_paid_minor_units + :amount, status = CASE ... WHEN reaches full THEN 'paid' ELSE 'partially_paid' END WHERE status IN ('approved','partially_paid') AND amount_paid_minor_units + :amount <= amount_minor_units RETURNING status`. Returns `None` (no row matched) if the invoice wasn't payable or this payment would overpay it. `record_payment` reads the invoice first and rejects with `PaymentCurrencyMismatchError` if `req.currency != invoice.currency`, before ever touching the atomic UPDATE. **Post-audit correction:** the currency check was missing from the first shipped version — the independent security-auditor reproduced live that a `JPY`-labelled payment could fully settle a `USD` invoice, silently corrupting the reconciliation report's per-currency sums (`docs/audit/d-018-security-audit.md` Finding 2, Medium). Unlike the amount guard, currency is immutable per invoice (never concurrently written), so a plain read-then-check ahead of the atomic UPDATE carries no race. | The exact race-guard shape D-005's budget engine and D-007/D-013/D-014's conditional-decision UPDATEs already use, extended here to a COMPUTED condition rather than a fixed prior-status match — Postgres's row-level locking makes two concurrent payment attempts serialize on this single statement, so neither can ever together overpay an invoice. Verified directly under 10-way concurrency (`test_concurrent_payments_never_overpay_invoice`), not just reasoned about. The currency check mirrors the invoice↔PO currency guard (Fork 3) — D-001's no-FX rule means a payment can only ever be denominated in its own invoice's currency. |
| **5 — reconciliation is entirely internal (PO commitment vs. non-disputed invoiced vs. paid), NOT integration with D-003's ledger or any external system** | `invoicing.service.get_vendor_reconciliation` sums `purchase_orders.amount_minor_units` (status='approved'), `invoices.amount_minor_units` (non-disputed), and `invoices.amount_paid_minor_units` for one vendor + currency, and returns `committed`/`invoiced`/`paid`/`outstanding` plus two defense-in-depth flags (`over_invoiced`, `over_paid`) that Forks 1 and 4's guards are DESIGNED to make impossible — flagged anyway as an independent runtime check, mirroring `delta.reconciliation`'s own complement-check philosophy (a construction-time guard AND a separate runtime check, not one or the other; this is exactly the pairing that let the security audit's live reproduction of Finding 1 be caught by inspection rather than only by an attack script). | This is the honest reading of "continuous ERP ledger reconciliation" available to a single unattended task: a real, always-computed-from-current-state check of Delta's OWN procurement/billing data (not a cached/stale report), stopping short of wiring vendor payments into an unrelated ledger schema (Fork context, §1) or building a real external bank-feed/corporate-ERP sync — D-019's named job. |
| **6 — `delta.invoicing` is gated by `require_admin` only, NOT retrofitted with D-017's RBAC** | `invoicing/router.py`'s router-level dependency is `Depends(require_admin)` — the same break-glass bearer every surface except D-008's dashboards uses. | Mirrors D-017 ADR §3's own explicit deferral: "the other six admin surfaces... remain `require_admin`-only — a real, large, cross-cutting retrofit." D-018 is the seventh; retrofitting RBAC across it too is out of scope for this task and would silently expand D-017's already-bounded slice after the fact. |
| **7 — an invoice submission, decision, AND a recorded payment are all wired into D-009's hash-chained audit log** | Every one of the three mutating calls in `invoicing.service` ends with `append_history(..., entity_type="invoice"` or `"invoice_payment"`, `action=...)` in the SAME transaction as the store write, mirroring D-014's identical rule for PO decisions (and unlike D-013/D-015/D-016/D-017's own business-process/access-control writes, which are explicitly NOT audited). | A vendor invoice and its payment are unambiguously financial transactions — D-009's own stated scope ("every automated corporate financial workflow"). This is a stronger audit posture than D-014's PO flow (which only audits the DECISION, not the initial `requested` creation — though on inspection D-014 audits both; D-018 matches that same both-ends coverage for submission and decision, and extends it to payment recording, the point money actually changes hands). |
| **8 — mounted on the existing admin app, not a new process** | `POST/GET /v1/admin/invoicing/invoices`, `POST /v1/admin/invoicing/invoices/{id}/decision`, `POST/GET /v1/admin/invoicing/invoices/{id}/payments`, `GET /v1/admin/invoicing/reconciliation` on the same D-007 admin app. | Same operators, same auth boundary, same trust boundary — mirrors D-008/.../D-017's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No wiring into D-003's ledger.** Vendor payments are NOT posted as
  `Transaction`/`LedgerEntry` rows — that schema is structurally scoped to AI-usage
  cost attribution (team/project/agent), not accounts-payable, and D-014 established
  this same boundary for its own PO/asset writes. Named here as a deliberate,
  reasoned exclusion, not an oversight (§1, Fork 5).
- **No external ERP/bank-feed sync.** No NetSuite/SAP/Coupa/Ariba integration, no
  bank-statement import, no automated payment execution (this records that a payment
  WAS made — presumably via whatever payment rail the business already uses — it does
  not initiate one). D-019 ("Corporate ERP integrations... Depends on: D-014, D-018")
  is the roadmap's own named future task for this.
- **No RBAC gating.** `require_admin` only, matching six of Delta's seven other admin
  surfaces — D-017's RBAC retrofit was deliberately bounded to D-008's dashboards
  alone (Fork 6).
- **No invoice line items, tax calculation, or multi-currency FX.** One amount, one
  currency (which must match the PO's), per invoice — mirrors D-014's own PO/asset
  cost-field simplicity.
- **No due dates, aging, or dunning.** No `due_at` field, no "overdue" status, no
  automated vendor reminders — an invoice is `submitted` → `approved`/`disputed` →
  (approved) `partially_paid` → `paid`, nothing calendar-driven.
- **No automatic invoice generation from milestone completion.** A D-015 task
  reaching `status = 'done'` does not itself create an invoice — a vendor/operator
  still submits one explicitly; the task's `done` status is only a REQUIRED PROOF
  when a milestone link is claimed, never a trigger.
- **No multi-PO invoices.** Each invoice references exactly one PO — a vendor
  invoicing across several purchase orders at once submits one invoice per PO.
- **No token/session-level attribution for `submitted_by`/`recorded_by`.** Like every
  other Delta admin surface's `actor`/`requested_by` fields, these are operator-typed
  free strings, not verified identities — D-017's RBAC role gates WHAT an operator can
  do, not WHO they provably are (that remains D-017 §3's own named future work,
  federating with Sentinel's F-014).

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Concurrent payments overpay a single invoice | `try_record_payment`'s single atomic UPDATE with a computed WHERE guard (Fork 4) — Postgres row-level locking serializes concurrent attempts | `test_concurrent_payments_never_overpay_invoice` (10-way concurrency, exactly 5 of 10 attempts succeed, summing to exactly the invoice total) |
| An invoice (or the sum of several) claims more than its PO committed, including under concurrent submissions | `create_invoice` locks the PO row (`SELECT ... FOR UPDATE`) before summing all non-disputed prior invoices against it and rejecting an over-commitment (Fork 1 — corrected post-audit; the original unlocked version was reproduced live as a 10x-over-commitment TOCTOU race, Finding 1) | `test_create_invoice_exceeding_po_amount_raises`, `test_sum_non_disputed_invoiced_for_po_excludes_disputed`, `test_invoice_exceeding_po_amount_returns_422`, `test_concurrent_invoice_creation_never_exceeds_po_commitment` (10-way concurrency) |
| A payment settles an invoice in a different currency than the invoice's own, corrupting reconciliation totals | `record_payment` rejects `PaymentCurrencyMismatchError` if the payment's currency doesn't match the invoice's (Fork 4 — corrected post-audit; Finding 2) | `test_record_payment_currency_mismatch_raises` |
| An invoice is submitted against an unapproved, or a different vendor's, PO | `create_invoice` checks `po.status == "approved"` and `po.vendor_id == req.vendor_id` before any write | `test_create_invoice_against_unapproved_po_raises`, `test_create_invoice_vendor_mismatch_raises` |
| A false "delivery" claim — an invoice cites a milestone task that isn't actually done | `create_invoice` reads the task's live status and rejects unless it is exactly `'done'` | `test_create_invoice_with_undone_milestone_task_raises`, `test_create_invoice_with_missing_milestone_task_raises` |
| Cross-tenant invoice/payment/reconciliation leak | Composite tenant-scoped FKs (`invoices.(vendor_id/po_id, tenant_id)`, `invoice_payments.(invoice_id, tenant_id)`) plus the same fail-closed RLS `NULLIF` predicate every prior migration uses | `test_cross_tenant_invoice_is_invisible`, `test_cross_tenant_invoice_list_isolated_over_http` |
| Double-decision race on an invoice's approve/dispute | `try_decide_invoice`'s conditional UPDATE only matches a row still `'submitted'` — identical shape to D-014's `try_decide_purchase_order` | `test_try_decide_invoice_only_succeeds_once`, `test_decide_invoice_twice_raises` |
| A payment is recorded against a non-payable (submitted/disputed/paid) invoice | `try_record_payment`'s WHERE clause only matches `status IN ('approved','partially_paid')` | `test_try_record_payment_rejects_when_not_payable`, `test_record_payment_against_unapproved_invoice_raises` |
| Financial actions (submission, decision, payment) leave no attributable, tamper-evident trail | All three are wired into D-009's hash chain in the same transaction as the write (Fork 7) | `test_create_invoice_submission_is_audited`, `test_record_payment_is_audited` |
| Control-character / log-injection via `invoice_number`/`description`/`submitted_by`/`recorded_by`/`note` | Same `_reject_control_chars` discipline as every prior Delta package | `test_invoice_create_request_rejects_control_chars_in_*` (schema tests) |
| SQL injection via any invoicing identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.invoicing.store` | code review |

## 5. Verification

- `black --check .` / `ruff check .` clean on the FULL repository (not just
  `src/delta/invoicing` — the explicit lesson carried forward from D-016's own CI
  failure), 246 files.
- New `tests/invoicing/` suite: 54 tests — 19 pure schema-validation tests
  (`test_schemas.py`, no DB/I/O), 11 DB-backed store tests (`test_store_db.py`,
  including the 10-way concurrent-payment race test and cross-tenant isolation), 19
  DB-backed service tests (`test_service_db.py`, covering every guard in §2's forks,
  the D-009 audit-chain wiring, and the two post-audit concurrency/currency
  regression tests), 5 non-stubbed HTTP e2e tests (`test_router_e2e.py` — real ASGI
  app, real auth, real DB, driving the full three-way match: D-014 vendor/PO → D-015
  milestone task → D-018 invoice submit/decide/pay → reconciliation report).
- Full existing Delta suite green (839 passed, 15 skipped, post-fix) — zero regressions.
- Migration 0012 applied cleanly against a live local Postgres (`alembic upgrade
  head`), `delta_app` role provisioned exactly as every prior migration's test
  harness does; schema verified directly via `psql \d` (composite FKs, CHECK
  constraints, RLS policies all present as designed).
- Frontend: `tsc --noEmit` clean, `next lint` clean (0 warnings/errors on all new/
  modified files). Live browser smoke test performed against a real running backend
  with real data entered through the UI itself: seeded a vendor + approved PO + a
  done milestone task via direct backend calls, logged in via the break-glass token,
  loaded the (previously empty) invoicing page, submitted an invoice through the UI
  form (with the milestone task linked), approved it via the UI, recorded a partial
  payment via the UI (confirmed the invoice moved to `partially_paid` with the
  correct running total against the live backend), and pulled the vendor
  reconciliation report via the UI, confirming it showed the correct committed/paid
  totals computed from the real database state — every step verified against the
  real backend, not mocked.
- Independent security-auditor review dispatched against this diff — initial verdict
  **BLOCK**: one High finding (Fork 1's over-invoicing ceiling was a live-reproduced
  TOCTOU race — a 10x over-commitment) and one Medium (Fork 4's missing payment
  currency check — a live-reproduced JPY-settles-USD-invoice case). Both were fixed
  (the `SELECT ... FOR UPDATE` row lock and the `PaymentCurrencyMismatchError` guard,
  Forks 1 and 4 above), with dedicated regression tests added and verified under
  concurrency, and the full suite (now 54 invoicing tests, 839 total across the repo)
  re-run green post-fix. Two more Low findings were also fixed for consistency (the
  untyped `currency` query param on `GET /reconciliation`, and a permissive `ge=0`
  invoice-amount bound tightened to `gt=0`); one Low (the BFF break-glass-implies-
  full-trust boundary, already accepted in D-017's audit) required no code change.
  Full findings, the live reproduction detail, and the fix verification are in
  `docs/audit/d-018-security-audit.md`.

## 6. Alternatives considered

- **Posting vendor payments as D-003 `Transaction`/`LedgerEntry` rows ("continuous
  ERP ledger reconciliation" read literally).** Rejected (§1, Fork 5): that schema is
  structurally attributed to Sentinel's AI-usage stable IDs (team/project/agent), not
  vendor accounts-payable — forcing a fit would misrepresent vendor spend as AI agent
  cost and corrupt the exact attribution D-003 exists to protect. D-014 itself never
  did this for the identical reason.
- **A read-then-write (`SELECT` current paid total, check in Python, `UPDATE`) for
  payment recording.** Rejected (Fork 4): a textbook TOCTOU race under concurrent
  payment attempts — exactly the bug class D-015's own security audit found and D-016/
  D-017 explicitly re-checked for. A single atomic UPDATE with a computed WHERE
  guard closes the window entirely, verified under real concurrency rather than
  reasoned about.
- **Allowing an invoice against a still-`requested` (not yet approved) PO.** Rejected
  (Fork 1): a PO is only a real financial commitment once decided `approved` —
  invoicing against a merely-requested PO would let a vendor bill for spend the
  business never actually authorized.
- **Treating `milestone_task_id` as informational only (no status check).**
  Rejected (Fork 2): the roadmap's own wording ties invoicing to delivery metrics —
  an unchecked, decorative field would not actually deliver that requirement, just
  gesture at it.
- **Retrofitting D-017's RBAC onto this surface too.** Rejected (Fork 6): D-017's ADR
  §3 explicitly bounded its retrofit to D-008's dashboards alone and named the other
  six surfaces (now seven, including this one) as deliberately deferred — expanding
  that scope silently, from a different task, would misrepresent D-017's own stated
  boundary.
