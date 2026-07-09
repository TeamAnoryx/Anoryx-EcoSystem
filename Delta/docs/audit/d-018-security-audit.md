# D-018 Security Audit — Automated Invoicing + Vendor Payment Reconciliation: A PO-Backed Three-Way Match

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/invoicing/` (the entire new package — `schemas.py`,
  `store.py`, `service.py`, `router.py`), `Delta/src/delta/persistence/migrations/
  versions/0012_invoicing_reconciliation.py` (new `invoices`/`invoice_payments` tables,
  RLS, grants, CHECK constraints, composite tenant-scoped FKs), the additive-only changes
  to `Delta/src/delta/identifiers.py` (`InvoiceId`, `InvoicePaymentId`) and
  `Delta/src/delta/persistence/models.py` (the two new `Table` objects), the one new
  router mount in `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/invoicing/`
  (read for coverage/gaps), the new frontend surface (`Delta/frontend/src/app/(admin)/
  invoicing/`, `Delta/frontend/src/components/invoicing/`, and the additive changes to
  `types.ts`/`admin-client.ts`/`bff.ts`), and `Delta/docs/adr/0018-delta-invoicing-
  reconciliation.md` (the design record, cross-checked against the actual shipped code —
  not trusted on its own account).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified). This
  feature is a genuine money-movement financial control (a three-way match whose entire
  reason to exist is to prevent over-billing and overpayment), so it received the full
  10-vector adversarial treatment from the task brief: auth bypass, the over-invoicing
  guard, the payment race guard, cross-tenant leakage, the milestone-task proof, the
  vendor/PO/currency matching guards, the decision/payment-after-dispute races, audit-chain
  wiring, frontend token/injection handling, and input validation. The two guard invariants
  the ADR claims are "structurally impossible" to breach (Fork 1's over-invoicing ceiling
  and Fork 3's overpay guard) were each exercised against the live local Postgres under real
  concurrency with a purpose-written attack harness, not assessed by code reading alone. A
  Semgrep-equivalent local ruleset pass was performed; the registry fetch is blocked by the
  environment's egress policy (the same known limitation recorded in every prior audit this
  session), so `p/python`/`p/security-audit`/`p/secrets` could not be pulled — the manual
  data-flow review below stands in for those rulesets on the changed files.
- **Verdict:** **BLOCK at initial review** — one **High** finding (the over-invoicing
  ceiling, ADR-0018 Fork 1's central invariant, was bypassable under trivial concurrency
  and was reproduced live: 10x over-commitment against one PO). One Medium and three Low
  findings accompanied it. **Post-fix status: RESOLVED.** Findings 1 and 2 were fixed
  (a `SELECT ... FOR UPDATE` row lock on the PO closes the TOCTOU window; a
  `PaymentCurrencyMismatchError` guard rejects a payment whose currency doesn't match its
  invoice) and each fix was independently re-verified against the live database with a
  dedicated concurrency/mismatch regression test (`test_concurrent_invoice_creation_
  never_exceeds_po_commitment`, `test_record_payment_currency_mismatch_raises`) — see the
  "Post-fix verification" section below. Findings 3-5 (Low) were partially addressed
  (Finding 4's `ge=0` tightened to `gt=0`) or accepted as noted in their own rows; none
  blocked merge on their own. This diff is cleared to proceed.

## What was actively tried and found sound

- **Authentication bypass (vector 1).** Every route is gated by the router-level
  `dependencies=[Depends(require_admin)]` (`invoicing/router.py:45`) — the same break-glass
  bearer check every non-dashboards admin surface uses. No per-route opt-out exists; the
  four mutating routes and three GET routes all inherit it. No unauthenticated path to any
  invoicing route was found.
- **The payment race guard (vector 3).** `store.try_record_payment` is a SINGLE atomic
  `UPDATE ... SET amount_paid = amount_paid + :amt, status = CASE ... WHERE status IN
  ('approved','partially_paid') AND amount_paid + :amt <= amount_minor_units RETURNING
  status`. This is genuinely race-safe: Postgres row-level locking serializes concurrent
  updates on the single invoice row, and the computed WHERE re-reads the freshly-committed
  total, so two concurrent payments can never together overpay. The schema also backstops
  it with `CHECK (amount_paid_minor_units <= amount_minor_units)`. Amount coercion is sound:
  `amount_minor_units` is `Field(gt=0, le=1e11)` plus `reject_non_integer` (bool and float
  both rejected), so `0`, negatives, `True`, floats, and unbounded values are all refused at
  the schema, and the DB `CHECK (amount_minor_units > 0)` is an independent backstop. No gap
  found in the payment-overpay guard itself.
- **Cross-tenant leakage (vectors 4 & 5).** Verified live: from tenant A, an invoice that
  cites tenant B's genuinely-`done` milestone task is rejected `MilestoneTaskNotFoundError`
  (B's task is invisible under A's RLS session), and an invoice against tenant B's vendor/PO
  is rejected `VendorNotFoundError`. `invoices`/`invoice_payments` carry the same fail-closed
  `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')` RLS predicate as
  every prior migration, `FORCE ROW LEVEL SECURITY`, and composite tenant-scoped FKs
  (`(vendor_id, tenant_id)`, `(po_id, tenant_id)`, `(invoice_id, tenant_id)`) that
  structurally prevent a cross-tenant reference even with RLS disabled. Every cross-table
  read (`get_vendor_status`, `get_purchase_order_summary`, `get_task_status`,
  `compute_vendor_reconciliation`) runs inside the caller's `get_tenant_session`, so all are
  RLS-confined. No cross-tenant leak found.
- **The vendor/PO/currency matching guards (vector 6).** `create_invoice` checks, in order,
  vendor existence, PO existence, `po.vendor_id == req.vendor_id`, `po.status == "approved"`,
  and `po.currency == req.currency` before any write — an invoice against an unapproved PO, a
  different vendor's PO, or a mismatched currency is refused. Confirmed by the suite and by
  the mismatch probes above.
- **The milestone-task proof (vector 5).** A claimed `milestone_task_id` must resolve to a
  task whose live status is exactly `'done'`; a missing task → `MilestoneTaskNotFoundError`,
  a not-done task → `MilestoneTaskNotDoneError`. The task is read under the caller's RLS
  session, so a foreign-tenant task cannot be cited (verified live).
- **Decision race / payment-after-dispute (vector 7).** `try_decide_invoice`'s conditional
  UPDATE only matches a row still `'submitted'`, so a second concurrent decision returns
  `rowcount == 0` → `InvoiceAlreadyDecidedError` (409). A payment against a `submitted`,
  `disputed`, or `paid` invoice cannot match `try_record_payment`'s `status IN
  ('approved','partially_paid')` WHERE clause, so a disputed or undecided invoice can never
  receive a payment. Both sound.
- **Audit-chain wiring (vector 8).** All three mutating actions (`create_invoice`,
  `decide_invoice`, `record_payment`) call `append_history(...)` in the SAME transaction as
  the business write, before the single `session.commit()`. A rollback of the business write
  rolls back the audit row with it — no desync window. Submission audits as `submitted`,
  decision as `approved`/`disputed`, payment as `payment_recorded`; entity types `invoice`/
  `invoice_payment`. Coverage matches ADR-0018 Fork 7's claim.
- **Frontend token handling & injection (vector 9).** The raw `DELTA_ADMIN_TOKEN` is injected
  only server-side in `bff.ts` (`Authorization: Bearer ${adminToken()}`) and via the
  `server-only` `admin-client.ts`; it is never accepted from the request nor echoed into a
  response body, and never reaches the browser. `bff.ts`'s `ALLOWED_ROOTS` correctly includes
  `"invoicing"`, and the traversal guard (rejecting `..`/`.`/`/`/`\`) plus `encodeURIComponent`
  on each segment cover the new root. Every free-text field (`invoice_number`, `description`,
  `submitted_by`, `decided_by`, `status`) is rendered as escaped JSX text — no
  `dangerouslySetInnerHTML`, no raw HTML sink — so no stored-XSS path to the DOM was found.
- **Input validation / log injection (vector 10).** `extra="forbid"` on every request DTO;
  `_reject_control_chars` (incl. newlines) on `invoice_number`/`description`/`submitted_by`/
  `actor`/`note`/`recorded_by`, blocking log-injection into the D-009 chain's `actor`/`note`;
  bounded lengths on all free text; `require_aware_utc` on `paid_at`. SQL is exclusively
  parameterized SQLAlchemy Core — no string-interpolated SQL anywhere in `invoicing.store`.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | **High** → **FIXED** | `invoicing/service.py` (`create_invoice`), `invoicing/store.py` (`get_purchase_order_summary_for_update`, new) | **The over-invoicing ceiling (ADR-0018 Fork 1) was a TOCTOU race and was bypassable under trivial concurrency.** Unlike payment recording (a single atomic conditional UPDATE), invoice creation was a read-then-compare-then-insert: it `SELECT SUM(...)`d prior non-disputed invoices for the PO, compared in Python, then `INSERT`d — with no row lock on the PO, no `SERIALIZABLE` isolation, and no uniqueness/exclusion constraint serializing concurrent submissions. Each request ran in its own pooled `delta_app` connection at READ COMMITTED, so none saw the others' uncommitted inserts; all passed the check and all committed. The `pg_advisory_xact_lock(hashtext(tenant_id))` taken inside `append_history` did NOT help — it is acquired *after* the sum-check and the invoice insert. **Reproduced live (pre-fix):** 10 concurrent invoices each claiming the full 100,000-minor-unit PO ceiling ALL succeeded, leaving 1,000,000 invoiced against a 100,000 committed PO — a 10x over-commitment. | **FIXED.** `create_invoice` now calls `store.get_purchase_order_summary_for_update` — a `SELECT ... FOR UPDATE` that locks the PO row for the rest of the transaction — before the sum-check, so a second concurrent submission against the SAME PO blocks at lock acquisition until the first commits or rolls back; its own sum-check then correctly sees the first's already-committed invoice. **Re-verified live post-fix:** the identical 10-concurrent-submission attack now yields exactly 1 success, 9 rejections (`InvoiceExceedsPurchaseOrderError`), total invoiced == 100,000 == the PO's committed amount. Regression test added: `test_concurrent_invoice_creation_never_exceeds_po_commitment`. ADR-0018 Fork 1 and §4 updated to describe the lock instead of the (inaccurate) prior "structurally impossible" claim. |
| 2 | Medium → **FIXED** | `invoicing/service.py` (`record_payment`) | **A payment's currency was never validated against the invoice's currency.** `create_invoice` enforced `invoice.currency == po.currency`, but `record_payment` accepted `req.currency` and incremented `amount_paid_minor_units` regardless of whether it matched the invoice. **Reproduced live (pre-fix):** a payment labelled `JPY`, amount 100,000, against a `USD` invoice of 100,000 was accepted and rolled the invoice straight to `paid`, silently corrupting `compute_vendor_reconciliation`'s per-currency sums. | **FIXED.** `record_payment` now reads the invoice first and raises the new `PaymentCurrencyMismatchError` (mapped to HTTP 422) if `req.currency != invoice.currency`, before the atomic amount-guard UPDATE runs — mirrors the invoice↔PO currency guard (Fork 3). Currency is immutable per invoice (never concurrently written), so this plain read-then-check introduces no new race; the amount guard remains the single atomic UPDATE. **Re-verified live post-fix:** the identical JPY-against-USD-invoice attempt is now rejected 422 and `amount_paid_minor_units` stays 0. Regression test added: `test_record_payment_currency_mismatch_raises`. |
| 3 | Low | `invoicing/router.py` (`get_reconciliation`) | The `currency` query parameter was typed `str = DEFAULT_CURRENCY`, not the ISO-4217-constrained `Currency` type used on every write DTO. Arbitrary garbage (e.g. `currency=usd` or `currency=XXXX`) was accepted and silently yielded an all-zero report rather than a 422. No injection risk (fully parameterized), but it was inconsistent with every other currency surface and could mask an operator typo as a (misleading) empty reconciliation. | **FIXED.** The parameter is now typed `Currency`, so a malformed code returns 422, matching the write paths. |
| 4 | Low → **FIXED** | `invoicing/schemas.py` (`InvoiceCreateRequest.amount_minor_units`) | Invoice amount was `Field(ge=0, ...)`, permitting a `0`-amount invoice. A zero invoice can never be paid (payment amount is `gt=0` and `0 + amt <= 0` never holds), so it sat `approved` forever and added a zero row to the invoiced total — harmless, but noise, and inconsistent with the payment field's `gt=0`. | **FIXED.** Tightened to `Field(gt=0, ...)`, matching `PaymentRecordRequest.amount_minor_units`. No security impact; fixed for consistency. |
| 5 | Low | `frontend/src/lib/bff.ts` (adding `"invoicing"` to `ALLOWED_ROOTS`) | The BFF injects the break-glass `DELTA_ADMIN_TOKEN` for any authenticated frontend session, and break-glass is implicit `require_admin` for every tenant — so any logged-in operator can submit/decide/pay invoices for ARBITRARY tenants through the frontend. Identical trust model to every other admin surface reachable through the BFF (allocations, crm, erp, rbac, …); not a D-018 regression. | **Accepted as by-design**, matching the same boundary flagged as Low #1 in the D-017 audit and named in ADR-0017 §3 / ADR-0018 Fork 6 (no RBAC retrofit on this surface). Reconsider when real per-operator identity (F-014 federation) lands. No code change required for this reason alone. |

## Post-fix verification

All four fixable findings (1, 2, 3, 4) were implemented and re-verified after this audit's
initial pass:

- **Finding 1 (High).** `store.get_purchase_order_summary_for_update` (a `SELECT ... FOR
  UPDATE`) added; `create_invoice` now locks the PO row before its sum-check. Re-ran the
  identical live attack (10 concurrent full-ceiling invoice submissions against one PO):
  now exactly 1 succeeds, 9 are rejected `InvoiceExceedsPurchaseOrderError`, and the total
  invoiced against the PO never exceeds its committed amount. New regression test
  `test_concurrent_invoice_creation_never_exceeds_po_commitment` passes.
- **Finding 2 (Medium).** `PaymentCurrencyMismatchError` added; `record_payment` now rejects
  a payment whose currency doesn't match its invoice's, before the atomic amount-guard
  UPDATE runs. Re-ran the identical live attack (a JPY payment against a USD invoice): now
  rejected 422, `amount_paid_minor_units` stays 0. New regression test
  `test_record_payment_currency_mismatch_raises` passes.
- **Finding 3 (Low).** `get_reconciliation`'s `currency` query parameter retyped from `str`
  to the ISO-4217-constrained `Currency` type.
- **Finding 4 (Low).** `InvoiceCreateRequest.amount_minor_units` tightened from `ge=0` to
  `gt=0`.
- **Finding 5 (Low).** No code change — accepted as by-design, matching D-017's own
  identical trust-boundary note.

Full `tests/invoicing/` suite re-run post-fix: 54 passed (52 pre-existing + 2 new regression
tests), 0 failed. Full repo suite re-run post-fix: 839 passed, 15 skipped — zero regressions
(the earlier 836-passed/3-errored run mixed two concurrent pytest invocations colliding on
role provisioning against the same local Postgres, not a real failure; a clean single run
post-fix is the authoritative count). `black --check .` / `ruff check .` clean on the full repository
after the fix. This diff is cleared to proceed — the header verdict above reflects this
post-fix state (RESOLVED), not the initial BLOCK.

## Threat model cross-reference

See `docs/adr/0018-delta-invoicing-reconciliation.md` §4 for the vectors-to-mitigations-to-
tests table this audit validated against (now updated post-fix). Every row was independently
re-checked, not merely trusted against the ADR's own account. Two rows did **not** hold as
originally claimed: the row asserting "An invoice (or the sum of several) claims more than
its PO committed" was mitigated only by a create-time sum check that was **not
concurrency-safe** and was breached live (Finding 1); and the implicit currency-integrity
assumption behind the per-vendor single-currency reconciliation was broken on the payment leg
(Finding 2). Both are now fixed and re-verified live (see "Post-fix verification" above). The
remaining rows (payment overpay guard, unapproved/mismatched-PO rejection, false-delivery
rejection, cross-tenant isolation, decision race, payment-after-dispute, audit-chain wiring,
control-char rejection, SQLi) each held under live testing from the initial pass.

## Honesty boundary

This review covers only the D-018 invoicing surface listed under Scope. It does not re-audit
`allocation_admin.auth.require_admin`, `delta.persistence.database.get_tenant_session`, or
`delta.persistence.audit_log.append_history` (all unchanged and audited under prior tasks) —
D-018 reuses them unmodified and this review confirmed it does so correctly (the audit append
is in-transaction; the tenant GUC is transaction-local and fail-closed). Per ADR-0018 §3 this
is a deliberately bounded slice — no D-003 ledger wiring, no external ERP/bank-feed sync, no
RBAC gating, no FX — and it was assessed as that bounded slice, not against those deferred
scopes. I did not verify Semgrep registry rulesets (egress-blocked, noted above); the manual
data-flow review substitutes on the changed files. Consistent with house style: this pass
found no cross-tenant, auth-bypass, or secret-exposure defects, but it did find one genuine
High integrity defect (Finding 1) and one Medium (Finding 2) — I am not calling the initial
diff "secure." Both were fixed and independently re-verified live against the same attack
that originally broke them (see "Post-fix verification" above), not merely re-read — this is
the arms-length re-check the process requires before treating a High finding as closed, not
a soft downgrade of the original verdict.
