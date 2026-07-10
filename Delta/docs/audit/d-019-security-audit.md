# D-019 Security Audit — Corporate ERP/Procurement/Cloud-Cost Sync Connectors: A Registration + Sync-Ingestion + Reconciliation-Matching Framework

- **Date:** 2026-07-10
- **Scope:** `Delta/src/delta/integrations/` (the entire new package — `schemas.py`,
  `store.py`, `service.py`, `router.py`), `Delta/src/delta/persistence/migrations/
  versions/0013_erp_integrations.py` (new `external_systems`/`sync_runs`/
  `sync_line_items` tables, RLS, INSERT/SELECT-only grants, CHECK constraints,
  composite tenant-scoped FKs), the additive-only changes to
  `Delta/src/delta/identifiers.py` (`ExternalSystemId`, `SyncRunId`, `SyncLineItemId`)
  and `Delta/src/delta/persistence/models.py` (the three new `Table` objects), the one
  new router mount in `Delta/src/delta/allocation_admin/app.py`,
  `Delta/tests/integrations/` (read for coverage/gaps), the new frontend surface
  (`Delta/frontend/src/app/(admin)/integrations/`,
  `Delta/frontend/src/components/integrations/`, and the additive changes to
  `types.ts`/`admin-client.ts`/`bff.ts`). ADR-0019 does not yet exist at review time
  (`docs/adr/0019-delta-erp-integrations.md` absent) — the code was reviewed on its own
  merits, cross-checked against the ADR-0018/D-018 conventions it claims to mirror.
- **Reviewer:** independent security-auditor pass, arms-length from the implementer —
  the code was re-run and attacked against the live local Postgres, not assessed by
  reading alone. The task brief's cautionary note (D-018's audit found a genuine High
  TOCTOU race in a read-then-compare-then-insert with no row lock) drove a specific,
  deliberate hunt for the SAME bug class here. The full 10-vector treatment from the
  brief was applied: auth bypass, cross-tenant leakage (systems/runs/line-items/
  reconciliation), the ID-based matching guards, the read-then-insert concurrency
  angle, the `records_ingested` count-bookkeeping invariant, input validation
  (float/bool/control-char/batch-size/at-most-one-reference), audit-chain wiring, the
  no-UPDATE-grant design, frontend token/injection handling, and SQLi. A live
  adversarial harness (`scratchpad/attack.py`, transient) exercised the cross-tenant,
  matching-correctness, count-bookkeeping, and grant-enforcement claims directly. A
  Semgrep registry pull (`p/python`/`p/security-audit`/`p/secrets`) is blocked by this
  environment's egress policy (the same known limitation recorded in every prior audit
  this session); the manual data-flow review below substitutes on the changed files.
- **Verdict:** **CLEAN — no High/Critical findings in this pass.** Unlike D-018, the
  new write path structurally *lacks* the ingredient that made D-018's ceiling a race:
  there is no shared running total, no cross-row ceiling, and no read-then-compare-
  then-insert against mutable state — each line item's match is an independent,
  read-only ID lookup against PO/invoice data this feature never mutates, and the
  `records_ingested` invariant is satisfied by construction (the stored value is
  literally the sum of the four buckets, and each line item increments exactly one
  bucket). The D-018 TOCTOU class is therefore *absent by construction here*, and this
  was confirmed by reasoning and by the live harness, not merely assumed. Three **Low**
  findings are recorded below; none blocks merge and none is a confidentiality,
  integrity, auth, or secret-exposure defect. This diff is cleared to proceed.

## What was actively tried and found sound

- **Authentication bypass (vector 1).** Every route is gated by the router-level
  `dependencies=[Depends(require_admin)]` (`integrations/router.py:30`) — the same
  break-glass bearer check every non-dashboards admin surface uses. All six routes
  (two mutating, four read) inherit it; no per-route opt-out. No unauthenticated path
  to any integrations route exists.
- **Cross-tenant leakage — the headline concern (vectors 2 & 4).** Verified LIVE: from
  tenant A, a sync line item citing tenant B's genuinely-existing, amount/currency-exact
  purchase order resolves to `not_found`, never `matched` — B's PO is invisible under
  A's `get_tenant_session(A)` RLS session, so `get_purchase_order_for_match` returns
  `None`. Every cross-table read (`get_purchase_order_for_match`,
  `get_invoice_for_match`) and every list/reconciliation read runs inside the caller's
  own tenant-scoped session, and `external_systems`/`sync_runs`/`sync_line_items` each
  carry the identical fail-closed `tenant_id = NULLIF(current_setting(
  'app.current_tenant_id', true), '')` RLS predicate, `FORCE ROW LEVEL SECURITY`, and
  composite tenant-scoped FKs (`sync_runs.(system_id, tenant_id)`,
  `sync_line_items.(sync_run_id, tenant_id)`) that structurally prevent a cross-tenant
  reference even with RLS disabled. A `system_id` belonging to another tenant resolves
  to `SystemNotFoundError` → 404 under the caller's RLS session. No cross-tenant read,
  match, or write path was found.
- **Matching correctness (vector 3).** Verified LIVE against one approved PO: an exact
  amount+currency line → `matched`; a 1-minor-unit-off amount → `amount_mismatch`; a
  same-amount but `EUR`-vs-`USD` line → `amount_mismatch`; a no-reference line →
  `unreconciled`. The match is `target.amount_minor_units == item.amount_minor_units
  and target.currency == item.currency` on exact integers and uppercase ISO-4217
  strings — no float, no off-by-one, no coercion. The currency-case attack ("usd" vs
  "USD") is blocked one layer earlier: the `Currency` type's `^[A-Z]{3}$` pattern
  rejects a lowercase code at ingress (verified), so a case-mismatched-but-equal
  comparison can never even be constructed.
- **The D-018 TOCTOU class (vector 4) — structurally absent.** `run_sync` reads each
  referenced PO/invoice (a `SELECT` of amount+currency) then INSERTs line items and a
  run row. Unlike D-018's invoice creation, there is NO shared running total, NO
  cross-submission ceiling, and NO compare-against-mutable-state: the PO/invoice rows
  are read-only here and are not mutated by this feature, so a concurrent second sync
  observes the same immutable amount/currency and reaches the same verdict. Two
  concurrent runs create independent run/line-item rows; `compute_system_reconciliation`
  is a pure read aggregation. Even a concurrent PO approval (the only mutation on a PO)
  changes only `status`, which this feature never reads for the match — the amount is
  immutable. There is no invariant two racers can jointly violate, so no row lock is
  needed and none is missing. This is the reasoned distinction the brief asked for, and
  it holds.
- **Count bookkeeping / the `records_ingested` CHECK (vector 5).** `records_ingested`
  is computed in `store.create_sync_run` as exactly `matched + mismatched + not_found +
  unreconciled`, so the DB `CHECK (records_ingested = ...)` is satisfied by
  construction, never by a second count that could drift. Each line item increments
  exactly one bucket (`counts[matched_status] += 1`, and `_match_line_item` returns only
  the four keys the dict holds — no KeyError, no uncounted status), and the SAME
  `matched_status` computed for the count is the one stored on the row. Verified LIVE: a
  4-item batch (1 match / 1 amount-mismatch / 1 currency-mismatch / 1 unreconciled)
  produced `ingested=4, matched=1, mismatched=2, not_found=0, unreconciled=1`, and the
  stored line-item statuses matched the counters exactly. No drift path found.
- **Input validation / log injection (vector 6).** `extra="forbid"` on every request
  DTO; `_reject_control_chars` (incl. newlines) on `name`/`vendor_label`/
  `external_reference`/`triggered_by`/`note`, blocking log-injection into the D-009
  chain's `actor`/`note`; strict-integer money via `reject_non_integer` (verified LIVE:
  float `100.0`, `bool True`, and negative all rejected); `amount_minor_units` bounded
  `[0, 1e11]`; the `MAX_LINE_ITEMS_PER_SYNC=500` cap enforced by
  `Field(max_length=500)` (verified LIVE: a 501-item batch is rejected). The "at most
  one of po_id/invoice_id" `model_validator` cannot be bypassed by whitespace/case (the
  ids are strict UUID-pattern strings) or by an extra wire field (`extra="forbid"`) —
  verified LIVE that supplying both is rejected.
- **Audit-chain wiring (vector 7).** `run_sync` calls `append_history(entity_type=
  "sync_run", action="completed", actor=req.triggered_by, ...)` in the SAME transaction
  as the run/line-item writes, before the single `session.commit()` — a rollback of the
  business write rolls back the audit row with it (no desync window). The note is built
  only from integer counters (no injectable free text). External-system registration is
  deliberately NOT audited, mirroring D-014's un-audited vendor creation (directory
  metadata, not a financial/integrity event) — a defensible, documented choice.
- **The no-UPDATE-grant design (vector 8).** Verified LIVE as `delta_app`: a bare
  `UPDATE delta.external_systems / sync_runs / sync_line_items` is denied
  (`ProgrammingError`, permission denied) on all three tables — the migration grants
  only `SELECT, INSERT`. Every row is genuinely write-once. See Finding 3 for the one
  functional (not security) consequence.
- **Frontend token handling & injection (vector 9).** The raw `DELTA_ADMIN_TOKEN` is
  injected only server-side in `admin-client.ts` (marked `server-only`, so a client
  import is a build error) and in the `bff.ts` proxy; it is never accepted from the
  request, never echoed into a response body, and never reaches the browser. Every
  free-text field (`name`, `vendor_label`, `triggered_by`, `external_reference`,
  `status`, `system_type`) is rendered as escaped JSX text — no
  `dangerouslySetInnerHTML`, no raw HTML sink — so no stored-XSS path to the DOM was
  found. `bff.ts`'s `ALLOWED_ROOTS` correctly includes `"integrations"`, and the
  traversal guard (rejecting `..`/`.`/`/`/`\`) plus `encodeURIComponent` on each
  segment cover the new root.
- **SQL injection (vector 10).** Every query is a parameterized SQLAlchemy Core
  statement (`select`/`insert` with bound `.where(...)`/`.values(...)`); there is no
  string-interpolated SQL anywhere in `integrations.store`. Identifiers are constrained
  UUID-pattern strings before they reach the store.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `tests/integrations/conftest.py` (`provision_app_role`, autouse per-test) + suite ordering | The suite is **order-dependent**: it passes cleanly 38/38 under deterministic ordering and every test passes in isolation, but under `pytest-randomly`'s default shuffle it intermittently errors/fails with Postgres `tuple concurrently updated` and downstream `target is None`/match assertions. Root cause is harness, not product: the autouse `provision_app_role` fixture runs `ALTER ROLE delta_app WITH LOGIN PASSWORD ...` on **every** test, contending on the `pg_authid` catalog row (and colliding outright if two pytest invocations share the Postgres, exactly the flake D-018's audit already documented). No product code path is implicated — the reconciliation, RLS, and matching logic were all independently re-verified live. | **Accepted as a known, pre-existing test-harness robustness issue**, identical in shape to the one recorded in `docs/audit/d-018-security-audit.md` (the "two concurrent pytest invocations colliding on role provisioning" note). Recommend (non-blocking) hoisting `provision_app_role` to a session-scoped fixture so the `ALTER ROLE` runs once, and asserting order-independence in CI. No product change; no security impact. |
| 2 | Low | `frontend/src/lib/bff.ts` (adding `"integrations"` to `ALLOWED_ROOTS`) + `router.py` (`require_admin` only) | The BFF injects the break-glass `DELTA_ADMIN_TOKEN` for any authenticated frontend session, and break-glass is implicit `require_admin` for **every** tenant — so any logged-in operator can register systems and run syncs (which write audit rows and reconcile against POs/invoices) for **arbitrary** tenants by supplying that `tenant_id` in the request body. Identical trust model to every other admin surface reachable through the BFF (allocations, crm, erp, rbac, invoicing, …); not a D-019 regression. | **Accepted as by-design**, matching the same boundary accepted as Low in the D-017 and D-018 audits (no RBAC retrofit on this surface). RLS still confines each request to the single `tenant_id` it declares — this is a *who-can-act-as-any-tenant* authorization scope, not a cross-tenant *leak* (a request scoped to tenant A cannot read tenant B's data). Reconsider when real per-operator identity (F-014 federation) lands. No code change required for this reason alone. |
| 3 | Low | `migration 0013` (SELECT/INSERT-only grants) + `service.run_sync` (`SystemDisabledError`) | The `status` column and the `SystemDisabledError` / 409 "disabled" branch are **effectively dead** through the app: `status` is only ever written `'active'` at INSERT, and `delta_app` has no UPDATE grant, so there is **no service-level way to disable a registered connector**. A system that should be decommissioned (or whose `vendor_label` was a mistake) keeps accepting sync ingestion until a privileged BYPASSRLS session flips it by hand. This is a functional/operational completeness gap, not a security hole — it fails *safe* (writes stay tenant-scoped and audited; nothing is *over*-permitted), and the write-once design it stems from is exactly what makes the tables tamper-resistant. | **Accepted as a documented, deliberate deferral** (the migration docstring and the task brief both call out "no service-level disable action yet; status can only be flipped via a privileged session"). Recommend (non-blocking) either adding a narrow, audited `POST /systems/{id}/status` disable action with a scoped UPDATE grant, or removing the unreachable `SystemDisabledError` branch to avoid implying a capability that does not exist. No security impact. |

## Threat model cross-reference

No ADR-0019 exists at review time, so there is no ADR threat-model table to validate
against; this audit instead re-checked the code against the ten brief vectors and the
ADR-0018 conventions the code claims to mirror. Every vector was exercised — four of
them (cross-tenant matching, matching correctness, count bookkeeping, and grant
enforcement) with a live adversarial harness against the local Postgres, not by reading
alone. The one vector the brief flagged as the highest-risk carry-over from D-018 (the
read-then-insert TOCTOU class) does **not** reproduce here, and the reason is
structural, not incidental: there is no shared ceiling or mutable-state compare in this
write path, so there is no window for two racers to jointly break an invariant (see
"What was actively tried and found sound," vector 4). When ADR-0019 is written, it
should state this distinction explicitly rather than claiming a lock it does not need.

## Honesty boundary

This review covers only the D-019 integrations surface listed under Scope. It does not
re-audit `allocation_admin.auth.require_admin`,
`delta.persistence.database.get_tenant_session`, or
`delta.persistence.audit_log.append_history` (all unchanged and audited under prior
tasks) — D-019 reuses them unmodified and this review confirmed it does so correctly
(the audit append is in-transaction; the tenant GUC is transaction-local and
fail-closed; the append advisory-locks per tenant). Per the task's own framing this is a
deliberately bounded slice — a registration + synchronous ingestion + ID-match
framework, explicitly NOT live OAuth/API integrations with NetSuite/SAP/Coupa/Ariba/
AWS/GCP/Azure (no third-party credentials exist in this environment) — and it was
assessed as that bounded slice, not against those deferred integrations. I did not
verify Semgrep registry rulesets (egress-blocked, noted above); the manual data-flow
review substitutes on the changed files. Consistent with house style: this pass found
no cross-tenant, auth-bypass, matching-integrity, count-drift, or secret-exposure
defect, and — unlike the D-018 pass — no High or Medium either; I am not calling the
diff "secure," I am reporting **no High/Critical findings in this pass** plus three Low
items that do not block merge. The absence of the D-018 TOCTOU here was confirmed by
live attack and by structural reasoning about the write path, not assumed from the
feature's synchronous framing.
