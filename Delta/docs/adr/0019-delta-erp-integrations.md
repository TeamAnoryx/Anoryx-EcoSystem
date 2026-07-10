# ADR-0019 — Corporate ERP/Procurement/Cloud-Cost Sync: A Generic Ingestion + Reconciliation-Matching Framework

- **Status:** Accepted
- **Date:** 2026-07-10
- **Task:** D-019 (Corporate ERP integrations) · Builder: orchestration-hooks ·
  Phase 3 (post-investment vision) — the seventh task built past Delta's committed
  MVP (D-001→D-012), continuing directly after D-018 per the standing "complete all
  post-investment tasks" instruction.
- **Depends on:** D-014 (`delta.erp` — purchase orders are one of two reconciliation
  targets), D-018 (`delta.invoicing` — invoices are the other).
- **Builds on:** ADR-0018's own honesty boundary, which explicitly named "real
  continuous reconciliation against an actual bank feed or corporate ERP system" as
  D-019's job — this task is the direct continuation of that named deferral.
- **Supersedes:** nothing. Adds a new `delta.integrations` package, three new tables
  (`external_systems`, `sync_runs`, `sync_line_items`) via migration 0013, one new
  router mount to `allocation_admin/app.py`. No existing D-007–D-018 file's runtime
  behavior is modified.

## 1. Context

The roadmap's literal text for D-019 is: *"Seamless integration with corporate ERPs
for continuous ledger reconciliation; cloud cost sync; procurement,"* naming SEVEN
specific third-party systems in its title — NetSuite, SAP, Coupa, Ariba, AWS, GCP,
Azure — at *"28h+ each."* Taken at face value this means building seven live
OAuth/API integrations, each with its own authentication flow, rate limits, webhook
or polling model, and vendor-specific data shape. This unattended task cannot
responsibly do that: there are no real NetSuite/SAP/Coupa/Ariba/AWS/GCP/Azure
credentials in this environment, and fabricating a "live" integration against a
system that doesn't actually exist here would be dishonest — either a stub dressed
up as a connector, or untested code claiming a capability nobody has verified. This
ADR applies the same discipline every prior D-013→D-018 ADR established: build the
part that is genuinely real and testable — a generic external-system registration +
sync-ingestion + reconciliation-matching FRAMEWORK, reusing D-014's purchase orders
and D-018's invoices as the Delta-side target — and name the seven live connectors as
the concrete, well-defined future work this framework exists to receive.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — a generic ingestion endpoint, not seven vendor-specific connectors** | `POST /v1/admin/integrations/systems/{id}/sync` accepts a batch of caller-supplied line items (`external_reference`, `amount_minor_units`, `currency`, optionally one of `po_id`/`invoice_id`) in a single normalized shape. A future NetSuite (or SAP, Coupa, Ariba, AWS Cost Explorer, ...) connector's entire job would be: authenticate to that vendor's real API, fetch its data, normalize it into this exact shape, and POST it here — this task builds and tests that receiving half completely; the per-vendor fetching half is out of scope and named explicitly in §3. | This is the only honest way to make measurable, testable progress on a "28h+ each, seven systems" item in one unattended pass: build the shared mechanism every future connector will need once, correctly and with real tests, rather than seven untested stubs. |
| **2 — reconciliation matching is precise ID-based comparison, not fuzzy heuristics** | A line item that supplies `po_id` (or `invoice_id`) is matched by looking up that EXACT record under the caller's own tenant-scoped RLS session and comparing `amount_minor_units`/`currency` exactly — `'matched'` iff both are equal, `'amount_mismatch'` otherwise, `'not_found'` if the ID doesn't resolve. No vendor-name substring matching, no "close enough" amount tolerance, no date-proximity heuristics. | Fuzzy matching is a real, separate engineering problem (deciding tolerance thresholds, handling near-duplicate vendor names) that trades false precision for false confidence — a wrong "smart" match is worse than an honest "not found." A future connector is expected to know Delta's own `po_id`/`invoice_id` (via whatever ID-mapping bookkeeping it maintains, a standard integration pattern), making precise matching both correct and simple. |
| **3 — a line item with NEITHER `po_id` nor `invoice_id` resolves `'unreconciled'`, not an error** | `SyncLineItemInput` allows both fields to be omitted; `_match_line_item` returns `("unreconciled", None, None)` in that case — a valid, expected outcome, not a validation failure. | This is the honest, structural answer to `cloud_cost`-type line items (an AWS/GCP/Azure charge has no Delta-side purchase order or invoice to compare against — Delta doesn't track its own cloud infrastructure spend anywhere). Forcing every line item to reference something would either reject legitimate cloud-cost data or invite a caller to fabricate a spurious reference just to satisfy the shape. |
| **4 — fully synchronous ingestion; no run-level failure/retry state** | `run_sync` matches every line item, then writes ONE `sync_runs` row (with `records_matched`/`records_mismatched`/`records_not_found`/`records_unreconciled` counts) plus one `sync_line_items` row per input, all before a single `session.commit()`. There is no `status` column on `sync_runs` — a row's existence means it completed; there is nothing else it could mean, since the data is supplied directly by the caller with no live external I/O to fail partway through. | Avoids designing dead machinery for a failure mode that cannot occur in THIS task's scope (mirrors "don't design for hypothetical future requirements" — a `status` field with only one ever-observed value would be speculative). When a real per-vendor connector adds genuine external I/O (network calls, rate limits, partial-batch failures), that is the natural point to add a run-level status/retry model — named in §3, not built prematurely here. |
| **5 — no UPDATE grant on any of the three new tables** | Migration 0013 grants `delta_app` SELECT+INSERT only, on `external_systems`, `sync_runs`, AND `sync_line_items` — no UPDATE, no DELETE anywhere in this feature. Every row is written once and never revised. | The simplest possible write pattern this session has shipped: with no shared running total (unlike D-018's `amount_paid_minor_units`) and no decision state to transition (unlike D-007/D-013/D-014/D-018's propose→decide shapes), there is no concurrent-mutation race to guard against at all — Fork 5 is a direct, structural response to D-018's own audit-confirmed TOCTOU lesson: the safest way to avoid a mutation race is to have no mutation. |
| **6 — `delta.integrations` is gated by `require_admin` only, NOT retrofitted with D-017's RBAC** | `integrations/router.py`'s router-level dependency is `Depends(require_admin)` — the same break-glass bearer every surface except D-008's dashboards uses. | Mirrors D-018 ADR §2 Fork 6's identical reasoning: D-017's RBAC retrofit was deliberately bounded to D-008's dashboards; D-019 is the eighth surface to correctly stay out of that bounded scope. |
| **7 — a sync run is audited (D-009); external-system registration is not** | `run_sync` calls `append_history(..., entity_type="sync_run", action="completed", ...)` in the same transaction as its writes. `create_external_system` does not. | A sync run is the information-integrity event — it records what an external system claimed and whether Delta's own records agreed. Registering a system is directory/config metadata, mirroring D-014's own vendor creation (also unaudited) — only the PO/invoice DECISIONS that followed were audited there, the same distinction applied here. |
| **8 — mounted on the existing admin app, not a new process** | `POST/GET /v1/admin/integrations/systems`, `POST /systems/{id}/sync`, `GET /systems/{id}/sync-runs`, `GET /sync-runs/{id}/line-items`, `GET /systems/{id}/reconciliation` on the same D-007 admin app. | Same operators, same auth boundary, same trust boundary — mirrors D-008/.../D-018's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No live OAuth/API integration with NetSuite, SAP, Coupa, Ariba, AWS, GCP, or
  Azure.** Zero network calls to any of these systems exist anywhere in this diff.
  The concrete, well-defined future work this framework exists to receive: a
  per-vendor connector authenticates to that vendor's real API (its own OAuth/API-key
  flow), fetches the relevant data (AP invoices, cost-center exports, cloud billing
  line items), normalizes it into `SyncLineItemInput`'s exact shape (`external_reference`,
  `amount_minor_units`, `currency`, optionally `po_id`/`invoice_id` from whatever
  ID-mapping the connector maintains), and calls `POST /systems/{id}/sync` — the
  receiving half this task built and tested end-to-end.
- **No continuous/scheduled sync.** Every sync is a single request-response call —
  there is no cron, background worker, or webhook receiver. A real connector would
  need its own scheduling (a periodic job, or a webhook endpoint for push-based
  vendors), which is part of the per-vendor work named above, not this framework.
- **No fuzzy/heuristic matching.** No vendor-name substring matching, no amount
  tolerance, no date-proximity logic (Fork 2). A caller without Delta's own
  `po_id`/`invoice_id` handy gets an honest `'unreconciled'`, never a guessed match.
- **No system enable/disable action exposed via the API.** `external_systems.status`
  exists in the schema and is checked by `run_sync` (`SystemDisabledError` if not
  `'active'`), but no endpoint can set it to `'disabled'` — only a privileged
  (BYPASSRLS) session can, which is how this task's own tests exercise that path. A
  `POST /systems/{id}/status` action is a small, natural follow-up, not built here.
- **No sync-request idempotency.** Two identical `POST .../sync` calls (e.g. a
  retried request) create two separate `sync_runs` rows with no deduplication —
  mirrors D-007's own break-glass token's noted residual risk pattern of naming a gap
  honestly rather than building unrequested idempotency-key machinery for a
  synchronous, caller-driven endpoint.
- **No FX / multi-currency reconciliation.** A `'matched'` result requires exact
  currency equality (D-001's no-FX rule) — a line item reporting the same real-world
  amount in a different currency than its PO/invoice reads as `'amount_mismatch'`,
  not a converted match.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant leak — a sync line item matches a DIFFERENT tenant's purchase order or invoice | `get_purchase_order_for_match`/`get_invoice_for_match` run inside the caller's own `get_tenant_session(tenant_id)`; RLS makes a foreign-tenant row simply invisible, resolving `'not_found'`, never `'matched'` | `test_run_sync_cannot_match_a_different_tenants_po`, `test_cross_tenant_external_system_is_invisible`, `test_cross_tenant_system_list_isolated_over_http` |
| A line item's reported amount/currency doesn't actually match its referenced PO/invoice, but is accepted as `'matched'` anyway | Exact integer/string equality on both `amount_minor_units` and `currency` — no tolerance, no coercion | `test_run_sync_flags_amount_mismatch` |
| A concurrent-mutation race analogous to D-018's audit-confirmed TOCTOU finding | Structurally absent: `run_sync` has no shared running total or ceiling to check-then-violate (unlike D-018's over-invoicing guard) — every write is an independent INSERT, and `delta_app` has no UPDATE grant at all on any of the three tables (Fork 5), so there is no mutation for two concurrent callers to race on | code review + migration grants (`GRANT SELECT, INSERT` only, verified via `psql`) |
| A sync run's summary counts (`records_matched`/etc.) drift from the actual `sync_line_items` rows written | `run_sync` derives every count from the SAME `matched_items` list it then iterates to insert each line item — the counts and the rows are computed from one pass over one list, not two independently-maintained tallies; the DB `CHECK (records_ingested = records_matched + ... )` constraint is an independent backstop | `test_create_sync_run_and_line_items_roundtrip`, `test_reconciliation_reflects_multiple_line_item_outcomes` |
| A sync run leaves no attributable, tamper-evident trail | Wired into D-009's hash chain in the same transaction as the write (Fork 7) | `test_run_sync_is_audited` |
| A sync is accepted against a disabled external system | `run_sync` checks `system.status != "active"` before matching or writing anything | `test_run_sync_against_disabled_system_raises` |
| Unbounded request body / line-item batch | `SyncRunCreateRequest.line_items` is `Field(min_length=1, max_length=500)` | `test_sync_run_create_request_rejects_too_many_line_items` |
| Both `po_id` and `invoice_id` supplied on one line item (ambiguous match target) | A `model_validator` rejects the combination at the schema layer | `test_sync_line_item_input_rejects_both_references` |
| Control-character / log-injection via `name`/`vendor_label`/`external_reference`/`triggered_by`/`note` | Same `_reject_control_chars` discipline as every prior Delta package | `test_external_system_create_request_rejects_control_chars_in_name`, `test_sync_line_item_input_rejects_control_chars_in_reference`, `test_sync_run_create_request_rejects_control_chars_in_*` |
| SQL injection via any integrations identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.integrations.store` | code review |
| Auth bypass on any of the 5 new routes | Router-level `dependencies=[Depends(require_admin)]` covers all 5 with no per-route opt-out | `test_systems_endpoint_401_without_bearer` |

## 5. Verification

- `black --check .` / `ruff check .` clean on the FULL repository (not just
  `src/delta/integrations` — the explicit lesson carried forward from D-016's own CI
  failure), 258 files.
- New `tests/integrations/` suite: 38 tests — 15 pure schema-validation tests
  (`test_schemas.py`, no DB/I/O), 8 DB-backed store tests (`test_store_db.py`,
  including cross-tenant isolation and the reconciliation-aggregation query), 14
  DB-backed service tests (`test_service_db.py`, covering every matched-status
  outcome, the disabled-system guard, the cross-tenant PO-matching check, and the
  D-009 audit-chain wiring), 4 non-stubbed HTTP e2e tests (`test_router_e2e.py` —
  real ASGI app, real auth, real DB, driving the full flow: D-014 vendor/PO → D-019
  register system → run sync → list line items → reconciliation report).
- Full existing Delta suite green (877 passed, 15 skipped) — zero regressions.
- Migration 0013 applied cleanly against a live local Postgres (`alembic upgrade
  head`), `delta_app` role provisioned exactly as every prior migration's test
  harness does; the no-UPDATE-grant design verified directly (an app-role UPDATE
  attempt against `external_systems` was rejected `InsufficientPrivilegeError` —
  Fork 5's own test had to switch to a privileged/BYPASSRLS session to simulate a
  disabled system, which is itself a confirmation the grant is doing its job).
- Frontend: `tsc --noEmit` clean, `next lint` clean (0 warnings/errors on all new/
  modified files). Live browser smoke test performed against a real running backend
  with real data entered through the UI itself: seeded a vendor + approved PO via
  direct backend calls, logged in via the break-glass token, loaded the (previously
  empty) integrations page, registered an external system through the UI form,
  navigated to its sync-run history, submitted a two-line-item sync through the UI
  (one referencing the real PO by ID, one with no reference) — confirmed the run
  came back with exactly one `matched` and one `unreconciled` line item against the
  live backend, both in the UI and via a direct follow-up API call.
- Independent security-auditor review: verdict **CLEAN** — no High or Critical
  findings. The review specifically hunted for D-018's own audit-confirmed TOCTOU
  bug class (a read-then-compare-then-insert with no row lock) and confirmed it does
  NOT reproduce here, for a structural reason rather than luck: `run_sync` has no
  shared running total or cross-submission ceiling to check-then-violate — each line
  item's match is an independent, read-only ID lookup against PO/invoice data this
  feature never mutates, so no row lock is needed and none is missing (Fork 4/5's
  own reasoning, independently confirmed live under adversarial testing, not merely
  assumed from the synchronous framing). Three Low findings, none requiring a code
  change: a pre-existing test-harness order-dependency issue (also noted in D-018's
  own audit, unrelated to this feature's product code), the same BFF
  break-glass-implies-full-tenant-trust boundary already accepted in the D-017/D-018
  audits, and a confirmation that the `SystemDisabledError` branch is currently
  unreachable through the app (by design — Fork 5/§6 already named adding an UPDATE
  grant for this as explicitly out of scope). Full findings in
  `docs/audit/d-019-security-audit.md`.

## 6. Alternatives considered

- **Building one real connector (e.g. AWS Cost Explorer, since AWS SDKs are
  well-documented) instead of a generic framework.** Rejected (Fork 1): even one real
  connector needs live credentials this environment doesn't have and cannot verify
  end-to-end — an "integration" that has never actually talked to AWS is not more
  honest than a clearly-labeled framework, and building the generic receiving half
  first is reusable by ALL seven named systems, not just one.
- **Fuzzy matching (vendor-name substring + amount-tolerance window) so more line
  items resolve to something other than `'unreconciled'`.** Rejected (Fork 2): a
  wrong "smart" match actively corrupts the reconciliation report it's supposed to
  protect — an honest `'unreconciled'`/`'not_found'` is strictly safer than a
  confident-looking wrong answer, and the precise-ID-match design is simple enough to
  implement and test correctly in one pass.
- **A run-level `status` field on `sync_runs` (e.g. `'completed'`/`'failed'`) for
  future-proofing.** Rejected (Fork 4): nothing in this task's actual scope can ever
  produce a `'failed'` run (no external I/O to fail), so the column would carry
  exactly one value forever — designing for a future connector's needs before that
  connector exists is exactly the "don't build for hypothetical requirements"
  discipline this session has followed throughout; the field is trivial to add when
  real failure modes exist.
- **Granting `delta_app` UPDATE on `external_systems` so a `status` toggle endpoint
  could be built now.** Rejected (Fork 5): the enable/disable action itself is out of
  this task's bounded slice (§3); granting UPDATE ahead of actually building and
  testing that endpoint would be unused privilege — access is added when the
  capability that needs it ships, not preemptively.
