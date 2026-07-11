# ADR-0025 — Privacy-First Multi-Bank Aggregation: A Consent-Scoped Generic Ingestion Framework, Not a Live Bank/OAuth Connector

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-025 (Privacy-first multi-bank financial data aggregation) · Phase 4
  (B2C personal finance, post-investment vision tier) — the FIFTH and final task in
  the D-021→D-025 B2C track.
- **Depends on:** D-021 (the `personal_accounts`/`personal_transactions` ledger this
  task extends — a B2C consumer IS one `tenant_id`, ADR-0021 Fork 1, reused here
  unchanged), D-009 (hash-chained audit log — every consent-lifecycle change and
  every sync run lands there).
- **Builds on:** D-019's own "generic ingestion endpoint, not vendor connectors"
  precedent (ADR-0019 Fork 1) — ADR-0021 §3 names this exact shape, verbatim, as
  D-025's job: *"No real bank data aggregation. Every account/transaction here is
  operator/user-entered (`source = 'manual'`). D-025's named job — a generic
  ingestion framework (mirroring D-019's own precedent), not live Plaid/bank
  OAuth."* Also builds on D-024's own designed extension of D-021's `source` column
  (widening `('manual')` → `('manual', 'execution')`) — this task exercises that
  same extension point a second time, and on D-024's per-account
  `pg_advisory_xact_lock` TOCTOU-closing pattern (Fork 5 there), reused here for an
  analogous account-scoped mutual-exclusion race.
- **Supersedes:** nothing. Adds a new `delta.bank_aggregation` package, one new
  migration (0018: `linked_institutions`, `aggregation_sync_runs`,
  `aggregation_ingested_references`, plus a second widen of
  `ck_personal_txn_source`), one new router mount to `allocation_admin/app.py`. No
  existing D-001–D-024 file's runtime behavior is modified beyond that one CHECK
  widen and `personal_finance.schemas.TransactionSource`'s literal (both additive).

## 1. Context

The roadmap's literal title is *"Privacy-first multi-bank financial data
aggregation."* Read literally this could imply a live Plaid-style integration: real
OAuth against real banks, real credential storage, a live webhook/polling feed.
Before starting, this was checked directly against the codebase and this
environment, exactly as every prior D-013+ task has done:

- **No bank/Plaid/OAuth credential, API key, or webhook receiver of any kind exists
  anywhere in this codebase or environment.** Fabricating one — or accepting
  caller-declared "bank data" with no way to verify it came from a real bank — would
  not be meaningfully more honest than a clearly-labeled generic framework, while
  adding scope (OAuth flow, webhook signature verification, per-vendor API
  clients) this task cannot responsibly build unilaterally in one unattended pass.
- **D-021's own ADR already named this task's job precisely** (quoted above) — the
  identical "build the generic RECEIVING half, name the live-connector half as
  future work" resolution D-019 already applied to seven named ERP/cloud systems.
- **"Privacy-first"** is not just a marketing adjective here — it is read as a
  concrete, testable design constraint: never store a bank credential of any kind,
  and never store more of an account number than a human already sees printed on a
  bank statement (the last four digits). Both are enforced structurally (§2 Fork 1),
  not merely documented as an intention.

What CAN be built honestly — and is genuinely the valuable, hard part of an
aggregation feature — is the **consent-scoped ingestion framework**: a caller
(standing in for a not-yet-built connector) registers a consent-gated link between
one D-021 `personal_accounts` row and a named institution, then posts normalized,
already-Plaid-shaped transaction batches against that link. This PR builds and tests
that receiving half completely, end to end, against Delta's own real ledger.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — a masked last-4 reference is the ONLY account identifier ever stored, enforced at the DB layer twice over** | `linked_institutions.masked_account_last4` is a `VARCHAR(4)` column (so a longer value cannot even be written) that ALSO carries a `CHECK (masked_account_last4 ~ '^[0-9]{4}$')` (so a short-but-wrong value, e.g. `"12a4"`, is rejected too). No column anywhere in this feature can hold a full account or routing number. | This is the concrete, testable meaning of "privacy-first" this ADR commits to: not a policy statement, a structural guarantee verified by `test_masked_last4_check_constraint_rejects_full_account_number` inserting directly through the store layer with a bypassed schema check — the DB itself is the backstop, not just Pydantic. |
| **2 — a generic ingestion endpoint, not a live bank/OAuth connector** | `POST /v1/admin/bank-aggregation/links/{id}/sync` accepts a batch of caller-supplied, already-normalized line items (`external_reference`, signed `amount_minor_units`, `currency`, `category`, `occurred_at`) in one shape — mirrors D-019's `SyncLineItemInput`. A future real connector's entire job would be: authenticate to a real bank API (Plaid or direct), fetch transactions, normalize them into this exact shape, and POST them here. This task builds and tests that receiving half completely; the live-connector half is out of scope and named in §3. | Direct application of D-019 Fork 1's reasoning, and the literal continuation of ADR-0021's own named deferral for this task. |
| **3 — no credential/token storage of any kind, anywhere in this feature** | There is no column, table, or field in migration 0018 that stores an access token, refresh token, API key, or any other bank credential. `linked_institutions` records ONLY: which D-021 account, which institution (a free-text label), a masked last-4, and the consent timestamps. | A real Plaid-style integration would need to store a `access_token` server-side (usually via Vault/KMS, per this monorepo's CLAUDE.md secrets rule). Since no real bank connection exists to authenticate, there is nothing honest to store — inventing a placeholder credential column would be exactly the "stub dressed up as a real integration" pattern this codebase's engineering culture rejects (ADR-0019 §1's identical reasoning). |
| **4 — an explicit, schema-enforced consent gate; consent is revocable, forward-only, and reusable per account** | `LinkCreateRequest.consent_confirmed: Literal[True]` — the caller must affirmatively pass `true`; there is no default. `linked_institutions.status` moves forward-only `'linked' → 'revoked'` (conditional UPDATE, mirrors D-014/D-022's transition-guard pattern) via `try_revoke_link`. A partial UNIQUE index (`account_id WHERE status = 'linked'`) permits at most one ACTIVE link per account at a time, but an account MAY be re-linked after a revoke (a new row, not a resurrected old one) — modeling the real "unlink, then later re-authenticate" flow a bank-linking feature needs. | Privacy-first requires consent to be a real, checked gate (not implied by the request simply existing) AND a real right to revoke (mirrors GDPR/open-banking consent-lifecycle expectations named honestly, without claiming this ADR performs any actual regulatory compliance verification — see the ecosystem's "audit-ready not compliant" language mandate). Forward-only transition mirrors this codebase's established terminality-guard precedent (D-014 asset status, D-022 subscription cancel). |
| **5 — consent-lifecycle events (link created, link revoked) AND every sync run are D-009 audited — a deliberate divergence from D-019's own "registration not audited" precedent** | `create_link`/`revoke_link`/`sync_link` each call `append_history` in the SAME transaction as their store write. D-019's ADR (Fork 7) explicitly left external-system REGISTRATION unaudited, reasoning it was directory/config metadata. This task audits registration (`create_link`) too. | A privacy-first feature's consent state is not directory metadata — it is the exact kind of fact a user (or a future regulator) must be able to prove happened and when: "I granted consent on this date, and revoked it on that date." Treating it as unaudited config would undercut the feature's own stated privacy posture. This is a NAMED, deliberate divergence from the D-019 precedent, not an oversight. |
| **6 — dedup is a structural composite-PRIMARY-KEY backstop, not app-layer-only idempotency** | `aggregation_ingested_references`'s primary key is `(link_id, external_reference)` — a retried sync posting the SAME bank-reported transaction ID against the SAME link cannot physically insert a second row. The service layer checks this table BEFORE inserting a ledger row (an app-layer pre-check for a friendly, per-item "deduplicated" count rather than a raw constraint-violation exception), but the composite PK is the real correctness backstop, mirroring D-024's identical `UNIQUE(tenant_id, idempotency_key)` reasoning applied at the per-line-item granularity a batch sync needs (one key per bank transaction, not one key per whole sync call). | A bank feed WILL redeliver the same transaction on a retried/overlapping sync window (this is normal behavior for real aggregation feeds, e.g. Plaid's own de-dup guidance) — an aggregation framework that could double-count a redelivered transaction into a person's own budget/health-score numbers would be actively misleading, not just imprecise. |
| **7 — currency mismatch is a per-item REJECTED count, never a silent conversion, never a whole-batch failure** | An item whose `currency` differs from the linked account's own `currency` is skipped and counted in `records_rejected` — the rest of the batch still processes. No FX anywhere (D-001's no-FX rule), mirrors D-024's identical `currency_mismatch` handling exactly, generalized from "reject the one transaction" to "reject the one line item, keep going." | Rejecting the WHOLE batch for one bad-currency line item would make the framework fragile against a single malformed record in an otherwise-valid feed; silently converting would fabricate an exchange rate this codebase does not have (same reasoning D-024 Fork 8 already established). |
| **8 — an aggregated transaction writes into D-021's OWN `personal_transactions` ledger, `source='aggregated'`, exactly like D-024 exercised the same extension point for `'execution'`** | Migration 0018 widens `ck_personal_txn_source` a second time: `('manual', 'execution')` → `('manual', 'execution', 'aggregated')`. `personal_finance.schemas.TransactionSource` widens in lock-step. | An aggregated transaction that D-021's budgets/health score could not see would be a dishonest ledger — the exact reasoning ADR-0024 Fork 3 already established for execution rows, applied here for the second (and, per D-021's own naming, final) time this designed extension point is exercised. The alternative (a parallel, aggregation-only ledger) was rejected as the same kind of unreconciled data silo D-024 already rejected. |
| **9 — an account-scoped advisory lock closes the active-link-creation TOCTOU race** | `store.create_link` takes `pg_advisory_xact_lock(hashtext(account_id))` before checking for an existing active link and inserting — same shape as D-024's per-account execution lock (Fork 5 there), scoped to the SAME lock-key space (an account cannot be executing a micro-transaction and being linked "simultaneously" in a way that races, by design — they share a lock key, which only serializes unrelated operations on the same account, never a correctness problem). | Without the lock, two concurrent link-creation requests for the same account could both pass the "no active link exists" check and both insert, racing the partial-unique-index's own guarantee into an unpredictable 500 instead of a clean, deterministic 409 for the loser. The DB constraint (Fork 1's sibling, `uq_linked_institution_active_account`) is still the ultimate backstop — `test_active_link_partial_unique_index_enforced_at_db_layer` proves this by bypassing the lock/check entirely via a raw privileged-session INSERT. |
| **10 — mounted on the existing admin app, `require_admin` only** | `POST/GET /v1/admin/bank-aggregation/links`, `POST /links/{id}/revoke`, `POST /links/{id}/sync`, `GET /links/{id}/sync-runs` on the same D-007 admin app, alongside the other 15 mounted routers. | Same reasoning as every prior D-021+ task: an internal operator/testing surface until a real B2C onboarding shell (still unbuilt anywhere in this ecosystem) exists to front it with genuine end-user auth. |

## 3. Honest deferrals (named, not half-built)

- **No live Plaid/bank-OAuth integration of any kind.** Zero network calls to any
  bank or aggregation vendor exist anywhere in this diff. The concrete, well-defined
  future work this framework exists to receive: a real connector authenticates to a
  real bank API (directly or via an aggregator like Plaid), fetches transactions and
  balances, normalizes them into `SyncLineItemInput`'s exact shape, and calls
  `POST /links/{id}/sync` — the receiving half this task built and tested
  end-to-end.
- **No credential/access-token storage** (Fork 3) — there is nothing to store
  because there is no real bank session to hold a token for. When a real connector
  exists, its credential storage is a Vault/KMS concern per this monorepo's root
  CLAUDE.md secrets rule, entirely outside this feature's tables.
- **No balance aggregation, only transaction ingestion.** A real aggregation feed
  also reports account BALANCES (not just transactions); this task's `sync`
  endpoint only accepts transaction-shaped line items. A future extension could add
  a parallel balance-snapshot concept (mirrors D-023's own `investment_holdings`
  snapshot shape) without changing this task's transaction path.
- **No continuous/scheduled sync, no webhook receiver.** Every sync is a single
  request-response call — mirrors D-019 Fork 4's identical reasoning: a real
  connector's own scheduling (cron, or a webhook endpoint for push-based
  aggregators) is part of the per-vendor work this framework exists to receive, not
  this framework itself.
- **No fuzzy institution-identity verification.** `institution_name` is a
  caller-supplied free-text label, not validated against any real registry of banks
  (no such registry exists in this codebase). A future connector would populate this
  from whatever real institution metadata its own bank API returns.
- **No FX / multi-currency reconciliation** (Fork 7) — a currency-mismatched line
  item is rejected, never converted (D-001's no-FX rule, ecosystem-wide).
- **No per-tenant configurable ingestion caps or rate limiting** beyond the
  schema-level `MAX_SYNC_BATCH_SIZE` (500 items/call, mirrors D-019's identical
  `SyncRunCreateRequest.line_items` cap). A per-tenant policy store is real,
  separate future work this ADR does not claim to deliver.
- **No actual regulatory compliance verification** (GDPR "right to erasure," PSD2/
  open-banking consent-lifecycle rules, etc.). This feature's consent-gate/revoke
  design is INSPIRED by those real-world requirements' shape, but no compliance
  audit against any actual regulatory text was performed — describing this feature
  as "GDPR-compliant" or similar would violate this monorepo's honest-language
  mandate; "privacy-first" here means the three structural properties named in
  Forks 1/3/4, nothing broader is claimed.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| A full account/routing number is stored instead of a masked reference | `masked_account_last4` is `VARCHAR(4)` (physically cannot hold more) + a regex CHECK (rejects a short-but-non-numeric value) — both enforced at the DB layer, bypassing the store function's own Python-level call | `test_masked_last4_check_constraint_rejects_full_account_number`, `test_masked_last4_must_be_exactly_four_digits`, `test_masked_last4_cannot_carry_a_full_account_number` |
| Two simultaneously 'linked' rows for one account (a TOCTOU race on concurrent link-creation requests) | `pg_advisory_xact_lock(hashtext(account_id))` serializes the check → insert critical section (Fork 9); the partial UNIQUE index `uq_linked_institution_active_account` is the DB-layer backstop even if the lock were somehow bypassed | `test_create_link_against_already_linked_account_raises`, `test_active_link_partial_unique_index_enforced_at_db_layer` (proves the DB constraint directly via a raw bypass) |
| A retried/redelivered sync double-writes the same bank transaction into the ledger | Composite PRIMARY KEY `(link_id, external_reference)` on `aggregation_ingested_references` makes a second insert for the same reference structurally impossible; the service layer's pre-check turns this into a clean per-item "deduplicated" count rather than a raw constraint exception | `test_sync_dedups_repeated_external_reference`, `test_ingested_reference_dedup_backstop` (proves the PK directly) |
| Cross-tenant leak — one tenant's links/sync-runs/ingested-transactions visible to another | Every store function runs inside the caller's own `get_tenant_session(tenant_id)`; all three new tables have `ENABLE`+`FORCE ROW LEVEL SECURITY` with the strict `NULLIF` predicate, `delta_app` is NOBYPASSRLS | `test_cross_tenant_links_isolated`, `test_cross_tenant_link_list_isolated`, `test_cross_tenant_sync_against_other_tenants_link_is_404`, `test_cross_tenant_links_isolated_over_http` |
| A link is created against an account that doesn't exist or belongs to another tenant | `create_link` explicitly re-fetches the account via D-021's `personal_finance.store.get_account` and checks tenant ownership before writing (404), mirroring D-021's own `create_transaction` pattern — RLS/FK alone would not distinguish "doesn't exist" from "exists, wrong tenant," but both must 404 identically with no side effects | `test_create_link_unknown_account_raises`, `test_create_link_cross_tenant_account_raises`, `test_link_unknown_account_404_over_http`, `test_cross_tenant_links_isolated_over_http` |
| A sync is accepted against a 'revoked' link | `sync_link` checks `link.status != "linked"` before processing any line item — raises `LinkRevokedError` → 409, zero line items processed | `test_sync_against_revoked_link_raises`, and the router e2e's revoke-then-sync-blocked flow |
| Currency-mismatched line item silently converted or corrupts the batch | Rejected per-item, counted, never converted; the rest of the batch still processes | `test_sync_currency_mismatch_is_rejected_not_written`, `test_sync_mixed_batch_counts_are_consistent` |
| A sync run's summary counts drift from what was actually written/deduplicated/rejected | `records_received = records_written + records_deduplicated + records_rejected` is BOTH a DB CHECK constraint AND derived from ONE pass over ONE list in the service layer (not two independently-maintained tallies) | `test_sync_mixed_batch_counts_are_consistent`; the CHECK itself is exercised implicitly by every passing sync test (a violation would 500, not silently pass) |
| An aggregated transaction is invisible to D-021's own budget/health-score reads | `source='aggregated'` lands in the SAME `personal_transactions` table every D-021 read already consumes — no parallel ledger | `test_sync_writes_ledger_row_visible_to_d021`, `test_full_link_and_sync_flow_over_http` (confirms over HTTP via D-021's own transactions endpoint) |
| Consent-lifecycle changes leave no attributable, tamper-evident trail | `create_link`/`revoke_link`/`sync_link` each call `append_history` in the same transaction as their write (Fork 5) | `test_create_link_lands_in_d009_audit_chain`, `test_revoke_link_lands_in_d009_audit_chain`, `test_sync_lands_in_d009_audit_chain` |
| `aggregation_sync_runs`/`aggregation_ingested_references` rewritten after the fact to hide what a sync actually did | No UPDATE/DELETE grant to `delta_app` on either table (DB ACL layer, not just app code) | `test_aggregation_sync_runs_table_has_no_update_delete_grant`, `test_aggregation_ingested_references_table_has_no_update_delete_grant` |
| `linked_institutions` deleted to erase consent history | No DELETE grant to `delta_app` (UPDATE is granted, for the forward-only revoke transition only) | `test_linked_institutions_table_has_no_delete_grant` |
| Control-character / log-injection via `institution_name`/`requested_by`/`merchant`/`description`/`note`/`triggered_by` | Same `_reject_control_chars` discipline as every prior Delta package | `test_link_institution_name_rejects_control_chars`, `test_link_requested_by_rejects_control_chars`, `test_revoke_request_rejects_control_chars`, `test_line_item_control_chars_rejected`, `test_sync_run_request_rejects_control_chars_in_note` |
| Float/bool money injection into `amount_minor_units` | `reject_non_integer` at the schema layer (`mode="before"`, mirrors D-024's `ExecutionRequest` exactly — a `mode="after"` validator would run too late, after Pydantic's own lax int coercion already silently accepted a float/bool) | `test_line_item_rejects_float_amount`, `test_line_item_rejects_bool_amount` |
| Unbounded sync batch size | `SyncRunCreateRequest.line_items` is `Field(min_length=1, max_length=500)`, mirrors D-019's identical cap | `test_sync_run_request_caps_batch_size` |
| SQL injection via any bank-aggregation identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.bank_aggregation.store` | code review |
| Auth bypass on any of the 5 new routes | Router-level `dependencies=[Depends(require_admin)]` covers all 5 with no per-route opt-out | `test_create_link_endpoint_401_without_bearer` |

## 5. Verification

- `ruff check .` / `black --check .` clean on the FULL repository (332 files).
  `semgrep scan --config=p/python --severity=ERROR --no-git-ignore src/` could not be
  run in this development sandbox (its rule registry fetch is blocked by the
  sandbox's outbound network policy — a sandbox limitation, not a code issue); it
  runs for real in CI's `quality` job and is expected to pass (no new pattern this
  diff introduces differs from the parameterized-query / no-eval / no-raw-SQL shape
  every prior semgrep-clean Delta package already uses).
- New `tests/bank_aggregation/` suite: 60 tests — 21 pure schema-validation tests
  (`test_schemas.py`, no DB/I/O, including the masked-last4 charset/length
  boundaries and the float/bool money-injection guards), 17 DB-backed store tests
  (`test_store_db.py`, including the DB-layer masked-last4 CHECK, the partial
  unique-index proof via a raw bypass insert, the dedup-backstop proof, and the
  three grant-shape assertions), 15 DB-backed service tests (`test_service_db.py`,
  covering the full link/revoke/sync lifecycle, dedup, currency-mismatch handling,
  cross-tenant isolation, and D-009 audit-chain wiring), 7 non-stubbed HTTP e2e
  tests (`test_router_e2e.py` — real ASGI app, real auth, real DB, driving the full
  flow: create account → link → sync → verify in D-021's own ledger → replay-dedup →
  revoke → blocked re-sync).
- Full existing Delta suite green on a fresh Postgres — zero regressions (verified
  locally against a from-scratch `delta_dev` database provisioned identically to
  CI's `ledger-db`/`migration-roundtrip` jobs: `delta`/`delta_app` roles, SCRAM
  password provisioning, `DELTA_PROVISION_APP_ROLE=1`, `pip install -e
  "../Rendly[dev]"` for the X-005 cross-repo lane exactly as CI's `ledger-db` job
  does): 1122 passed, 15 skipped, 0 failed.
- Migration 0018 applied cleanly against a live local Postgres: `alembic upgrade
  head` from 0017, a full `downgrade base` → `upgrade head` round trip, and a true
  `DROP SCHEMA delta CASCADE` → `upgrade head` fresh rebuild — all clean.
- A pre-existing gap this task's own e2e test caught and fixed before merge:
  `personal_finance.schemas.TransactionSource` had only been widened to
  `('manual', 'execution')` (D-024) — without also widening it here, the FIRST
  aggregated transaction ever ingested would 500 the instant anyone listed it
  through D-021's own `GET /transactions` endpoint (a Pydantic response-model
  validation failure on an unrecognized `source` literal, masked by the admin app's
  generic 500 handler). Caught by `test_full_link_and_sync_flow_over_http` failing
  locally before this fix; `TransactionSource` now reads
  `Literal["manual", "execution", "aggregated"]`.

## 6. Alternatives considered

- **A live Plaid Sandbox integration** (Plaid does offer a free sandbox
  environment). Rejected: even a sandbox integration requires a real Plaid
  developer account/API keys this environment does not have and cannot provision
  unilaterally in an unattended run, and a "sandbox-only" integration presented as
  the feature would misrepresent its production-readiness — the generic framework
  is honest about being framework, not a working bank connection at any tier.
- **Accepting a caller-declared full account number and masking it server-side
  before storage.** Rejected (Fork 1): this would mean a full account number
  transits the request body and briefly exists in application memory/logs before
  being discarded — a strictly weaker privacy property than never accepting one at
  all. The wire format itself only ever carries the masked value.
- **A single combined `bank_accounts` + `bank_transactions` shadow ledger, separate
  from D-021.** Rejected (Fork 8): the same "unreconciled data silo" problem D-024
  already rejected for its own execution ledger — an aggregated transaction the
  owner's own budget tracking could not see would be a dishonest ledger.
- **Storing a mock/placeholder `access_token` column "for future use."** Rejected
  (Fork 3): an unused credential column with no real value to ever populate it is
  exactly the speculative, build-for-a-hypothetical-future-requirement pattern this
  codebase's engineering standards reject; the column is trivial to add when a real
  connector needs it.
- **Auto-relinking or silently reactivating a previously revoked link on a new sync
  attempt.** Rejected: revocation must mean revocation — a sync against a revoked
  link is rejected outright (Fork 4/§4), never silently treated as an implicit
  re-consent.
