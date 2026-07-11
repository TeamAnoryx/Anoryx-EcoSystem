# ADR-0025 — Privacy-First Bank-Statement Import Framework (Multi-Bank Aggregation, Ledger-Internal)

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-025 (Privacy-first multi-bank financial data aggregation) · Builder: FinOps backend
- **Depends on:** D-021 (the `personal_accounts`/`personal_transactions` ledger every import
  normalizes into), D-009 (hash-chained audit log — every source registration and import run
  lands there)
- **Builds on:** D-019's ERP-sync precedent (a generic caller-supplied-line-items ingestion +
  matching FRAMEWORK instead of fabricated live per-vendor integrations — reused here as the
  structural template), D-024's `source` extension-point precedent (widened a third time, to
  `'import'`), D-024's per-entity advisory-lock shape.
- **Numbering note:** ADR-0023 remains reserved for D-023 (parallel track), matching the
  task-aligned numbering D-021/D-022/D-024 settled into.
- **Supersedes:** nothing. Adds a new `delta.bank_import` package, one new migration (0018:
  `bank_sources`, `statement_imports`, `imported_statement_lines` + the widened source CHECK),
  and one new router mount to `allocation_admin/app.py`.

## 1. Context

The roadmap's literal Phase-4 text for D-025 is *"Privacy-first multi-bank financial data
aggregation."* Read literally, that means live connections to multiple banks — open-banking
OAuth flows, aggregator APIs (Plaid/Tink/TrueLayer), consent management against real
institutions. **None of that exists in this codebase or this environment**: no bank credential,
no aggregator API key, no open-banking client registration. This is the same situation D-019
faced with "seamless integration with corporate ERPs" naming seven live vendors — and this ADR
makes the same decision D-019's did: build the generic, honest ingestion framework, and name the
future per-provider connector's integration point explicitly rather than fabricating a live
integration.

What IS genuinely buildable — and is the differentiating word in the task's own title — is the
**privacy-first** core:

1. **Normalized import framework** — a registered `bank_source` per institution feed (an
   operator-typed `institution_label`, exactly like D-019's `vendor_label` — a label, not a
   connection), each linked to the D-021 personal account it fills. Caller-supplied statement
   lines POST through a generic import endpoint and are normalized into D-021's own ledger
   (`source='import'`), where every existing read (budgets, health score, category spend)
   aggregates them across all sources/accounts — that IS the "multi-bank aggregation" read path,
   already shipped by D-021 and reused unmodified.
2. **Privacy-first properties, enforced structurally** (Sec 2, Forks 2/4/5) — data minimization
   by construction, hashed external references, and refusal to store card-number-shaped text.

**The future real-aggregator integration point is named**: a provider connector (Plaid/Tink/…)
normalizes its webhook/API data into this ADR's `StatementLine` shape and POSTs it through this
same import endpoint. The dedup, normalization, privacy filters, and audit trail it needs are
exactly what this PR ships.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — caller-supplied statement lines, not a fabricated live connection** | The import endpoint takes `lines: list[StatementLine]` supplied by the caller (bounded, ≤500/request), mirroring D-019's sync-ingestion decision verbatim. `bank_sources.institution_label` is a free-text label. | An unattended run cannot responsibly create bank/aggregator credentials, and a mock "live" integration presented as real would violate the honest-language mandate. D-019 already established the pattern AND the escape hatch: the framework is the durable part; connectors are thin adapters onto it later. |
| **2 — the bank-side transaction reference is stored ONLY as a SHA-256 hash** | `imported_statement_lines.external_reference_hash` holds `sha256(external_reference)`; the raw reference is never persisted and never echoed back from storage (the caller already has it). | Dedup — the only thing the reference is for — needs equality, and a hash gives exactly equality. A bank's transaction identifier can encode account fragments, timestamps, and processor metadata; storing it raw retains data with no purpose beyond what its hash already serves. This is data minimization applied to a single field, and it costs nothing. |
| **3 — imported lines land in D-021's OWN ledger via the `source` extension point, third value** | Each imported line becomes a `personal_transactions` row with `source='import'` (signed amount as supplied — statements carry income and expenses). Migration 0018 widens `ck_personal_txn_source` to `('manual','execution','import')`; the `TransactionSource` Literal widens in lock-step. | Identical reasoning to D-024 Fork 3: an import invisible to the owner's budgets/health score would be a dishonest ledger, and a parallel imported-transactions table would double-book the same money. The `source` column exists precisely so each writer is distinguishable. |
| **4 — free text that looks like a card/account number is REFUSED, not stored** | `merchant`/`description`/`institution_label` reject any run of 12+ digits (separators allowed) at the schema layer → 422. `external_reference` is charset-constrained to the request-id-safe pattern. There is deliberately NO raw-payload JSONB column anywhere in this feature (unlike D-004's DLQ / D-019's framework). | Statement descriptors are the classic vector for PAN/IBAN leakage into systems never audited to hold them. Refusing at the boundary is strictly stronger than storing-then-redacting: data that was never written cannot leak, and `extra="forbid"` on every model means a future aggregator's surplus fields cannot even arrive. This fork (with 2 and 5) is what makes "privacy-first" a set of testable properties instead of a slogan. |
| **5 — append-only everywhere, one audit row per import RUN** | SELECT/INSERT grants only on all three tables; every source registration and import run appends to D-009's hash chain (the run row's note carries the counters). Per-LINE audit rows are deliberately not written. | Immutability is the same trustworthiness property D-022/D-024 established for their ledgers. One chain row per run keeps the tamper-evident chain proportional to operator actions, not statement sizes — the per-line record already lives, append-only, in `imported_statement_lines`. |
| **6 — batch dedup: one query per import + in-batch first-occurrence-wins, partial-unique backstop** | `imported_hashes_for_source` fetches the already-imported subset of the batch's hashes in ONE query (never per-line); duplicates within the request batch dedup against each other too. The DB backstop is a partial unique index on `(source_id, external_reference_hash) WHERE status='imported'` — so a REJECTED line's reference stays retryable after the caller fixes it, while an imported one can never import twice. A per-source `pg_advisory_xact_lock` serializes concurrent imports of the same source. | The no-N+1 discipline is D-012 Fork 2's, applied to writes. The partial index encodes the exact business rule (uniqueness is a property of successful imports only) instead of over-blocking retries. The advisory lock (D-024's shape, per source) makes two concurrent uploads of the same export dedup cleanly rather than aborting the second with a unique-violation IntegrityError. |
| **7 — line-level outcomes are first-class, counters must sum** | Every supplied line gets an `imported_statement_lines` row (`imported`/`skipped_duplicate`/`rejected` + typed reason), with paired CHECKs (`imported ⇔ txn_id`, `rejected ⇔ reason`) and a `records_supplied = imported + skipped + rejected` CHECK on the run row (D-019's `ck_sync_run_counts_sum` shape). | Partial success is the NORMAL case for statement imports (overlapping exports). Making each line's fate durable and the counters structurally consistent is what lets an operator trust "487 imported, 13 duplicates" without re-deriving it. |
| **8 — currency mismatch is a per-LINE rejection, not a request failure** | A line whose currency differs from the target account's is recorded `rejected/currency_mismatch`; the rest of the batch proceeds. No FX (D-001's rule). | One bad line failing a 500-line import forces the caller to binary-search their statement. Recording it (Fork 7) keeps the attempt visible; converting it would fabricate an exchange rate this codebase does not have. |
| **9 — mounted on the existing admin app, same `require_admin` posture** | `POST /v1/admin/bank-imports/sources`, `GET .../sources`, `POST .../sources/{id}/import`, `GET .../imports`. | Same reasoning as D-021/D-024: an internal operator/testing surface until a real B2C onboarding shell exists; fabricating consumer auth here would be scope-widening. |

## 3. Honest deferrals (named, not half-built)

- **No live bank/aggregator connection.** No OAuth consent flow, no provider webhooks, no
  credential storage. The integration point for a real connector is named in Sec 1 — it is this
  feature's input shape, not a parallel system.
- **No file parsing (CSV/OFX/MT940).** Lines arrive already normalized as JSON. A statement-file
  parser is a real, separable future feature; bundling format heuristics into an unattended run
  invites silent misparses of financial data.
- **No automatic categorization.** `category` defaults to `'other'` unless the caller supplies
  one — merchant-to-category inference is exactly the kind of model this ecosystem has
  consistently declined to fabricate (D-011/D-012/D-015 precedent).
- **No consent/data-subject-rights machinery.** Real open-banking compliance (PSD2 consent
  lifecycles, right-to-erasure against append-only stores) is named as the hard future work it
  is; this PR's privacy contribution is structural minimization of what gets stored at all.
- **No source disable/delete lifecycle.** Sources are append-only registrations in v1; a
  future lifecycle needs its own authorization story.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant source/import/line leak, or importing into another tenant's account | Tenant-scoped RLS session everywhere; composite `(account_id, tenant_id)` / `(source_id, tenant_id)` / `(import_id, tenant_id)` FKs; unknown and cross-tenant sources/accounts both 404 with no side effects | `test_cross_tenant_source_is_404`, `test_cross_tenant_sources_list_isolated`, `test_register_source_missing_account_raises` |
| Double-import of the same statement (retry, overlapping exports) | Batch dedup vs. already-imported hashes + in-batch dedup (Fork 6); partial unique index backstop; per-source advisory lock serializing concurrent imports | `test_reimport_of_same_lines_skips_all_as_duplicates`, `test_duplicate_within_one_batch_imports_once` |
| Raw bank identifiers retained | Only `sha256(external_reference)` is stored (Fork 2) — verified by querying the stored rows and asserting the raw reference appears nowhere | `test_raw_external_reference_is_not_stored` |
| PAN/IBAN leakage via statement descriptors | 12+-digit-run rejection on `merchant`/`description`/`institution_label` → 422; charset-constrained `external_reference`; no raw-payload column exists (Fork 4) | `test_card_number_like_text_rejected`, code review — no JSONB/payload column in migration 0018 |
| Rejected line blocks its own retry forever | The unique index is PARTIAL (`WHERE status='imported'`) — a fixed line re-imports cleanly | `test_rejected_line_reference_is_retryable_after_fix` |
| Counter/lines divergence (run says X imported, lines say Y) | `ck_statement_import_counts_sum` DB CHECK + paired line-consistency CHECKs (Fork 7); counters computed from the same loop that writes the lines | `test_counters_match_line_outcomes`, DB CHECK constraints |
| Ledger/import-log divergence | Ledger rows, line rows, run row, and audit row all commit on ONE session | `test_imported_lines_land_in_d021_ledger` (asserts exact txn linkage) |
| Currency confusion / fabricated FX | Per-line `currency_mismatch` rejection (Fork 8); no conversion path exists in the package | `test_currency_mismatch_line_rejected_rest_import` |
| History rewritten to hide an import | No UPDATE/DELETE grant on any of the three tables; D-009 chain row per registration/run | `test_bank_import_tables_have_no_update_delete_grant`, `test_import_lands_in_d009_audit_chain` |
| Resource amplification via huge batches | `lines` bounded 1..500 at the schema layer; dedup is one query per batch | `test_import_over_500_lines_rejected_422` |
| Float/bool money injection, log injection | `reject_non_integer` + non-zero + overflow guard on amounts; control-character rejection on all free text | `test_amount_rejects_float`, `test_control_characters_rejected` |

## 5. Verification

- `black --check .` / `ruff check .` clean.
- `alembic upgrade head` / `downgrade 0016` / `upgrade head` round trip clean (fresh Postgres) —
  including the source-CHECK widen/restore and the partial unique index.
- `tests/bank_import/`: pure schema unit tests (digit-run/PAN guard, bounds, charset), DB-backed
  service tests (dedup across imports and within a batch, retryable rejections, hash-only
  storage, counter consistency, cross-tenant isolation, D-009 wiring, append-only grants), and
  non-stubbed HTTP e2e (full register→import→D-021-ledger-visible flow, 401/404/422 paths).
- Full Delta suite green on a fresh Postgres (with `pip install -e "../Rendly[dev]"` matching
  CI's own install step for the X-005 lane) — zero failures beyond the pre-existing,
  environment-gated skips documented in every prior ADR's Sec 5.

## 6. Alternatives considered

- **Fabricating a live aggregator integration (mock Plaid client, fake OAuth).** Rejected
  (Sec 1): the D-019 precedent applies exactly — a mock presented as an integration is the
  dishonesty the language mandate exists to prevent.
- **Storing raw external references / raw payloads for debuggability.** Rejected (Forks 2/4):
  the caller retains their own statement; Delta keeping data it doesn't need contradicts the
  task's own defining adjective.
- **A separate imported-transactions ledger.** Rejected (Fork 3): same double-booking argument
  as D-024's Fork 3.
- **Failing the whole import on the first bad line.** Rejected (Fork 8): partial success with
  durable per-line outcomes is strictly more operable for overlapping statement exports.
- **A full-request unique constraint instead of the partial index.** Rejected (Fork 6): it would
  permanently block retrying a line that was rejected for a fixable reason.
