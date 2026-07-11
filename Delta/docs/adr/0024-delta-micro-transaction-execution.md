# ADR-0024 — Real-Time Personal Micro-Transaction Execution (Ledger-Internal)

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-024 (Real-time secure personal micro-transaction execution) · Builder: FinOps
  backend
- **Depends on:** D-021 (the `personal_accounts`/`personal_transactions` ledger every execution
  writes into), D-009 (hash-chained audit log — every execution attempt, executed or rejected,
  lands there)
- **Builds on:** D-018's audit-caught TOCTOU over-commitment lesson (designed out up front here
  via a per-account advisory lock), D-021's signed-amount + `source` column conventions (its
  designed extension point, exercised for the first time).
- **Numbering note:** ADR-0023 is deliberately left for D-023 (asset allocation +
  micro-investment), which is being built on a parallel track — the same task-aligned numbering
  D-021/D-022 settled into.
- **Supersedes:** nothing. Adds a new `delta.micro_transactions` package, one new migration
  (0016: `micro_transaction_executions` + a widened `ck_personal_txn_source` CHECK), and one new
  router mount to `allocation_admin/app.py`.

## 1. Context

The roadmap's literal Phase-4 title for D-024 is *"Real-time secure personal micro-transaction
execution."* Read literally, "execution" implies moving real money over a payment rail. **No
payment rail, card network, bank connection, or external money-movement integration of any kind
exists anywhere in this codebase** — D-025 (multi-bank aggregation, the only plausible source of
a real financial connection) is itself still unbuilt, and no payment-processor credential exists
in this environment. An unattended run cannot responsibly fabricate one, and pretending a
ledger write is a bank transfer would violate the repo's honest-language mandate.

What CAN be built honestly — and is genuinely the hard, valuable part of any execution engine —
is the **execution safety core**: the synchronous decision path that real payment execution
would sit behind. This PR ships exactly that, operating on Delta's OWN D-021 personal-finance
ledger:

- **"Real-time"** = a synchronous accept/reject decision in one request/response cycle, with
  the decision durably recorded before the response is sent.
- **"Secure"** = idempotency-keyed (replays return the stored original outcome, never
  re-execute), cap-enforced (a per-transaction "micro" ceiling + a rolling 24h per-account
  cumulative ceiling), concurrency-safe (per-account advisory lock closes the cap-check TOCTOU
  race), tenant-isolated (RLS), append-only (no UPDATE/DELETE grant), and tamper-evident (D-009
  audit chain in the same transaction).
- **"Execution"** = atomic bookkeeping: the execution record + the D-021
  `personal_transactions` ledger row + the D-009 audit row commit or roll back together. No
  real money moves (Sec 3).

When a real payment rail eventually exists, the natural integration point is named: the
accepted branch of `execute_micro_transaction` is where a rail call would go, and the engine's
idempotency/cap/serialization semantics are exactly what that call must be wrapped in.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — record REJECTED attempts as first-class rows** | A capped-out or currency-mismatched attempt inserts a `status='rejected'` row (with a typed `rejection_reason`) and a D-009 audit entry, exactly like an executed one — it is not just bounced with an error. Two paired DB CHECKs make the outcomes structurally exclusive: `executed ⇔ txn_id IS NOT NULL`, `rejected ⇔ rejection_reason IS NOT NULL`. | For an execution engine, the trace of what was ATTEMPTED is a security property, not noise — a burst of cap-rejected attempts on one account is precisely the signal an operator needs to see. A rejection that leaves no record is invisible to any later review. |
| **2 — idempotency key returns the stored ORIGINAL outcome, executed or rejected** | `execute` first looks up `idempotency_key` (RLS-confined to the caller's tenant); a hit returns the stored row flagged `idempotent_replay: true` with nothing re-checked or re-executed. `UNIQUE (tenant_id, idempotency_key)` is the backstop that makes a duplicate-insert race structurally impossible. A rejected outcome is also replayed — a retry after rejection needs a NEW key. | Standard execution-API semantics (one key = one attempt = one durable outcome). Replaying a rejection rather than retrying it keeps the engine's promise exact: the key identifies an ATTEMPT, not an intent to keep trying. The unique constraint spans the whole tenant (not per-account) so a key can never be reused across accounts either. |
| **3 — executed transactions land in D-021's OWN ledger via its designed `source` extension point** | The accepted branch writes a `personal_transactions` row with `source='execution'` and a NEGATIVE amount (D-021's expense sign convention), in the same transaction as the execution row. Migration 0016 widens D-021's `ck_personal_txn_source` CHECK from `('manual')` to `('manual','execution')`, and the `TransactionSource` Literal widens in lock-step. | An "executed" payment that D-021's budgets, category spend, and health score could not see would be a dishonest ledger — the owner's own budget tracking must reflect what the engine spent. The `source` column with a one-value vocabulary was D-021's explicitly designed extension point for non-manual writers; this is its first exercise, not a redesign. The alternative (a parallel, execution-only ledger) was rejected as a data silo that double-books the same money the moment anyone reconciles the two. |
| **4 — caps are module constants, not caller-tunable parameters** | `MAX_MICRO_TRANSACTION_MINOR_UNITS = 10_000` ($100, the definition of "micro", enforced at the request-schema layer → 422) and `DAILY_CAP_MINOR_UNITS = 50_000` ($500 rolling 24h per account, enforced in the engine against DB state). Neither is a query/body parameter. | A safety cap a caller can raise in the same request it applies to is not a cap. Same posture as D-012's fixed `ratio_threshold`/`min_floor_cents` (library defaults, not API knobs). Per-tenant configurable caps are real future work (Sec 3) — the safe default ships first. |
| **5 — per-account advisory lock closes the daily-cap TOCTOU race** | `pg_advisory_xact_lock(hashtext(account_id))` is taken before the daily-total read; transaction-scoped, auto-released at commit/rollback. | Without it, two concurrent requests both read a within-cap total and both commit, jointly exceeding the cap — the exact check-then-act race class D-018's independent audit caught in invoice over-commitment (fixed there reactively; designed out proactively here). Same lock shape as D-009's per-tenant chain lock, scoped to one account, so unrelated accounts never contend. |
| **6 — the daily cap counts EXECUTED rows only, over a rolling 24h window** | `executed_total_since(account, now - 24h)` sums executed magnitudes; rejected rows never consume cap. The window is rolling (`executed_at >= now - 24h`), not a calendar day. | Counting rejections against the cap would let a burst of rejected attempts deny service outright (a self-inflicted DoS vector). A rolling window has no midnight-reset cliff where a caller can double-spend by straddling the boundary. |
| **7 — unknown account is a 404, not a recorded rejection** | An `account_id` that doesn't resolve under the caller's tenant-scoped RLS session raises `AccountNotFoundError` → 404 `account_not_found`, mirroring D-021's own `create_transaction` behavior. No execution row is written. | There is no account row to attribute the attempt to — the composite FK would reject the insert anyway — and a cross-tenant `account_id` probe must be indistinguishable from a nonexistent one (both 404, no side effects), so the endpoint leaks no existence signal. |
| **8 — currency mismatch is a RECORDED rejection, not a silent conversion** | `req.currency != account.currency` → `rejection_reason='currency_mismatch'` row. No FX anywhere (D-001's no-FX rule). | Executing a EUR payment against a USD account by silent conversion would fabricate an exchange rate this codebase does not have. Recording the rejection (Fork 1) keeps the attempt visible. |
| **9 — mounted on the existing admin app, same `require_admin` break-glass auth** | `POST /v1/admin/micro-transactions/execute`, `GET /v1/admin/micro-transactions`. | Same posture as D-021's own router: an internal operator/testing surface until a real B2C onboarding shell (still unbuilt ecosystem-wide) exists to front it with genuine end-user auth. A fabricated consumer-auth layer would be scope-widening this run's procedure forbids. |

## 3. Honest deferrals (named, not half-built)

- **No real money movement.** No payment rail, card network, ACH/SEPA/UPI connection, or
  processor API exists in this codebase or this environment; this engine's "execution" is
  atomic bookkeeping over Delta's own D-021 ledger. The integration point for a future rail is
  named in Sec 1. Claiming more would be false.
- **No B2C end-user authentication.** Same deferral D-021 named: `require_admin` gates the
  surface until a real onboarding shell exists. A consumer-facing money endpoint behind a
  fabricated auth layer would be worse than the named gap.
- **No per-tenant configurable caps.** The $100/txn and $500/day ceilings are safe-default
  module constants (Fork 4). A per-tenant cap store (with its own audit trail and authorization
  story) is real, valuable future work this ADR does not claim to deliver.
- **No budget-aware rejection.** The engine does not consult D-021's `personal_budgets` to
  reject an over-budget execution — budgets are advisory tracking in D-021's design, and
  silently promoting them to hard spending controls would change that feature's meaning from
  the outside. An explicit opt-in budget-enforcement mode is named future work.
- **No async/queued execution, no retries, no reversal endpoint.** One synchronous request, one
  durable outcome. A reversal is a new manual D-021 transaction, not an engine feature yet.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Double-spend via request replay (network retry, client bug) | Idempotency-key lookup returns the stored outcome without re-executing; `UNIQUE (tenant_id, idempotency_key)` makes the duplicate-insert race structurally impossible (Fork 2) | `test_replayed_key_returns_original_without_reexecuting`, `test_replayed_rejection_is_replayed_not_retried` |
| Daily-cap TOCTOU race (two concurrent within-cap reads both commit) | Per-account `pg_advisory_xact_lock` serializes the read→insert critical section (Fork 5) | `test_daily_cap_enforced_exactly_at_boundary` (sequential proof) + code review of the lock placement before the cap read |
| Cap bypass via a single large transaction | `amount_minor_units le=MAX_MICRO_TRANSACTION_MINOR_UNITS` at the schema layer → 422 before the engine | `test_amount_above_micro_cap_rejected_422` |
| Cap bypass via many small transactions | Rolling 24h executed-sum per account; the request is rejected (and recorded) when `total + amount > DAILY_CAP` (Fork 6) | `test_daily_cap_exceeded_records_rejection`, `test_daily_cap_enforced_exactly_at_boundary` |
| Cross-tenant execution or probe | Tenant-scoped RLS session for every read/write; composite `(account_id, tenant_id)` FK; unknown and cross-tenant accounts both 404 with no side effects (Fork 7) | `test_cross_tenant_account_is_404`, `test_cross_tenant_executions_list_isolated` |
| Executed history rewritten to hide spend | No UPDATE/DELETE grant on `micro_transaction_executions` (append-only, DB ACL layer); D-009 hash-chain rows in the same transaction | `test_executions_table_has_no_update_delete_grant`, `test_execution_lands_in_d009_audit_chain` |
| Ledger/execution-log divergence (one commits without the other) | The execution row, `personal_transactions` row, and audit row are written on ONE session committed once | `test_executed_row_and_ledger_row_are_atomic` (asserts the paired txn exists with the exact negative amount) |
| Currency confusion / fabricated FX | `currency_mismatch` recorded rejection (Fork 8); no conversion path exists in the package | `test_currency_mismatch_records_rejection` |
| Float/bool money injection | `reject_non_integer` on `amount_minor_units` (the ecosystem-wide money rule) | `test_amount_rejects_float` |
| Log injection via free text | `_reject_control_chars` on merchant/description/requested_by; `idempotency_key` charset-constrained to the request-id-safe pattern | `test_control_characters_rejected` |

## 5. Verification

- `black --check .` / `ruff check .` clean.
- `alembic upgrade head` / `downgrade base` / `upgrade head` round trip clean (fresh Postgres) —
  including the `ck_personal_txn_source` widen/restore.
- `tests/micro_transactions/`: pure schema unit tests (no DB), DB-backed service tests (real
  RLS, real caps, real idempotency against Postgres), and non-stubbed HTTP e2e tests (real ASGI
  app, real auth, real DB) covering the full execute→ledger→audit path, replay semantics, cap
  boundary, and cross-tenant isolation.
- Full Delta suite green on a fresh Postgres — zero failures beyond the pre-existing,
  environment-gated skips documented in every prior ADR's Sec 5.

## 6. Alternatives considered

- **Fabricating a payment-rail integration (mock processor, fake webhook flow).** Rejected
  (Sec 1): a mock rail presented as "execution" is exactly the dishonesty the repo's language
  mandate exists to prevent, and it would teach downstream readers the wrong thing about what
  this system can do.
- **A separate execution-only ledger, leaving D-021's untouched.** Rejected (Fork 3): the same
  money would exist in two unreconciled places; D-021's budgets and health score would not see
  executed spend.
- **Enforcing D-021 budgets as hard caps in the engine.** Rejected (Fork 4/Sec 3): silently
  converts another feature's advisory concept into a control it never promised to be; named as
  explicit opt-in future work instead.
- **Caller-supplied cap overrides.** Rejected (Fork 4): a cap the request can raise is not a
  safety property.
- **Calendar-day cap window.** Rejected (Fork 6): the midnight reset creates a
  straddle-the-boundary double-spend window; rolling 24h has no cliff.
