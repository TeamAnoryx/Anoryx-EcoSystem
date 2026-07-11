# D-023 Security Audit — Personal Asset-Allocation + Micro-Investment Recommendations (B2C Track)

- **Date:** 2026-07-11
- **Scope:** `Delta/src/delta/asset_allocation/` (the entire new package — `schemas.py`,
  `store.py`, `service.py`, `router.py`),
  `Delta/src/delta/persistence/migrations/versions/0016_asset_allocation.py` (new
  `personal_allocation_recommendations` table, RLS, SELECT+INSERT-only grants, CHECK
  constraints, composite tenant-scoped FK to `personal_accounts`), the additive changes
  to `identifiers.py`/`persistence/models.py`, the one new router mount in
  `allocation_admin/app.py`, and `Delta/tests/asset_allocation/` (read for
  coverage/gaps, not just presence). ADR-0023 existed at review time and was used to
  distinguish deliberate design decisions (tenant-wide surplus computation, fixed
  risk-tier allocation table, append-only history, no audit-chain wiring) from
  candidate bugs.
- **Reviewers:** two independent, arms-length passes — a `code-reviewer` pass
  (correctness/contract-conformance/maintainability) and a `security-auditor` pass
  (trust boundaries, injection, auth, money handling), both performing their own read
  of every source file rather than trusting this ADR or the implementer's description.
  A Semgrep registry pull (`p/python`) was blocked by this environment's egress
  policy (the same known limitation recorded in every prior audit this session); both
  reviewers substituted a full manual review of the trust boundaries instead of
  routing around the policy.
- **Verdict:** **CLEAN of High/Critical findings.** One **Medium/Low** finding
  (correctness, security-adjacent — a money-handling rule violation, no data leak, no
  auth gap) independently reproduced by BOTH reviewers, plus one **Medium** test-
  coverage gap from the code-reviewer pass — **both fixed below, before this diff
  shipped.**

## Findings

### Medium (code-reviewer) / Low (security-auditor) — micro-investment amount computed via float multiplication, violating the codebase's integer-only money rule (FIXED)

- **Location:** `Delta/src/delta/asset_allocation/service.py`
  (`_recommended_micro_investment_minor_units`, pre-fix) /
  `Delta/src/delta/asset_allocation/schemas.py` (`MICRO_INVESTMENT_SURPLUS_RATE`,
  pre-fix).
- **Issue:** the original implementation computed
  `int(surplus_minor_units * MICRO_INVESTMENT_SURPLUS_RATE)` where
  `MICRO_INVESTMENT_SURPLUS_RATE = 0.10` is a Python `float` literal. `money.py`
  states explicitly, project-wide: *"Money is held as integer minor units (cents) —
  never a float. Floats are forbidden in every monetary field across Delta."* No
  other monetary computation anywhere in Delta multiplies minor-units by a float —
  both reviewers independently flagged this as a novel pattern this diff introduced,
  and both independently verified numerically that it is not exact: for
  `surplus_minor_units = 9_000_000_000_000_009`,
  `int(surplus_minor_units * 0.10) == 900_000_000_000_001` — **one minor unit ABOVE**
  the true 10% floor (`9_000_000_000_000_009 // 10 == 900_000_000_000_000`), because
  IEEE-754 cannot represent `0.10` or the product exactly at that magnitude. This
  directly contradicts ADR-0023 Fork 3's documented "never over-recommends" invariant.
  `personal_transactions.amount_minor_units` has no DB-level upper bound (unlike the
  request-schema-level `MAX_AMOUNT_MINOR_UNITS` guard, which only applies to
  client-supplied values — a tenant's SUMMED transaction history over time is
  unbounded), so the magnitude required to trigger this is reachable in principle,
  even though realistically remote (~$90 trillion at cent precision for a single
  window).
- **Exploit scenario:** not practically exploitable at realistic scale — requires a
  tenant net surplus above ~9e15 minor units in one query window. No cross-tenant
  impact, no negative value, bounded to a single minor unit of over-recommendation.
  Flagged and fixed as a correctness/honesty-boundary violation regardless: the
  codebase's money discipline is a hard invariant (CLAUDE.md: "Delta: all money is
  integer minor units. Never floats"), not a best-effort guideline, and the ADR's own
  claimed guarantee was not actually true by construction.
- **Fix applied:** `MICRO_INVESTMENT_SURPLUS_RATE` (a float) replaced with
  `MICRO_INVESTMENT_SURPLUS_RATE_BPS = 1000` (an exact integer, basis points out of
  10,000). `_recommended_micro_investment_minor_units` now computes
  `(surplus_minor_units * MICRO_INVESTMENT_SURPLUS_RATE_BPS) // 10_000` — exact
  integer arithmetic, `//` floors a nonnegative numerator at any magnitude, no float
  anywhere in the monetary path. New regression test:
  `test_large_surplus_micro_investment_uses_exact_integer_math` (asserts the exact
  floor at the same magnitude both reviewers used to demonstrate the bug — proves the
  fix numerically, not just "it looks right now").

### Medium (code-reviewer) — no test distinguished tenant-wide surplus from the rejected account-scoped alternative (FIXED)

- **Location:** `Delta/tests/asset_allocation/test_store_db.py` /
  `test_service_db.py` (pre-fix).
- **Issue:** ADR-0023 Fork 4 — the most architecturally significant decision in this
  feature — states surplus is computed TENANT-WIDE across all of a tenant's
  `personal_transactions`, not scoped to the target investment account. Every
  pre-existing surplus test recorded transactions only on the very account being
  recommended against, so the suite could not distinguish the actual, intentional
  implementation ("sum every `personal_transactions` row for the tenant") from the
  explicitly-rejected alternative ("sum only the target account's own transactions")
  — both would have passed every test that existed. A future maintainer unaware of
  Fork 4's reasoning adding an "obviously correct-looking" `account_id` filter to
  `store.get_net_surplus_minor_units` would silently regress this and nothing would
  catch it.
- **Fix applied:** new regression test
  `test_surplus_computed_tenant_wide_across_all_accounts` seeds a SECOND
  `personal_accounts` row (`type="checking"`) for the same tenant, records a
  transaction against it, and asserts that transaction's amount is reflected in the
  surplus of a recommendation computed against a DIFFERENT (`investment`) account —
  the one test shape that can only pass under the actually-intended, tenant-wide
  behavior.

## What was actively verified and found sound

- **Authentication.** `require_admin` is a router-level dependency on the
  `APIRouter` and all three routes inherit it — including `GET /risk-tiers`, the one
  route with no DB access at all, still gated for consistency rather than carved out
  as a public exception. Fail-closed, constant-time `hmac.compare_digest`, no
  per-route opt-out.
- **Cross-tenant isolation.** RLS is `ENABLE` + `FORCE` with the strict `NULLIF`
  transaction-local GUC predicate on the new table (migration 0016, same shape as
  0014/0015); `delta_app` is `NOBYPASSRLS`; every query runs in the caller's own
  `get_tenant_session(tenant_id)`. `service.create_recommendation`'s
  `account is None or account.tenant_id != req.tenant_id` check runs BEFORE the
  investment-type check — a cross-tenant `account_id` is filtered by RLS to `None`
  and correctly returned as 404 (`AccountNotFoundError`), never leaked and never
  allowed to fall through to the type check. Verified by both reviewers
  independently.
- **SQL injection.** All SQL is SQLAlchemy Core with bound parameters — no
  string-interpolated SQL in `store.py`; the migration's f-string DDL interpolates
  only trusted module constants (schema/role/table names), consistent with the
  existing `S608` semgrep-suppression scope for this directory.
- **Money handling — no client-supplied monetary field at all.**
  `AllocationRecommendationRequest` carries only `tenant_id`/`account_id`/
  `risk_tier` (a closed enum)/`period_start`/`period_end`, `extra="forbid"`. Every
  dollar figure in a response (`surplus_minor_units`,
  `recommended_micro_investment_minor_units`) is computed server-side from already-
  validated `personal_transactions` rows — there is no wire input to coerce, an
  entire injection/overflow class removed by construction rather than by validation.
- **DB constraint / ORM-invariant cross-check.** `service.py` always writes
  percentages from the fixed, sum-to-100 `RISK_TIER_TARGET_ALLOCATION_PCT` table and
  a `recommended_micro_investment_minor_units` value that is provably `>= 0`
  (post-fix) — there is no code path by which the service layer could construct a row
  violating its own DB `CHECK` constraints (`cash_pct + bonds_pct + equities_pct =
  100`, `period_end > period_start`, `recommended_micro_investment_minor_units >=
  0`).
- **Append-only guarantee.** Migration 0016 grants `delta_app` only `SELECT, INSERT`
  on `personal_allocation_recommendations` — no `UPDATE`/`DELETE` — enforced at the
  database ACL layer, verified directly via `information_schema.role_table_grants`
  in `test_recommendations_table_has_no_update_delete_grant`.
- **Composite FK correctness.** `(account_id, tenant_id) -> personal_accounts` is
  backed by the pre-existing `uq_personal_account_id_tenant` unique constraint
  (migration 0014); a recommendation against a nonexistent account is structurally
  impossible at the DB layer even if the app-layer check were bypassed.
- **Naive-datetime handling.** `require_aware_utc` (D-008's validator, reused
  unchanged) rejects any `period_start`/`period_end` without an explicit timezone
  offset; `period_end <= period_start` is rejected at the schema layer with a DB
  `CHECK` as defense in depth.

## Verification after fixes

- `Delta/tests/asset_allocation/` — 36 tests (up from 34: two new regression tests
  across the two findings). 11 pure schema-validation tests pass locally (no DB); the
  25 DB-backed store/service/router e2e tests self-skip in this sandboxed environment
  (no live Postgres available) and are the authority of the CI `ledger-db` job on a
  fresh Postgres, per this repo's banked "CI is authoritative" rule — they are not
  independently claimed as passing until that job is green.
- `black --check .` / `ruff check .` clean on the full repository after the fix.
- ADR-0023 §2 Fork 3/Fork 4 and §4 (threat model) record both findings and their
  fixes.
