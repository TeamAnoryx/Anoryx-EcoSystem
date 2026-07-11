# D-023 Security Audit — Personal Asset Allocation + Micro-Investment Recommendations

- **Date:** 2026-07-11
- **Scope:** `Delta/src/delta/investments/` (the entire new package — `schemas.py`,
  `store.py`, `service.py`, `router.py`),
  `Delta/src/delta/persistence/migrations/versions/0017_investment_holdings.py`
  (new `investment_holdings` table, RLS, SELECT+INSERT-only grants, CHECK
  constraints, composite tenant-scoped FK), the additive changes to
  `identifiers.py`/`persistence/models.py`, the one new router mount in
  `allocation_admin/app.py`, `Delta/tests/investments/` (read for coverage/gaps).
  ADR-0023 existed at review time and was used to distinguish deliberate design
  decisions (broad asset classes not tickers, self-reported values, fixed
  target-weight profiles, no trade execution) from candidate bugs.
- **Reviewer:** independent security-auditor pass, arms-length from the
  implementer, performing its own read of every in-scope file. The Semgrep
  registry (`p/python`/`p/security-audit`/`p/secrets`) was blocked by this
  environment's egress policy (a known limitation recorded in every prior audit
  this session); the reviewer substituted a full manual review of the trust
  boundaries covering the same finding classes instead of routing around the
  policy.
- **Verdict:** **CLEAN of High/Critical findings.** One **Medium** finding (real
  monetary-correctness defect) and three **Low** findings. The Medium and one Low
  are fixed below, before this diff shipped; the remaining two Lows are documented
  residual scope, consistent with this codebase's existing precedent for the same
  shared pattern.

## Findings

### Medium — portfolio total silently truncated by the 500-row list limit (FIXED)

- **Location:** `Delta/src/delta/investments/service.py`
  (`get_allocation_recommendation`, pre-fix), which called the LIST-shaped
  `store.get_latest_holdings(..., limit=store.MAX_LIST_LIMIT)` to compute
  `total_portfolio_value_minor_units`.
- **Issue:** a display-endpoint row cap (500) was reused to feed a monetary
  aggregate. A tenant whose count of distinct latest `(account_id, asset_class,
  currency)` snapshots exceeds 500 (≈84+ investment accounts) would have their
  portfolio total silently understated, with wrong `current_pct`/`drift_pct` and
  therefore wrong buy/sell recommendations — no error surfaced. The exact
  "silently misstate a monetary total" class this codebase elsewhere guards
  against (D-023's own largest-remainder contribution split exists specifically
  to avoid this class of bug).
- **Fix applied:** added `store.get_total_value_by_asset_class(session, *,
  currency)` — a genuine SQL `SUM()`/`GROUP BY` aggregate over the latest snapshot
  per `(account_id, asset_class)`, with **no** `LIMIT` clause of any kind.
  `get_allocation_recommendation` now calls this instead of the list helper;
  `get_latest_holdings` remains list-endpoint-shaped and keeps its `limit` param
  for the `GET /holdings` display route only. New regression tests:
  `test_get_total_value_by_asset_class_sums_across_accounts`,
  `test_get_total_value_by_asset_class_sums_only_the_latest_snapshot`.

### Low — `currency=None` list path hid a same-account, same-class holding in a second currency (FIXED)

- **Location:** `Delta/src/delta/investments/store.py` (`get_latest_holdings`,
  pre-fix).
- **Issue:** the "latest per pair" grouping subquery grouped by `(account_id,
  asset_class)` only, omitting `currency`, when the plain `GET /holdings`
  endpoint calls it with `currency=None`. If one account held the same asset
  class in two currencies (e.g. USD stocks and EUR stocks), `MAX(created_at)`
  picked only the more-recently-created row — the other currency's
  self-reported holding silently disappeared from the list view. The
  allocation-recommendation path was unaffected (it always passes an explicit
  `currency`).
- **Fix applied:** `currency` is now part of the grouping key in both the filter
  subquery and the join predicate, so each `(account_id, asset_class, currency)`
  triple gets its own "latest" snapshot regardless of how many currencies one
  account/class pair spans. New regression test:
  `test_get_latest_holdings_unscoped_keeps_same_class_in_different_currencies`.

### Low — recommendation currency hardcoded to USD, no caller override (documented, not fixed)

- **Location:** `Delta/src/delta/investments/router.py`
  (`get_allocation_recommendation`, `currency=DEFAULT_CURRENCY`).
- **Issue:** a tenant whose holdings/income/expense are entirely in a non-USD
  currency receives an all-zero, all-`hold` recommendation labeled
  `currency="USD"`, with no indication that their actual (non-USD) data was
  excluded from the computation.
- **Disposition:** this mirrors D-021's own `GET /health-score` route
  (`currency=DEFAULT_CURRENCY`, no query override) byte-for-byte — the same
  established single-reporting-currency convention this package's ADR (§2 Fork 8)
  deliberately adopted from D-021 rather than inventing a new one. Not made worse
  by this PR; the response is honestly labeled `USD` (no false claim), so it does
  not violate the honest-language mandate. A future task could add an optional
  reporting-currency query parameter across both D-021 and D-023 together — noted
  as real, named future work rather than fixed unilaterally in one package here.

### Low — a timestamp tie in `created_at` could double-count two snapshots (documented, not fixed)

- **Location:** `Delta/src/delta/investments/store.py` (the "latest per pair"
  self-join in both `get_latest_holdings` and `get_total_value_by_asset_class`).
- **Issue:** the join matches on `created_at` equality; two snapshots for the
  same `(account_id, asset_class[, currency])` written at the IDENTICAL
  timestamp would both satisfy the join and both be summed/returned.
- **Disposition:** effectively unreachable via the HTTP path — every
  `POST /holdings` call stamps `created_at` from `datetime.now(timezone.utc)` at
  microsecond resolution inside the request handler, not attacker-controllable.
  Identical shape to D-021's own `personal_budgets` "latest per category" query
  (never flagged as a finding there either); not introduced or worsened by this
  PR. Noted for completeness. A future hardening pass could switch to a
  `ROW_NUMBER() OVER (... ORDER BY created_at DESC, holding_id DESC) = 1`
  tiebreaker across both D-021 and D-023 uniformly.

## What was actively verified and found sound

- **Authentication.** `require_admin` is a router-level dependency on the
  `APIRouter` and all 3 routes inherit it (constant-time `hmac.compare_digest`,
  Bearer scheme required, fail-loud token load) — no auth gap, no per-route
  opt-out.
- **Cross-tenant isolation.** RLS is `ENABLE` + `FORCE` with the strict
  `NULLIF` transaction-local GUC predicate on `investment_holdings`; `delta_app`
  is `NOBYPASSRLS`; every query runs in the caller's own
  `get_tenant_session(tenant_id)`. A non-existent account and an other-tenant
  account both yield the same `AccountNotFoundError` → 404, so there is no
  existence-probing side channel across tenants.
- **Account-type enforcement.** `record_holding` re-fetches the account under
  the tenant session and enforces `tenant_id` match + `type == "investment"`
  before insert, in the same transaction; the composite FK
  `(account_id, tenant_id) → personal_accounts` and RLS `INSERT ... WITH CHECK`
  are structural backstops. `store.create_holding` is only reachable through
  `record_holding` on the production path.
- **Numeric/monetary correctness.** `value_minor_units` is `ge=0`,
  `le=1e11`, and `reject_non_integer` rejects both `bool` and `float` wire
  values. `_split_by_weights`'s largest-remainder allocation was verified to
  always produce non-negative parts summing exactly to the total, with
  zero-weight asset classes never receiving a leftover unit (the remainder is
  bounded by the count of positive-weight classes, since weights sum to 1.0
  exactly). The empty-portfolio path returns `current_pct`/`drift_pct = None`
  (never a divide-by-zero placeholder) and `hold`/0.
- **Target-weight integrity.** `_validate_target_allocations` runs at module
  import time and `raise`s (not `assert`, so it cannot be stripped by `-O`),
  checking both full asset-class coverage and `abs(sum - 1.0) < 1e-9` for all
  three risk profiles — backed by `test_target_allocations_sum_to_one`.
- **Currency mixing (recommendation path).** Both the portfolio total and
  `personal_finance.get_income_expense_totals` are scoped to the same
  `currency` parameter — no cross-currency summation on the path that actually
  drives recommendations (ADR-0023 §2 Fork 8).
- **SQL injection.** All store queries are parameterized SQLAlchemy Core; the
  migration's f-strings interpolate only internal constants (schema/table/RLS
  predicate/fixed asset-class list) — no request-derived data anywhere.
- **Honest-language compliance.** The package writes only to
  `investment_holdings`, never to `personal_transactions` — no claim of real
  money movement or trade execution anywhere in code, responses, or docs;
  every response is labeled `method="fixed_target_weights_v1"` and the ADR
  explicitly disclaims ML/live-market-data. Respects every ADR-0023 §3 deferral.

## Verification after fixes

- `Delta/tests/investments/` — 37 tests (up from 34: three new regression tests
  across the two fixed findings), all passing against live local Postgres.
- `black --check .` / `ruff check .` clean (scoped to `src/delta/investments` +
  `tests/investments`; the full-repository check is re-verified in CI).
- Full existing Delta suite green — zero regressions from either fix.
- ADR-0023 is the design record; this document is the audit record — no design
  fork changed as a result of these fixes, only the two query implementations.

## Process note

Semgrep could not be run against its rulesets in this sandbox because
`semgrep.dev` is blocked by egress policy (403 on CONNECT) — the same
environment-wide limitation recorded in every prior audit this session. CI's
`quality` job (which has registry access) is the automated SAST authority of
record for this PR; the manual review above covers the same finding classes
(SQLi, secrets, crypto misuse, injection) independently.
