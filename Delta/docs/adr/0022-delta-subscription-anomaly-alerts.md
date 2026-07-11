# ADR-0022 — Recurring-Subscription Registry + Trailing-Average Anomalous-Charge Alerts

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-022 (Automated subscription management + anomalous-charge alerts) · Builder: FinOps
  backend
- **Depends on:** D-009 (hash-chained audit log — every subscription/charge mutation lands there),
  D-012 (`chargeback.anomaly.detect_anomalies` — reused unmodified, not reimplemented), D-014
  (the `vendors` table a subscription may optionally link to)
- **Builds on:** D-012's ADR §2 Fork 1 trailing-average-ratio method and D-011's
  `current_rate_projection_v1` honesty-tagging precedent — both reused, neither re-derived.
- **Supersedes:** nothing. Adds a new `delta.subscriptions` package, one new migration (0015:
  `subscriptions`, `subscription_charges`), and one new router mount to
  `allocation_admin/app.py`; does not alter any D-001…D-021 runtime behavior, contract, or
  persistence schema.

## 1. Context

The roadmap's literal title for D-022 is *"Automated subscription management + anomalous-charge
alerts,"* filed under Phase 4's B2C personal-finance track: *"Depends on: D-003 + the B2C
onboarding shell."* As already established by this same unattended run's research for the
sibling task D-021 (and independently re-confirmed here by grep), **no B2C onboarding shell, no
personal/individual-account model, and no bank-linking of any kind exists anywhere in this
codebase** — Delta is, and has only ever been, an ENTERPRISE tenant's FinOps/ERP system. D-025
(privacy-first multi-bank aggregation — the only plausible source of a real external "here are
your subscriptions" bank-transaction feed) is itself still unbuilt. Building against a dependency
that does not exist would either fabricate a fake integration or silently narrow the task without
saying so — both violate this repo's honest-language mandate (CLAUDE.md).

This ADR instead builds D-022's title as a genuinely useful ENTERPRISE-tenant feature on Delta's
existing tenant/vendor model, reusing D-012's already-accepted, already-audited anomaly method
rather than inventing a new one:

1. **Subscription management** → a tenant-scoped registry of recurring commitments (SaaS
   licenses, vendor retainers, etc.), each optionally linked to a D-014 `vendors` row, with a
   forward-only lifecycle (active → cancelled) and an append-only ledger of each billing
   occurrence a tenant records against it. "Automated" here means *automated anomaly detection
   over recorded charges* (§2 below) — not automated discovery of subscriptions from a bank feed,
   which requires infrastructure this codebase does not have (§3).
2. **Anomalous-charge alerts** → flag a subscription whose most recently recorded charge is an
   outlier against that SAME subscription's own trailing charge history — the identical shape of
   signal D-012 already ships for departmental spend, applied to a different, finer-grained group
   (one subscription's own charge sequence instead of a department's calendar-window spend).

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — reuse `chargeback.anomaly.detect_anomalies` UNMODIFIED, do not reimplement** | The anomaly signal is computed by importing and calling D-012's pure `detect_anomalies` function as-is — same trailing-average RATIO method, same `SPEND_SPIKE`/`NEW_SPENDER` codes, same `DEFAULT_SPIKE_RATIO_THRESHOLD` (3.0x) and `DEFAULT_MIN_FLOOR_CENTS` ($10) defaults, same `trailing_average_ratio_v1` method tag on the response. | D-012's ADR (§2 Fork 1) already made — and an earlier audit already reviewed — the exact design decision this task would otherwise have to remake from scratch: no z-score/stddev/ML model, because the ecosystem has no forecasting/training-data precedent and small sample counts make variance-based methods unstable. A per-subscription charge history is, if anything, an even smaller sample than a department's daily spend buckets — the same "ratio against a trailing average, not a fitted statistical model" reasoning applies with even more force here. Reusing the function literally (not a fork/copy) also means a future fix to D-012's anomaly math benefits this feature for free, and there is exactly one anomaly algorithm in this codebase to audit, not two near-duplicates that can drift. |
| **2 — per-subscription baseline computed as a PRE-AVERAGED input, `baseline_periods=1`, one shared `detect_anomalies` call for every subscription** | D-012's baseline is one shared calendar window (every department's baseline covers the same `[baseline_start, baseline_end)`), so a single `baseline_periods` integer applies uniformly. A subscription's natural baseline is different: "however many of ITS OWN prior charges exist," which varies per subscription. Rather than forking `detect_anomalies` to accept a per-group divisor (widening an already-accepted pure function's contract) or calling it once per subscription (real N+1 risk), this task computes each subscription's own average (`sum(prior charges) / count(prior charges)`) in Python, then calls `detect_anomalies` exactly ONCE for every subscription in the report with `baseline_periods=1` — dividing an already-computed average by 1 leaves it unchanged, so the shared call's arithmetic is identical to what a per-subscription divisor would have produced. | Keeps `chargeback.anomaly` a single, unmodified, already-reviewed pure function (Fork 1) while still correctly handling that this task's "baseline window" is charge-count-shaped, not calendar-shaped. The alternative of widening `detect_anomalies`'s signature to accept a per-group baseline_periods dict was rejected as unnecessary complexity added to an already-accepted API for a need only this one caller has; passing a pre-averaged value under a `baseline_periods=1` divisor achieves the identical arithmetic without touching D-012's contract at all. |
| **3 — ONE windowed SQL query fetches the `window_size + 1` most recent charges for EVERY subscription in a report, never N+1** | `store.list_recent_charges_by_subscription` issues a single query using `ROW_NUMBER() OVER (PARTITION BY subscription_id ORDER BY charged_at DESC)`, filtered to `rn <= window_size + 1`, for the full list of active subscription ids at once. | Directly informed by D-012's own Fork 2 ("exactly 2 DB queries total, never N+1 per group") and D-011's audit Finding #1 (per-item sequential queries flagged as resource-amplification risk). A window-function query is the correct SQL-native way to get "top-N per group" in one round trip when each group's own N (its own baseline_periods, Fork 2) is derived from the SAME window_size but the group's available history differs — a plain `LIMIT` per subscription would require one query per subscription. |
| **4 — charge recording is NOT gated on subscription status** | `POST /{subscription_id}/charges` succeeds against an `active` OR `cancelled` subscription. | A charge that lands after a subscription was marked cancelled (billing lag, a final prorated invoice) is still a real, honest financial fact that should be recorded, not rejected. Gating charge recording on status would either lose that record entirely or force an operator to un-cancel/re-cancel just to log it — neither serves the "append-only, honest ledger" goal this feature exists for. Named here explicitly as a deliberate choice, not an oversight. |
| **5 — `subscription_charges` is append-only (SELECT, INSERT only — no UPDATE/DELETE grant)** | Mirrors D-018's `invoice_payments` / D-019's `sync_line_items`: a correction to a mis-recorded charge is a NEW charge row (optionally with a `note` explaining the correction), never an edit to history. | A charge ledger that can be silently rewritten after the fact is not a trustworthy input to an anomaly detector — an operator could otherwise "fix" a spike out of the history that flagged it. Immutability here is a correctness property for the anomaly signal itself, not just an audit-log nicety. |
| **6 — every create/cancel/charge lands in D-009's hash-chained audit log** | `append_history` is called in the SAME transaction as every `subscriptions`/`subscription_charges` write, with `entity_type` of `"subscription"` (create/cancel) or `"subscription_charge"` (each recorded charge). | Mirrors D-014's PO-decision wiring and D-018's invoice-payment wiring: a recorded charge is a genuine financial event (money a tenant is tracking as owed/paid on a recurring basis), not business-process metadata like D-013's CRM edits — it gets the same tamper-evident treatment every other Delta financial mutation does. |
| **7 — `vendor_id` is OPTIONAL, validated against the SAME shared `vendors` table every other package queries directly (no cross-package `erp.store` import)** | `SubscriptionCreateRequest.vendor_id` may be omitted; when present, `subscriptions.store.get_vendor_status` runs the identical query shape as `invoicing.store.get_vendor_status` — reading `delta.persistence.models.vendors` directly, not calling into `delta.erp.store`. | A subscription is a real, useful concept even for a tenant that hasn't registered every vendor in D-014's directory (e.g. a fast-moving SaaS spend the finance team wants tracked before procurement formally onboards the vendor) — making it mandatory would block the feature on an unrelated workflow. The "query the shared table directly, don't cross-import another feature's store module" choice mirrors the established precedent set by `invoicing.store.get_vendor_status` (D-018) rather than inventing a new cross-package coupling shape. |
| **8 — explicit, versioned method tag, reused literal-for-literal from D-012** | The response always carries `method: "trailing_average_ratio_v1"` — the exact same string D-012 uses, not a new `subscription_trailing_average_v1`-style tag. | The underlying math IS identical (Fork 1) — current value vs. a trailing average, ratio-thresholded. Minting a cosmetically different tag for the same method would misrepresent it as a different algorithm to a downstream reader. If the method ever diverges from D-012's, it gets a genuinely NEW literal at that time, per the same discipline D-011/D-012 already established. |
| **9 — mounted on the existing admin app, not a new process** | `POST /v1/admin/subscriptions`, `GET /v1/admin/subscriptions`, `POST /v1/admin/subscriptions/{id}/cancel`, `POST/GET /v1/admin/subscriptions/{id}/charges`, `GET /v1/admin/subscriptions/anomalies` on the same D-007 admin app, same `require_admin` break-glass bearer auth. | Same operators, same auth, same trust boundary — mirrors every prior Delta admin feature's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No B2C personal-account model, no bank-linking, no automated subscription DISCOVERY.** This
  task builds the tracking/lifecycle/anomaly-alerting mechanism for subscriptions a tenant
  registers itself (or links to an ERP vendor); it does not, and cannot honestly claim to, scan a
  bank or card feed to find subscriptions automatically — that requires D-025 (multi-bank
  aggregation), which does not exist in this codebase. "Automated" in this task's shipped scope
  refers specifically to the anomaly *detection* being automatic once a charge is recorded, not to
  automatic charge *discovery*.
- **No trained/validated statistical or ML anomaly-detection model.** Same deferral D-012 already
  named and this task explicitly reuses rather than re-litigates (Fork 1).
- **No underspend / "subscription went quiet" signal.** Mirrors D-012 Fork 6: only an outlier
  CURRENT charge is flagged; a subscription that simply stopped billing (no new charge recorded at
  all) produces no signal, since `detect_anomalies` only evaluates groups present in
  `current_by_group`. Real, plausible future work, named here rather than silently absent.
- **No price-drift-vs-`expected_amount_minor_units` comparison.** A subscription may optionally
  declare an expected/plan amount at creation time, but the anomaly report compares a charge only
  against that subscription's own charge HISTORY, never against the declared expectation. Adding
  that second, independent signal is real future work this ADR does not claim to deliver — folding
  it in here would be exactly the kind of scope-widening-under-ambiguity this run's operating
  procedure is instructed to avoid.
- **No anomaly acknowledgment/history.** Mirrors D-012's identical deferral: every report
  recomputes live; nothing persists a flagged anomaly or an operator's "dismissed" action.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant subscription/charge/anomaly leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`, opened via `get_tenant_session(tenant_id)` — the strict fail-closed NULLIF RLS predicate (migration 0015) confines every SELECT/INSERT/UPDATE to the caller's own tenant, including the windowed `list_recent_charges_by_subscription` query (Fork 3) | `test_subscription_cross_tenant_isolation`, `test_charge_cross_tenant_isolation`, `test_anomaly_report_cross_tenant_isolation`, `test_cross_tenant_over_http` |
| A subscription belonging to another tenant, or a nonexistent `vendor_id`, silently accepted | `vendor_id`'s existence is checked via `store.get_vendor_status` before insert (404 `vendor_not_found` on failure); the composite `(vendor_id, tenant_id)` FK (migration 0015) makes a cross-tenant vendor link structurally impossible even if the app-layer check were bypassed | `test_create_subscription_missing_vendor_raises`, `test_vendor_fk_blocks_cross_tenant_link_at_db_level` |
| Concurrent double-cancel | `try_cancel_subscription`'s conditional UPDATE only matches a row still `active` (same shape as D-014's `try_transition_asset_status`); a second concurrent cancel gets `rowcount == 0` → `SubscriptionAlreadyCancelledError`, never a silent no-op success | `test_cancel_already_cancelled_subscription_raises` |
| N+1 query amplification computing the anomaly report | `get_anomaly_report` issues exactly 2 queries total (`list_subscriptions` + the single windowed `list_recent_charges_by_subscription`), regardless of how many subscriptions or charges exist, bounded by `_MAX_SUBSCRIPTIONS = 100` and `MAX_RECENT_CHARGES_WINDOW = 25` | code review — no loop over subscriptions issues a query; `test_anomaly_report_query_count_is_constant` |
| `baseline_window` used to force an unbounded per-subscription scan | `SubscriptionAnomalyQuery.baseline_window` is capped `1..24` at the schema layer; `store.list_recent_charges_by_subscription` additionally clamps to `MAX_RECENT_CHARGES_WINDOW = 25` server-side even if a caller bypassed the schema layer | `test_baseline_window_out_of_range_rejected` |
| Below-floor noise / flat charges flagged as anomalous | Reuses D-012's own already-verified `min_floor_cents`/`ratio_threshold` gates unmodified (Fork 1) | `test_flat_subscription_charges_not_flagged` (this task) plus D-012's own existing `test_below_floor_never_flagged_even_at_huge_ratio`/`test_flat_spend_is_not_flagged` (unmodified, still covering the shared function) |
| Money handling: float/bool coercion into a monetary field | `expected_amount_minor_units`/`amount_minor_units` both pass through `money.reject_non_integer` (mirrors D-014's `AssetCreateRequest._cost_strict_integer`); DB `CHECK` constraints additionally reject negative amounts | `test_charge_amount_rejects_float`, `test_expected_amount_rejects_bool` |
| A subscription's `expected_amount_minor_units`/`currency` pairing left inconsistent (D-013's Finding #1 class of bug) | `(expected_amount_minor_units IS NULL) = (currency IS NULL)` DB CHECK (migration 0015), plus the same app-layer default-currency-when-amount-given logic D-014's `create_asset` already uses | `test_create_subscription_currency_defaults_when_amount_given` |
| Naive-datetime `charged_at` silently misinterpreted as UTC | `require_aware_utc` (D-008's own validator, reused unchanged) rejects any `charged_at` without an explicit timezone offset | `test_naive_charged_at_rejected` |
| Control-character / log-injection payloads in `name`/`created_by`/`recorded_by`/`note` | Every free-text field passes through a local `_reject_control_chars` check (mirrors D-014's `erp.schemas` identical helper) | `test_name_rejects_control_characters` |
| `subscription_charges` rewritten after the fact to erase a flagged spike | No UPDATE/DELETE grant to `delta_app` on `subscription_charges` (migration 0015, Fork 5) — enforced at the database ACL layer, not just application code | `test_subscription_charges_table_has_no_update_delete_grant` |

## 5. Verification

- `black --check .` / `ruff check .` clean.
- `alembic upgrade head` / `downgrade base` / `upgrade head` round trip (fresh Postgres, CI
  `migration-roundtrip` job) — clean both directions.
- `tests/subscriptions/` suite: pure schema-validation unit tests (no DB/no I/O), DB-backed
  service tests (real Postgres, real RLS) covering the vendor-link check, forward-only cancel
  guard, and the D-009 audit-chain wiring on create/cancel/charge, plus non-stubbed HTTP e2e tests
  (real ASGI app, real auth, real DB) covering cross-tenant isolation and the anomaly report end
  to end (a genuine spike seeded via real recorded charges, not hand-computed).
- Full Delta suite green on a fresh Postgres — zero failures beyond the pre-existing,
  environment-gated skips unrelated to this task (documented in every prior ADR's own §5).
- `semgrep scan --config=p/python --severity=ERROR --no-git-ignore src/` clean.

## 6. Alternatives considered

- **A second, independent anomaly algorithm tailored to subscriptions (e.g. comparing against
  `expected_amount_minor_units` instead of history).** Rejected for this task (named as a
  deferral in §3, not built): D-012's trailing-average-ratio method already does exactly what an
  anomalous-charge alert needs — flag an outlier against a group's own history — and reusing it
  unmodified avoids a second, divergence-prone implementation of the same underlying idea.
- **Forking `chargeback.anomaly.detect_anomalies` to accept a per-group `baseline_periods` dict.**
  Rejected (Fork 2): widens an already-accepted, already-audited pure function's public contract
  for the sole benefit of one new caller; the `baseline_periods=1` pre-averaged-input approach
  achieves identical arithmetic without touching D-012's code at all.
- **A B2C personal-subscription feature gated behind a fabricated "onboarding shell."** Rejected
  (§1): would require inventing infrastructure (personal accounts, bank-linking) this codebase
  does not have and this task cannot responsibly build unilaterally — exactly the honesty
  violation CLAUDE.md's mandatory-language rule and this run's own operating discipline exist to
  prevent.
- **Requiring `vendor_id` on every subscription.** Rejected (Fork 7): would block the feature on
  an unrelated D-014 procurement workflow for tenants that simply want to track a recurring cost
  without first formally onboarding a vendor.
