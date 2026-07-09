# ADR-0013 — Unified CRM (Deal Pipeline, Stakeholder Roster, Interaction History, Relationship Scoring)

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-013 (Unified CRM) · Builder: orchestration-hooks · Phase 3 (post-investment
  vision) — greenlit explicitly by the user to proceed past Delta's committed MVP
  (D-001→D-012, all shipped) into the 🏦 vision tier, starting with D-013.
- **Depends on:** D-001 (the identifier/domain-type conventions this task extends),
  D-003 (indirectly — CRM tables are new, not ledger-backed, but the tenant-RLS
  pattern D-003 established governs them identically)
- **Builds on:** D-007's admin-surface conventions (`require_admin`, one shared FastAPI
  app, `extra="forbid"` + control-character-rejected free text), D-008's window/scope
  validation conventions, D-011/D-012's "simple deterministic heuristic, not ML"
  honesty-boundary precedent and their security-review-driven query-amplification
  discipline (applied here proactively, not reactively).
- **Supersedes:** nothing. Adds a new `delta.crm` package, four new tables (migration
  0007), and one new router mount to `allocation_admin/app.py`; does not alter any
  D-001…D-012 runtime behavior, contract, or persistence schema.

## 1. Context

The roadmap's literal text for D-013 is: *"Complete enterprise deal pipeline, client
interaction history, relationship scoring, automated stakeholder mapping."* Tagged
`🏦 POST-INVESTMENT` — *"Committed vision, scheduled after a funding round — each is
effectively a sub-product"* — and sized "28h+ (Heavy)." Taken at face value, "complete
enterprise deal pipeline" and "automated stakeholder mapping" could imply
Salesforce-class feature breadth (custom fields, email/calendar sync, territory
management) or an NLP-driven contact-extraction pipeline. Before writing any code, the
same discipline D-011's ADR applied to "predictive modeling" applies here: there is no
CRM, contact-graph, or NLP-extraction precedent anywhere in the Anoryx ecosystem to
build against, and attempting full enterprise-CRM parity in a single unattended pass
would be exactly the kind of scope-widening-under-ambiguity this run's operating
procedure is instructed to avoid. This ADR scopes D-013 down to a deliberately bounded
**vertical slice** that honestly delivers all four named capabilities at a
proportionate depth, and names everything larger as a deferral rather than half-building
it.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — deterministic recency + frequency relationship score, not ML** | `delta.crm.scoring.compute_relationship_score` is a fixed step-function sum: a recency component (0–50, based on days since last interaction), a frequency component (0–40, based on interaction count in a trailing 90-day window), and an open-pipeline component (0–10, based on open deal count) — summing to exactly 100. Method is a literal, versioned tag (`recency_frequency_v1`), mirroring D-011's `current_rate_projection_v1` and D-012's `trailing_average_ratio_v1`. **Not** a trained/validated statistical or ML model. | Same reasoning as D-011/D-012: no ecosystem precedent for real scoring/ML anywhere in Sentinel, the Orchestrator, or Rendly. A simple, explainable, deterministic score an operator can verify by hand in one sentence is more honest than a black-box number this run has no way to validate or backtest. |
| **2 — deal-stage terminality is an app-level rule, not a DB CHECK constraint** | `deals.stage` is a plain `sa.String(16)` column; `won`/`lost` immutability is enforced by `delta.crm.store.try_transition_deal_stage`'s conditional `UPDATE ... WHERE stage NOT IN ('won','lost')` (the same conditional-UPDATE race-guard shape as D-007's `try_decide_allocation`), not a database-level CHECK restricting the stage vocabulary. | A DB CHECK on the exact stage set would force a migration every time the stage vocabulary changes; the terminality invariant (the actual business rule that matters) is enforced structurally at the query layer regardless of how many stages exist, and is directly tested (`test_deal_stage_transition_succeeds_once_then_blocked_when_terminal`). |
| **3 — stakeholder mapping is structured tagging + live-computed engagement, not NLP extraction** | "Automated stakeholder mapping" is implemented as: (a) stakeholders are explicit, structured rows (name/role/email), and (b) an interaction can optionally tag ONE `stakeholder_id`, from which `interaction_count`/`last_interaction_at` per stakeholder are computed LIVE via a single SQL `LEFT JOIN ... GROUP BY` (`delta.crm.store.list_stakeholders_for_client`) — never stored, never derived by parsing `summary` free text for names. | The word "automated" is satisfied honestly: an operator never manually tallies "how many times have I talked to Bob" — the system computes it. But NLP-driven entity extraction from unstructured text (inferring stakeholders nobody explicitly tagged) is a fundamentally different, much larger capability with no precedent or validation harness in this codebase — named as a deferral (§3), not silently approximated by fragile name-matching. |
| **4 — CRM mutations are NOT wired into D-009's hash-chained financial audit log** | `delta.persistence.audit_log.append_history` (D-009) is not called anywhere in `delta.crm`. | D-009's own module docstring scopes that chain to Delta's **automated financial workflows** (allocations, budget-engine enforcement, kill-switch, reconciliation failures) — deal-stage transitions and stakeholder edits are business-process data, not financial transactions or enforcement decisions, even though a deal carries an optional `value_minor_units`. Wiring an unrelated domain into a chain scoped and reviewed for a different purpose would blur that chain's own audited boundary. Named as a deliberate scope decision, not an oversight — a dedicated, non-financial CRM change-history log is real future work (§3). |
| **5 — composite tenant-scoped FKs + an explicit client-scope check above them** | Every CRM table's foreign keys are composite `(entity_id, tenant_id)` pairs (mirrors D-007's `allocation_targets → allocations` pattern) — structurally impossible for a deal/stakeholder/interaction to reference another tenant's parent row. Above that, `delta.crm.service` adds an explicit CLIENT-scope check (`_check_deal_scope`/`_check_stakeholder_scope`) before tagging an interaction to a deal or stakeholder, because the FK alone proves same-TENANT, not same-CLIENT. | An FK stops cross-tenant reference (a security boundary); it does not stop a caller from tagging Client A's interaction with Client B's deal (a data-integrity bug, same tenant, still wrong). Both checks are real and independently tested (`test_interaction_tagged_to_deal_from_another_client_rejected`). |
| **6 — exactly O(1) queries per detail view, never one-per-row** | Stakeholder engagement is one `LEFT JOIN ... GROUP BY` query (Fork 3), never one query per stakeholder. A client's relationship-score inputs (`get_client_engagement_summary`) are two small aggregate queries (`COUNT ... FILTER` + `MAX`, and a deal-stage `COUNT`), never a scan of every interaction/deal row into Python. | Directly informed by D-011's security review (Finding #1: per-budget sequential queries) and D-012's own proactive design (Fork 2: exactly 2 `top_spenders` calls for an anomaly report) — this task applies the same "small number of queries per request regardless of row count" discipline from the first draft, not as a post-audit fix. |
| **7 — chargeback/showback's honesty-boundary language extended: CRM is not billing, and a deal value is not a committed contract** | `value_minor_units` on a deal is optional, capped at `MAX_DEAL_VALUE_MINOR_UNITS` (1e11, mirrors `money.MAX_BUDGET_COST_CENTS`'s order of magnitude), and is never summed into any Delta ledger, budget, or forecast figure — it is CRM-local pipeline data only. | Delta has no billing/AR system (ADR-0001, ADR-0008, ADR-0012 all establish this boundary already) and no contract-management capability. A deal's dollar figure is a pipeline estimate an operator enters, not a verified, ledger-backed transaction — conflating the two would misrepresent CRM data as financial fact. |
| **8 — mounted on the existing admin app, not a new process** | `GET/POST /v1/admin/crm/*` on the same D-007 admin app, same `require_admin` break-glass bearer auth (imported unchanged from `allocation_admin.auth`, not redefined). | Same operators, same auth, same trust boundary — mirrors D-008/D-011/D-012's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No trained/validated ML relationship-scoring or lead-scoring model.** The
  recency+frequency heuristic is deliberately simple, deterministic arithmetic — same
  rationale as D-011/D-012's honesty boundaries. No backtest, no training data, no
  accuracy claim beyond "a bigger number means more recent/frequent/pipelined
  engagement."
- **No NLP-driven stakeholder extraction from free text.** Stakeholders are entered
  explicitly and interactions optionally tag ONE of them; nothing parses `summary` text
  to infer who was involved. A future capability that suggests stakeholders from
  interaction text is real, separate work.
- **Not full enterprise-CRM feature parity.** No custom fields, no email/calendar
  integration, no multi-currency FX conversion on deal value, no territory/quota
  management, no bulk import/export, no contract/document management, no
  stakeholder-to-stakeholder relationship graph (org charts) beyond a flat roster per
  client.
- **No dedicated CRM change-history/audit log.** Unlike D-007's allocations, no
  per-mutation history table exists for CRM edits (Fork 4) — only `created_at`/
  `updated_at` timestamps on each row. A non-financial CRM audit trail (who changed
  what when) is real, valuable future work, not built here.
- **No underspend/inactivity alerting.** A stale client (no interactions in months)
  is visible via a low relationship score on request, but nothing proactively notifies
  an operator — there is no notification/alerting system anywhere in Delta to hook into.
- **Deal value is optional, single-currency-per-deal, and never validated against any
  real payment or contract.** It is pipeline estimate data an operator types in, not a
  verified financial fact (Fork 7).

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant client/deal/stakeholder/interaction leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession` opened via `get_tenant_session(tenant_id)`; every table's RLS predicate is the same fail-closed `tenant_id = NULLIF(current_setting(...), '')` as every prior Delta migration | `test_cross_tenant_isolation_clients_invisible_to_other_tenant`, `test_cross_tenant_client_list_isolated_over_http` |
| Interaction/stakeholder tagged to a DIFFERENT client's deal/stakeholder (same tenant — FK alone would not catch this) | `service._check_deal_scope`/`_check_stakeholder_scope` explicitly compare the fetched row's `client_id` to the request's path client, independent of the FK's tenant-only guarantee | `test_interaction_tagged_to_deal_from_another_client_rejected`, `test_stakeholder_from_another_client_rejected_on_interaction`, `test_deal_scope_mismatch_returns_422` |
| A deal moves out of a terminal state ('won'/'lost' silently reopened) | `try_transition_deal_stage`'s conditional `UPDATE ... WHERE stage NOT IN ('won','lost')` — a transition attempt against an already-terminal deal affects zero rows, surfaced as 409 | `test_deal_stage_transition_succeeds_once_then_blocked_when_terminal`, `test_full_deal_pipeline_and_relationship_score_flow` (409 on repeat transition) |
| Resource amplification: engagement/score computed per-stakeholder or per-interaction (N+1) | Engagement is one `LEFT JOIN ... GROUP BY` query per client (not one per stakeholder); relationship-score inputs are 2 small aggregate queries (not a full interaction/deal scan) | code review; `test_stakeholder_engagement_computed_via_interaction_join` |
| Unbounded interaction/deal/stakeholder/client list growth | `DEFAULT_LIST_LIMIT`/`MAX_LIST_LIMIT` (100/500, mirrors D-007/D-008/D-011/D-012's own caps) clamp every list query server-side regardless of the caller-supplied limit | code review (`store._clamp_limit`) |
| Log-injection / control-character injection via free-text fields (name, summary, actor, note-equivalent) | Every free-text field goes through `_reject_control_chars` (mirrors D-007's exact `_ACTOR_MAX_LENGTH`/control-char discipline, itself informed by `docs/audit/d-007-security-audit.md` finding #2) | `test_client_create_rejects_control_chars_in_name`, `test_deal_stage_transition_rejects_control_chars_in_actor`, `test_interaction_create_rejects_control_chars_in_summary` |
| Naive (non-UTC-aware) timestamps silently misinterpreted | `require_aware_utc` (D-001's own helper, reused unchanged) on `expected_close_date`/`occurred_at` | `test_deal_create_rejects_naive_expected_close_date`, `test_interaction_create_rejects_naive_occurred_at` |
| Deal value overflow / negative value | Pydantic `Field(ge=0, le=MAX_DEAL_VALUE_MINOR_UNITS)`; DB-level `CHECK (value_minor_units IS NULL OR value_minor_units >= 0)` as a second, independent layer | `test_deal_create_rejects_negative_value`, `test_deal_create_rejects_value_above_max`, `test_deal_create_accepts_value_at_max` |
| Deal value / currency drift (a value without a currency, or vice versa) | `service.create_deal` forces `currency = None` whenever `value_minor_units is None`, AND defaults a caller-supplied `currency: null` to `DEFAULT_CURRENCY` whenever `value_minor_units` IS set (independent security review, finding #1 — the original code only enforced the first direction, letting `{value_minor_units: 1000, currency: null}` persist a value-without-currency row). A DB `CHECK ((value_minor_units IS NULL) = (currency IS NULL))` backs this as a second, independent layer regardless of the app-layer fix | `test_create_deal_with_value_defaults_currency_when_null`, `test_deal_value_without_currency_rejected_by_db_check` |
| Auth bypass on any of the 11 new endpoints | `require_admin` (D-007's break-glass bearer, unmodified) is the router-level `dependencies=[Depends(require_admin)]` on the whole `crm_router` — no per-route opt-out exists | `test_clients_endpoint_401_without_bearer` |
| Money-as-float leaking into a decision path | `value_minor_units` is always an `int`; the only `float` anywhere in `delta.crm` is `RelationshipScoreView.score` (informational, 0–100, never fed into any enforcement/budget decision) | code review — no `budget_engine`/`decision` import anywhere under `delta/crm/` |
| SQL injection via any CRM identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement (`insert`/`select`/`update` against `Table` objects) — no raw string-interpolated SQL anywhere in `delta.crm.store` | code review |

## 5. Verification

- `black --check` / `ruff check .` clean.
- New `tests/crm/` suite: 57 tests — 17 pure schema-validation tests (`test_schemas.py`),
  18 pure scoring-heuristic tests (`test_scoring.py`, no DB/no I/O), 9 DB-backed store
  tests (`test_store_db.py`, incl. the DB-CHECK regression test below), 7 DB-backed
  service tests (`test_service_db.py`, incl. the currency-defaulting regression test),
  6 non-stubbed HTTP e2e tests (`test_router_e2e.py`, real ASGI app, real auth, real DB).
- Full existing Delta suite green (624 passed, 15 skipped) — zero regressions, zero
  changes to any D-001…D-012 file's runtime behavior (the only modification to existing
  code is one router mount in `allocation_admin/app.py`, and one new section each in
  `identifiers.py`/`persistence/models.py`, additive only).
- Migration 0007 verified round-trip (`alembic upgrade head` → `downgrade -1` →
  `upgrade head`) against a live local Postgres, `delta_app` role provisioned exactly as
  every prior migration's test harness does — re-verified after the post-audit
  `ck_deal_value_currency_pair` CHECK constraint was added.
- Independent security-auditor review: verdict CLEAN, two Low findings, both fixed on
  this branch before merge (see `docs/audit/d-013-security-audit.md`) — a
  value-without-currency deal row was reachable via an explicit `currency: null` in the
  create-deal request (fixed in `service.py` + backed by a new DB CHECK constraint), and
  a docstring inaccurately described stakeholder-engagement matching as name-based when
  the code correctly matches by `stakeholder_id` (fixed).
- Frontend: `npm run typecheck` clean, `npm run lint` clean (0 warnings/errors),
  `npm run build` succeeds (`/crm` and `/crm/[clientId]` registered as dynamic routes).
  Live browser smoke test performed against a real running backend with real data
  entered through the UI itself (not seeded): created a client, added a deal with a
  dollar value, added a stakeholder, logged an interaction, transitioned the deal
  lead→qualified (confirmed the 409-producing already-terminal guard exists via the
  code path, exercised in the e2e HTTP suite), and confirmed the relationship-score
  stat tile, deal pipeline table, and stakeholder engagement table all render correctly
  with live-computed values.

## 6. Alternatives considered

- **A trained/validated lead-scoring or relationship-scoring ML model.** Rejected
  (Fork 1) for the same reason D-011/D-012 rejected ML: no ecosystem precedent, no
  training data, no backtest/validation story, and building one unilaterally in an
  unattended run would be exactly the scope-widening this run's procedure avoids.
- **NLP-based stakeholder extraction from interaction summaries.** Rejected (Fork 3):
  a fundamentally different, much larger capability (entity recognition, resolution
  against an existing roster, confidence scoring) with no precedent or evaluation
  harness anywhere in this codebase. Explicit tagging is a smaller, honest, fully
  deterministic substitute that still delivers genuinely "automated" (system-computed,
  not manually-tallied) engagement metrics.
- **A DB CHECK constraint enumerating the full deal-stage vocabulary.** Rejected
  (Fork 2): would force a schema migration for every future stage-vocabulary change;
  the actual invariant that matters (terminal stages are immutable) is enforced at the
  query layer instead, which is both sufficient and independent of how many stages
  exist.
- **Wiring CRM mutations into D-009's hash-chained audit log.** Rejected (Fork 4):
  that chain's own scope (per its module docstring) is Delta's automated financial
  workflows; CRM business-process edits are a different kind of event, and folding
  them in would blur a boundary that was deliberately drawn and reviewed for a
  narrower purpose. A dedicated, non-financial CRM history log is a separate, smaller,
  clearly-named piece of future work if operators need it.
- **Full enterprise-CRM feature parity (custom fields, calendar/email sync, territory
  management, contract documents).** Rejected as this task's scope: the roadmap's own
  framing tags D-013 "post-investment vision... effectively a sub-product" — a
  properly bounded vertical slice that honestly delivers the four named capabilities
  (deal pipeline, interaction history, relationship scoring, stakeholder mapping) at a
  real but proportionate depth is the correct scope for a single unattended task, with
  the larger surface named honestly as future work rather than attempted and half-built.
