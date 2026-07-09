# ADR-0017 — Budget Enforcement Loop Validated (X-003, non-stubbed)

- Status: **Proposed — flagging a conflicting conclusion for human review, not self-merging**
- Date: 2026-07-09
- Task: X-003 (Cross-product integration, the third and final untagged Cross-product MVP
  task — "the killer feature")
- Depends on: D-005 (Delta budget engine), O-004 (Orchestrator policy distribution), F-008
  (Sentinel policy intake + enforcement)
- Builds on: ADR-0004 (O-004 policy distribution — Fork F/F1, the test-shim precedent this
  ADR reuses), Anoryx-AI-Orchestrator's own `test_distribution_e2e.py` (the SAME precedent,
  already shipped, for MODEL policies), Orchestrator ADR-0016 / Delta ADR-0016 (X-001/X-002 —
  the same "prove the wiring with each product's real pure functions" pattern applied here to
  the third and final leg)
- Supersedes: nothing. Adds one new test file + one new ADR; zero new tables, zero new
  migration, zero new endpoint, zero new production code, zero contract changes.

## A conflicting conclusion exists — read this first

**Another concurrent session independently picked up X-003 and reached the opposite
conclusion** (PR #98, `claude/x/X-003-budget-enforcement-loop`): that the task is
**blocked**, because Sentinel exposes no *production* HTTP policy-intake route (only
`sentinel-cli policy push`, per ADR-0009 §11's own explicit scope decision), so proving the
loop would require either a real endpoint (a contract change, api-architect-owned, needing
human review) or a test-only shim that wouldn't reflect what a real deployment can do today.
That PR is docs-only and stops there, deliberately not building anything.

This ADR does not resolve that disagreement unilaterally. It documents a WORKING,
non-stubbed proof that reuses precedent already shipped elsewhere in this codebase, and
leaves the decision — is a test-shim-based proof an acceptable X-003 "done," or does the
roadmap's "budget-set → enforcement-active" demo bar require the real endpoint first — to a
human. See "The judgment call" below.

## Context

Three of the loop's legs already have independent non-stubbed proof:

1. **Delta → real O-004 distribution**: `Delta/tests/budget_engine/test_o004_e2e.py` drives
   Delta's real cap-crossing budget engine to a real signed POST accepted by a real O-004
   app — but its own docstring names the Sentinel-block leg as "the trivial accepting
   shim... the Sentinel-block leg is X-003."
2. **O-004 → real Sentinel intake + enforcement, for MODEL policies**:
   `Anoryx-AI-Orchestrator/tests/integration/test_distribution_e2e.py` (already merged,
   security-audited CLEAN as part of O-004) proves the FULL submit → distribute → intake →
   enforce loop non-stubbed, using `_sentinel_shim.py` — a test-only ASGI app whose intake
   route delegates ENTIRELY to Sentinel's real `intake_policy()` (ADR-0004 Fork F: "the shim
   exists ONLY so the Orchestrator's outbound distribution engine can make a GENUINE network
   call to a real socket and have Sentinel's REAL intake verify + persist the policy" — a
   deliberate, already-accepted design decision, not an oversight or a shortcut invented
   here).
3. Neither proves the loop for **`budget_limit`** policies specifically, and neither proves
   Sentinel's real budget DECISION (`evaluate_budget_pre_request` — the function
   `gateway/routes/chat_completions.py` calls at request time) actually flips from allow to
   blocked once that policy lands, scoped to one team and not its sibling, within the
   roadmap's 1-second claim.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — how to obtain a genuine Delta-signed `budget_limit` record without Delta's own DB | **A1**: `delta.budget_engine.definitions.BudgetDefinition` is a plain frozen dataclass (no DB row needed to construct one); `delta.budget_engine.emit.build_policy_payload` and `delta.policy.sign.sign_policy_record` are both pure functions — imported unmodified from the installed `anoryx-delta` package. This is Delta's REAL D-005 emit+sign path, minus the DB-backed cap-crossing DECISION (already proven separately, non-stubbed, by `test_o004_e2e.py`) — the same "each product's real pure functions, not hand-typed fixtures" pattern X-001/X-002 established. |
| **B** — which signing key | **B1**: the SAME `sentinel_signing` test key the existing `sentinel_shim_server`/`make_signed_policy` fixtures already use. Delta's `sign_policy_record` takes a raw `cryptography` `EllipticCurvePrivateKey` — it has no opinion on WHOSE key it is. In production this is the Delta signing identity ADR-0005 describes Sentinel as configured to trust; the test harness configures exactly one trusted key, so this substitution is required, not a shortcut. |
| **C** — the Sentinel-side transport | **C1**: reuse `_sentinel_shim.py` and `sentinel_shim_server` UNCHANGED — the identical fixture `test_distribution_e2e.py` already uses for model policies. This is the crux of the disagreement with PR #98: is reusing an already-shipped, already-audited test harness for a NEW policy_type an acceptable way to validate X-003, or does "the killer feature" require the underlying production gap (no Sentinel HTTP route) to close FIRST? Not resolved here — flagged for human review. |
| **D** — how to prove enforcement without a live gateway HTTP request | **D1**: call Sentinel's real `evaluate_budget_pre_request` directly (mirrors the existing `sentinel_enforce` fixture's identical treatment of `evaluate_model_policies` for MODEL policies) — the exact, real, DB-backed function `gateway/routes/chat_completions.py` calls at request time. Standing up a full mocked-provider gateway HTTP request was explicitly out of scope for the SAME reason `sentinel_enforce` doesn't either (documented in that fixture's own docstring). |
| **E** — scope proof | **E1**: a TEAM-scoped budget (`BudgetScope.TEAM`) blocks the capped team but leaves a sibling team on the SAME tenant untouched — proves `budget_matches_scope`'s exact team_id equality (no wildcard blast radius), matching the roadmap's literal "blocks the team's next request" wording (not "blocks the tenant"). |
| **F** — the 1-second claim | **F1**: `time.monotonic()` bracketing the HTTP submit call through the real O-004 BackgroundTask-driven distribution (httpx's `ASGITransport` runs FastAPI `BackgroundTask`s synchronously, so by the time POST returns, the distribution has already settled `distributed`) — asserted `< 1.0s`. Measured locally at ~0.02–0.05s per run (well inside the budget); this is a floor-check against the roadmap's own claim, not a load-test SLA. |

## What this proves (and what it doesn't)

**Proves:** a genuinely Delta-signed `budget_limit` policy — real payload shape, real ES256
signature — submitted through Orchestrator's real O-004 HTTP endpoint, distributed by the
real engine, intake'd by Sentinel's real `intake_policy()` (via the same test-shim transport
already shipped and audited for O-004's model-policy proof), makes Sentinel's real budget
enforcement function block the capped team's very next request while leaving a sibling team
untouched — the whole loop measured well under 1 second.

**Does not prove (honesty boundary, non-removable — same substance as PR #98's finding,
just not treated as fully blocking here):** that a real Sentinel deployment has any HTTP
route Orchestrator's real distribution engine could reach in production today — it does
not, per ADR-0009 §11's own explicit CLI-only scope decision, unchanged by this PR. This
test's Sentinel-side transport is the SAME test-only shim `test_distribution_e2e.py` already
uses, not a claim that this shim is (or should become) production code. Also does not
re-derive Delta's own cap-crossing DECISION from ledger data, and does not re-drive a live
`/v1/chat/completions` HTTP request end-to-end (same scope boundary `sentinel_enforce`
already carries for model policies).

## The judgment call (for human / api-architect review)

This PR and PR #98 disagree about what "X-003 done" means:

- **This PR's position**: the test-shim pattern is not a new shortcut invented for this
  task — it is the SAME mechanism already shipped, audited CLEAN, and merged to main as
  part of O-004's own acceptance gate (`test_distribution_e2e.py`). Extending it to a new
  `policy_type` (budget_limit vs. model_allowlist/denylist) is consistent reuse of accepted
  precedent, not scope creep, and it is the concrete "budget-set → enforcement-active" proof
  the roadmap names.
- **PR #98's position**: however precedented, a test-shim proof does not mean the loop
  works in a REAL deployment — Orchestrator's real distribution engine would 404 against a
  real Sentinel today. Claiming "the killer feature is validated end-to-end" without a real
  Sentinel HTTP route overstates deployability, and the honest path is to name the gap and
  defer to a contract-change decision (api-architect + human).

**Recommendation left to the human:** if the existing O-004 precedent was accepted as
sufficient to ship O-004 itself, the symmetric case is that this PR should be equally
acceptable for X-003. If the bar has since moved (e.g., the ecosystem now wants X-003
specifically to prove production-reachability, not just mechanism-compatibility), PR #98's
docs-only "blocked, needs api-architect" path is the correct one and this PR should be
closed unmerged. Both PRs are left open; this ADR does not pre-empt that decision.

## Testing

`Anoryx-AI-Orchestrator/tests/integration/test_x003_budget_enforcement_e2e.py`
(`pytest.mark.integration`, gated on Postgres reachability like every sibling e2e in this
suite):

- `test_budget_cap_policy_blocks_the_teams_next_request_within_one_second` — submit →
  distributed → capped team BLOCKED (`BudgetExceeded`, `budget_cost_exceeded`) → sibling
  team on the same tenant NOT blocked (`BudgetOk`) → round trip `< 1.0s`.

Verified locally against a real Postgres 16 instance (CI's exact `orchestrator-integration`
env/role/migration setup, Sentinel + Delta + Orchestrator all installed): passes in
isolation and the full `pytest tests` suite (614 tests) passes with it included.

## Out of scope (do not build here)

A real Sentinel HTTP policy-intake production endpoint (that decision belongs to the
api-architect + a human, per PR #98's own recommendation, which this ADR does not dispute);
any change to `Anoryx-Sentinel/contracts/` or `policy.schema.json` (neither is touched); a
live mocked-provider `/v1/chat/completions` HTTP request; Delta's own cap-crossing decision
logic (already proven elsewhere).

## Consequences

- If accepted: X-003 closes using the same precedent already shipped for O-004, completing
  the X-001→X-003 killer-loop MVP with all three legs proven non-stubbed.
- If rejected in favor of PR #98's position: this PR should be closed unmerged, and the real
  next step is the api-architect-owned contract decision PR #98 already recommends — this
  ADR and its test file stand as evidence for what the loop looks like once that lands.
- Either way, the disagreement itself — and the fact that O-004's own precedent already
  used this exact pattern — is now on record for whoever makes the call.
