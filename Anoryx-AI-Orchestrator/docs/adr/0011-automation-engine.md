# ADR-0011 — Tenant-Scoped Automation-Rules Engine (not a workflow engine)

- Status: Accepted
- Date: 2026-07-08
- Task: O-011 (eleventh Orchestrator task, third task from the Phase 2
  ecosystem-integration layer)
- Builds on: ADR-0003 (O-003 ingest — the accepted-event seam this reacts to), ADR-0004
  (O-004 policy distribution — `drive_distribution`, the ONE existing action this engine
  re-drives, reused unchanged), ADR-0009 (O-009 relay — the narrow-DB-connectivity-catch
  and privileged-chain-append discipline this reuses verbatim), ADR-0010 (O-010 identity
  correlation — the tenant-scoped-table-plus-global-chain shape, and the
  `KNOWN_IDENTITY_SOURCE_PRODUCTS` source-product allow-list, both reused here)
- Supersedes: nothing. Adds one new tenant-scoped table, one new global hash chain, one
  new automation package, and one new BackgroundTask scheduled from the EXISTING ingest
  router; does not alter the O-003 ingest pipeline's own dispositions, the O-004
  distribution engine's fan-out logic, or any other existing seam/engine/schema.

## Context

The roadmap lists O-011 as **"Event-driven cross-module automation engine"** — "Autonomous
multi-step triggers across all products (e.g., Sentinel policy violation → Delta budget
freeze → Rendly notification). The cross-product workflow engine." — in the same Phase-2
ecosystem-integration tier as O-009/O-010. As with those two, this run's default posture is
to stop in front of the post-investment gate; the task owner has explicitly authorized
proceeding with post-investment tasks in this run, which is the authorization this ADR
records (mirrors ADR-0009/ADR-0010's identical disclosure).

The literal ask — "autonomous multi-step triggers across ALL products," "the cross-product
WORKFLOW engine" — is not buildable as a single, honest PR today, for two independent
reasons:

- **Arbitrary multi-step orchestration across products is either dangerous or
  impossible to build honestly from here.** A genuine "workflow engine" implies some
  action language expressive enough to chain steps (`if X then Y then Z`) — which either
  means embedding a code-execution surface (arbitrary conditions/actions an attacker who
  can create a rule could turn into a confused-deputy or RCE primitive), or hand-coding
  every possible multi-step chain as bespoke logic (which is not an engine, it is a
  slowly-growing pile of one-offs). Neither is buildable as one honest, reviewable PR.
- **This agent cannot write to Delta or Rendly.** Protect-paths confines this run to
  `Anoryx-AI-Orchestrator/`. A true cross-product workflow ("Sentinel violation → Delta
  budget freeze → Rendly notification") requires write access into Delta's and Rendly's
  own internals that do not exist yet and that this run is not scoped to build.

This ADR resolves that tension the same way ADR-0009/ADR-0010 resolved O-009/O-010's
literal text: ship the smallest genuinely useful, honest slice — a tenant-scoped
automation-RULES engine that reacts to an event the Orchestrator ALREADY ingests (O-003)
by triggering exactly ONE closed, pre-existing, already-audited Orchestrator action
(re-driving an O-004 policy distribution) — and name everything else (multi-step chains,
new action types, cross-product writes, a real condition/operator language) as an honest
deferral, not a silently narrower "done."

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — trigger shape | **A1**: a rule fires on ONE F-002 event, identified by `trigger_event_type` (must be one of the closed set of event_type consts already declared in the locked `events.schema.json`, derived via a new `schema_validation.known_event_types()` helper — not a hand-maintained second list) plus an OPTIONAL `trigger_source_product` filter (one of `sentinel`/`delta`/`rendly`, the same closed set `KNOWN_IDENTITY_SOURCE_PRODUCTS` already uses). No multi-event triggers, no windows, no aggregation — one event, evaluated once, at ingest-accept time. |
| **B** — condition language | **B1**: `trigger_conditions` is a FLAT dict of `payload-top-level-field -> expected scalar value` (str/int/float/bool), matched by `==` ONLY. CLOSED — no nesting, no regex, no operators (`>`, `in`, `contains`, ...), no code, no template language. This is a hard security invariant, not a v1-scope shortcut: the matcher (`automation.matcher.rule_matches`) is a pure function with NO extensibility hook, and a condition value or the corresponding payload value that is a dict/list NEVER matches (treated as non-matching, never raises) — this closes the condition-language-injection/RCE threat structurally, by construction, not by input sanitization. |
| **C** — supported action set | **C1**: EXACTLY ONE action type in v1: `redistribute_policy`, which re-drives an EXISTING, already-audited O-004 distribution (`distribution.engine.drive_distribution`) — this module never duplicates that fan-out/retry/audit logic, it only calls it. A second action type (e.g. a relay dispatch, a new Delta-facing write) is real, explicit future work — not built here. The DB schema CHECK-constrains `action_type` to this one value so the closed set holds even against a direct DB write, not merely at the app boundary. |
| **D** — chaining / recursion | **D1**: NO CHAINING, NO RECURSION — a hard invariant, stated in the engine's docstring, not merely observed by omission. `evaluate_and_execute` NEVER itself causes a new event to be ingested or a new automation evaluation to be scheduled. This holds STRUCTURALLY: `drive_distribution` only performs outbound HTTP + its own bookkeeping/audit; it contains no call back into `ingest.router` or `automation.engine` anywhere in its call graph. A "trigger → trigger → trigger" cascade — the literal shape a "workflow engine" implies — is architecturally unreachable here, not merely undocumented. |
| **E** — master switch default | **E1**: `ORCH_AUTOMATION_ENABLED` DEFAULTS TO **FALSE**. This is new AUTONOMOUS behavior (a matched rule triggers a real outbound distribution re-drive without a human in the loop for that specific trigger) — unlike every prior Orchestrator seam, which is either a passive read or a caller-initiated write. Shipping it off by default means no existing deployment silently starts auto-triggering distributions merely by upgrading; an operator opts in explicitly. |
| **F** — tenant-ownership of the action target | **F1**: at rule-creation time, `action_config.distribution_id` MUST resolve (via the EXISTING `get_distribution` repository function, under `get_tenant_session(tenant_id)`) to a distribution belonging to the SAME tenant as the rule — else 422 `distribution_not_found`. This closes a real cross-tenant confused-deputy path: without it, tenant A could wire a rule that, on tenant A's own traffic, silently re-drives tenant B's distribution. |
| **G** — per-tenant rule cap | **G1**: `ORCH_AUTOMATION_MAX_RULES_PER_TENANT` (default 20) enforced at CREATE time (a `COUNT` under the tenant session before insert) — not at evaluation time. This bounds the worst-case per-event rule-evaluation cost structurally (evaluation is always a bounded scan of at most this many rules), rather than relying on an operator to notice unbounded growth after the fact. Exceeding it is 422 `rule_limit_exceeded`, never a 5xx. |
| **H** — idempotency / dedup mechanism | **H1**: `UNIQUE(rule_id, triggering_event_id)` on `automation_executions`, exploited as the dedup gate: if the ingest background task is ever scheduled twice for the same accepted event (a retry, a duplicate dispatch), the second attempt's INSERT hits this constraint and the caller catches the `IntegrityError` NARROWLY (mirrors the ingest pipeline's own dedup discipline) and treats it as "already executed, skip" — never a duplicate row, never an error. |
| **I** — what gets chain-audited | **I1**: ONLY a rule that GENUINELY MATCHED and was acted on produces an `automation_executions` row (`executed` or `failed`). A non-matching rule produces NO row — there is nothing tamper-evident to say about a rule that never fired. This differs from ADR-0010's identity chain (which audits both `accepted` and `duplicate`, i.e. every ingest ATTEMPT) because here the meaningful unit of audit is "did this rule's action run", not "was this record durably stored." |
| **J** — table scope (RLS vs. global) | **J1**: `automation_rules` is TENANT-SCOPED (RLS, mirrors `ingest_events`/`identity_events`) — a tenant's own rules are tenant data. `automation_executions` is a GLOBAL hash chain (mirrors `distribution_audit_log`/`ingest_audit_log`, NOT `relay_audit_log`/`identity_audit_log`) — privileged-session writes only, but UNLIKE the relay/identity chains it DOES carry RLS on SELECT, because (unlike the relay's cross-tenant fleet-dispatch metadata) this chain's rows are genuinely tenant-relevant audit data a tenant reads back via `GET /v1/automation/executions`. |
| **K** — auth model | **K1**: the automation CRUD + read seams reuse the EXISTING `require_tenant_principal` dependency (`query_service_tokens`) verbatim — the SAME credential already gating `GET /v1/events` and `GET /v1/identity/events`. No new principal type, no new trust root. |

## API additions

- `POST /v1/automation/rules` — create (name, trigger_event_type, trigger_source_product?,
  trigger_conditions?, action_type, action_config, enabled?) → 201, or 422/409 per the
  validation order in `automation/router.py`'s module docstring.
- `GET /v1/automation/rules` — cursor-paginated list of this tenant's rules.
- `GET /v1/automation/rules/{rule_id}` — 404 if unknown or another tenant's (RLS-hidden).
- `PATCH /v1/automation/rules/{rule_id}` — enable/disable ONLY (`{"enabled": bool}`); a
  full update is unnecessary v1 scope (delete+recreate covers edits).
- `DELETE /v1/automation/rules/{rule_id}` — 204.
- `GET /v1/automation/executions` — read-only, tenant-scoped audit visibility into this
  tenant's own rule executions.

## Data access

`automation.engine.evaluate_and_execute` is scheduled as a FastAPI `BackgroundTask` from
`ingest/router.py` immediately after a genuinely fresh `ACCEPTED` persist (mirrors exactly
how `distribution/router.py` schedules `drive_distribution` — never for `DEDUPED` or
`DEAD_LETTERED`). It loads this tenant's ENABLED rules for the event's `event_type` under
`get_tenant_session(tenant_id)` (RLS-scoped, bounded by the per-tenant cap), matches each
with the pure `automation.matcher.rule_matches` function (no I/O), and for a match calls the
EXISTING `distribution.engine.drive_distribution` unchanged. Every matched execution appends
ONE `automation_executions` link via `get_privileged_session()` + `session.begin()` (mirrors
`_append_audit` in `distribution/engine.py`).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT the roadmap's literal "autonomous multi-step triggers across ALL
  products" or "the cross-product workflow engine."** It is a single-step, single-product
  (Orchestrator-internal) rule engine: one accepted event in, at most one existing action
  triggered, no chaining.
- **This is NOT multi-step.** A rule triggers EXACTLY one action. There is no "then do Y"
  after the action runs — `drive_distribution`'s own completion is the end of this
  engine's involvement, full stop.
- **This does NOT write into Delta or Rendly.** The one supported action
  (`redistribute_policy`) re-drives an Orchestrator-internal, already-audited O-004
  distribution to a registered Sentinel. Nothing here calls Delta or Rendly.
- **The action set is exactly ONE type (`redistribute_policy`), and adding more is
  explicit future work**, not silently implied by the word "engine." A relay-dispatch
  action, a new secret-holding action, or any action requiring a new credential is
  explicitly OUT OF SCOPE for this PR.
- **There is no chaining, ever** (Fork D) — this is stated here a second time because it
  is the single most likely misreading of "O-011 shipped": a matched rule's action cannot
  itself cause another rule to evaluate.
- **The condition language is closed, scalar-equality-only, and Turing-incomplete by
  construction** (Fork B) — there is no path from a `trigger_conditions` value to code
  execution, because there is no code-execution path in the matcher at all.
- **Dispatched only via this run's explicit authorization to build post-investment
  tasks** (mirrors ADR-0009/ADR-0010's identical disclosure) — the roadmap's own 🏦 label
  means this was not scheduled as next-buildable MVP work.
- **Enabling automation extends the ingest peer secret's practical authority from
  record-only to trigger-a-distribution-redrive for every opted-in tenant; this is a real
  trust-boundary shift an operator should weigh before setting
  `ORCH_AUTOMATION_ENABLED=true`, not merely a hypothetical** (security-auditor follow-up
  — see the Threat model and Residual risk sections for the full statement). This is not a
  re-architecture: there is no interactive tenant credential available at ingest time to
  require instead without defeating the entire point of an event-triggered automation
  engine, so the default-off master switch (Fork E) is the primary, and currently only,
  mitigation.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Condition-language injection / RCE via `trigger_conditions` | Fork B: a closed, scalar-equality-only language with NO extensibility hook — the matcher performs `==` on JSON scalars only; a dict/list value on either side never matches and never raises. There is no eval, no regex, no operator table to smuggle a payload through. |
| Cross-tenant confused deputy via `action_config.distribution_id` | Fork F: tenant ownership of the referenced distribution is verified at rule-creation time (`get_distribution` under `get_tenant_session(tenant_id)`) — a rule can only ever re-drive ITS OWN tenant's distribution. |
| Unbounded rule fan-out per accepted event | Fork G: `ORCH_AUTOMATION_MAX_RULES_PER_TENANT` (default 20) enforced at creation time, so per-event evaluation cost is always bounded by a known, small ceiling, never by however many rules a tenant has accumulated. |
| Duplicate execution on a retried/duplicate background-task schedule | Fork H: `UNIQUE(rule_id, triggering_event_id)` on `automation_executions`, exploited as an idempotency gate via a narrow `IntegrityError` catch — a repeat schedule for the same event never re-executes or double-records. |
| Default-off blast radius | Fork E: `ORCH_AUTOMATION_ENABLED` defaults to `false` — an unconfigured or freshly upgraded deployment never auto-triggers anything; an operator must explicitly opt in. |
| Chaining/cascade turning one event into an unbounded cascade of triggered actions | Fork D: no code path from `drive_distribution` (or anywhere in this module) back into `ingest.router` or `automation.engine` — structurally, not conventionally, acyclic. |
| Tamper on the automation-execution audit chain | Append-only via BEFORE UPDATE/DELETE deny triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_automation_chain` re-verifies the full chain. |
| **Ingest peer secret gains cross-tenant, on-demand trigger authority for opted-in tenants' distribution re-drives** (security-auditor follow-up, named here honestly, not re-architected) | `evaluate_and_execute` acts on the ingest envelope's own asserted `payload.tenant_id` — not a tenant's own service-token credential — to look up and act on that tenant's automation rules. A holder of the shared ingest peer HMAC secret (previously usable only to durably RECORD an event) can therefore now, for ANY opted-in tenant, TRIGGER that tenant's own already-authorized `redistribute_policy` action on demand, without ever holding that tenant's own credential. Mitigated PRIMARILY by Fork E's default-off `ORCH_AUTOMATION_ENABLED=false`: an operator who flips it to `true` is knowingly, explicitly extending trust in the shared ingest peer secret from "can record events" to "can trigger this opted-in tenant's own already-authorized distribution re-drives on demand." This is BOUNDED — Fork F still closes any CROSS-tenant confused-deputy (a rule can only ever re-drive ITS OWN tenant's own pre-existing, already-signed distribution) — but Fork F does NOT change WHO can pull the trigger for a tenant that has opted in; that is a genuinely new authority the ingest secret gains, not a hypothetical one. There is no interactive tenant credential available at ingest time to require instead without defeating the entire point of an event-triggered automation engine, so this is named as a residual, weighed trade-off, not redesigned in this PR. |

## Residual risk (known, deferred)

- **No multi-step chains** — the roadmap's literal "Sentinel violation → Delta budget
  freeze → Rendly notification" example is NOT buildable from this PR; it would require
  either a second/third action type with cross-product write access (not built here) or
  an actual chaining mechanism (explicitly excluded by Fork D as a security invariant, not
  merely deferred).
- **Exactly one action type** — a rule can only ever re-drive an O-004 distribution.
  Anything else a rule owner might want to automate (a relay dispatch, a Delta write, a
  notification) is real future work requiring its own security review, not assumed
  "the same shape" as this one.
- **No cross-product write access** — this PR cannot and does not reach into Delta or
  Rendly; the roadmap's literal example spans three products and this ships zero of the
  cross-product legs.
- **The condition language cannot express anything beyond flat scalar equality** — an
  operator wanting `>`, `contains`, or a boolean combinator (`AND`/`OR` across
  conditions — today's semantics are an implicit AND of every key) must wait for a
  reviewed extension of the matcher, not work around it by encoding logic into the
  payload.
- **This is not the roadmap's full O-011 vision** — it is the smallest honest, buildable
  slice: a rule-based re-trigger of ONE existing action, named as such, not something
  broader.
- **Enabling automation extends the ingest peer secret's practical authority from
  record-only to trigger-a-distribution-redrive for every opted-in tenant** (security-auditor
  follow-up). Before O-011, a holder of the shared ingest peer HMAC secret could durably
  RECORD an event on a tenant's behalf, nothing more. After O-011, with
  `ORCH_AUTOMATION_ENABLED=true`, the SAME secret can cause that tenant's own opted-in
  automation rules to FIRE — an on-demand trigger of an already-authorized action, for any
  tenant that has created a matching rule, without holding that tenant's own credential.
  Fork F bounds this to the tenant's OWN pre-existing, already-signed distribution (no
  cross-tenant confused deputy), but it does not change who can pull the trigger. This is a
  real trust-boundary shift, not a hypothetical one.

## Configuration

New environment variables (both resolved NON-FATALLY — absence is not fatal):

- `ORCH_AUTOMATION_ENABLED` — master switch (default `false`).
- `ORCH_AUTOMATION_MAX_RULES_PER_TENANT` — per-tenant automation-rule cap (default `20`,
  minimum `1`).

## Testing

- **Unit** (`tests/unit/test_automation_matcher.py`, `test_automation_config.py`,
  `test_hash_chain_automation.py`, `test_automation_router.py`): the pure matcher's
  event_type/source_product/scalar-equality semantics and its dict/list-never-matches
  invariant; env-parsing defaults + overrides + misconfiguration; the automation hash
  chain's opt-in-when-present + tamper-evidence properties; the auth/validation boundary
  (401/422/409/404/PATCH/DELETE).
- **Integration** (`tests/integration/test_automation_e2e.py`,
  `pytest.mark.integration`, gated by `ORCH_REQUIRE_AUTOMATION_E2E=1`): a NON-STUBBED path
  reusing the O-004 distribution fixtures/shim — a real signed distribution, a real
  automation rule created via the real API, a real signed HMAC ingest that matches the
  rule, proving: exactly one `executed` automation_executions row is produced; a repeat
  scheduling of the same (rule, event) does not double-execute (the UNIQUE dedup gate); a
  second identical ingest dedupes upstream so automation is never even re-scheduled; the
  master switch off produces zero rows even though the rule genuinely matches; a
  non-matching rule produces zero rows.

## Out of scope (do not build here)

Multi-step chains of any kind; a second (or any additional) action type, including a
relay-dispatch action or any action that would hold/forward a secret; cross-product write
access into Delta or Rendly; a condition language beyond flat scalar equality (regex,
comparison operators, boolean combinators, templating, or any code-execution surface);
real-time/streaming triggers (this evaluates once, at ingest-accept time, on the accepted
event only); the remaining O-012→O-014 ecosystem-integration-layer tasks (sub-ms
messaging backbone, global third-party gateway, command dashboard).

## Consequences

- A tenant can now wire "when I see event X (optionally from product Y, optionally
  matching these exact field values), re-drive this ONE of my own distributions" —
  entirely additive, off by default, and reusing every existing credential/engine/audit
  pattern this repo already established.
- The gap between this slice and the roadmap's fuller "autonomous multi-step
  cross-product workflow engine" vision is named explicitly (Honesty boundaries, Residual
  risk, Out of scope) rather than implied away, consistent with CLAUDE.md's mandatory
  honest-language rule and ADR-0009/ADR-0010's identical precedent.
- No existing seam, engine, schema, or product credential changed — this PR is purely
  additive, and the ingest pipeline's own dispositions (accepted/deduped/dead_lettered)
  and audit chain are untouched (byte-identical).
