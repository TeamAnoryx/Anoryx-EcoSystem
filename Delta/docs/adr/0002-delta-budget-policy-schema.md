# ADR-0002 — Delta Budget Policy Schema

- **Status:** Proposed (awaiting Affu approval)
- **Date:** 2026-06-26
- **Task:** D-002 (second Delta task)
- **Scope:** The Delta-side **budget *policy* representation** — a `BudgetPolicy`
  document that bundles a hard cap with advisory soft-warning / escalation tiers
  — plus the **emit path** that serializes its hard cap, byte-valid, into
  Sentinel's LOCKED `BudgetLimitPolicy` variant. **Policy SHAPE + emit only. No
  engine, no DDL, no migration.**
- **Depends on:** shipped D-001 (`0001-delta-financial-domain-model.md` — the
  `BudgetConcept` hard cap, the `budget_concept_to_policy_payload` emitter, the
  round-trip proof) and F-008 (`Anoryx-Sentinel/contracts/policy.schema.json`
  frozen at `a9e2344`; `Anoryx-Sentinel/docs/adr/` ADR-0009 policy intake).
- **Numbering:** Delta-scoped sequence (this is Delta ADR **0002**); D-001 took
  0001. Delta does not extend Sentinel's global ADR sequence (D-001 decision D6).

---

## Context

The ecosystem's defining feature is *financial policy enforced in the security
path*:

```
Delta → (budget policies) → Anoryx-AI-Orchestrator → (enforcement) → Sentinel
```

For that loop to carry a **budget**, Delta needs a budget-policy document that an
operator can express (cap + the warnings they want as spend approaches it) and
that serializes into the one shape Sentinel will enforce: the LOCKED
`BudgetLimitPolicy` variant of `policy.schema.json` (frozen at F-008 `a9e2344`).

D-001 already shipped the **hard-cap half**: `BudgetConcept` (a token/cost ceiling
per period at a scope), `budget_concept_to_policy_payload` (the producer side of
the CONFIRM), and `test_budget_variant_roundtrip.py` (which validates a
Delta-emitted `budget_limit` record against the real locked schema). D-002 adds
the **policy layer above the concept**: soft-warning thresholds, escalation tiers,
and a `BudgetPolicy` document that carries a hard cap *plus* those advisory
warnings — and it re-proves the serialized hard cap still passes the **untouched**
locked schema.

**The seam this ADR governs (read carefully):** the locked
`policy.schema.json` is the integration contract between Delta and Sentinel. The
whole point of D-002 is that **Delta's policy shape bends to that locked schema,
never the reverse.** This ADR proposes **zero** edit to `policy.schema.json`. If
any later revision of this design needs a new policy field, that is a v2 schema
negotiation gated on a new `$id` (`sentinel:policy:v2`) and a migration plan — out
of scope here, and explicitly rejected for D-002.

---

## Decision

### CONFIRM (gating) — the field-by-field map onto the LOCKED Budget variant

`BudgetLimitPolicy` (`Anoryx-Sentinel/contracts/policy.schema.json`, lines
71–125) is a pure hard-limit shape, `additionalProperties:false`, every field
bounded. It has **no spare field** for a warning threshold, an escalation tier,
an action, or free-form metadata.

| D-002 / Delta concept | → LOCKED `budget_limit` field | mapping |
|---|---|---|
| `cap.limit_tokens: int \| None` | `max_tokens_per_period` (integer `0..1e12`) | 1:1 (D-001) |
| `cap.limit_cost_cents: int \| None` | `max_cost_cents_per_period` (`number` `0..1e11`; Delta emits **int**) | 1:1 (D-001) |
| `cap.period` | `period` (`hourly\|daily\|monthly`) | 1:1 |
| `cap.scope` | `scope` (`tenant\|team\|project\|agent`) | 1:1 (Fork 1a) |
| at-least-one-of {tokens, cost} | object `anyOf` | same rule |
| `policy_id`, `policy_version`, `effective_from` | envelope fields | carried on `BudgetPolicy`, forwarded at emit |
| `signature` | `signature` | supplied at emit (Delta/Orchestrator sign; D-002 does not) |
| **soft-warning threshold** | — | **NO HOME → Fork 1** |
| **escalation tier / advisory action** | — | **NO HOME → Fork 1** |

**CONFIRM result:** the hard cap maps **1:1 with zero schema change**. The only
D-002 concepts with no home in the locked variant are soft-warnings and
escalation — which is exactly what Fork 1 resolves. The schema does not move.

### Fork 1 — Warning / escalation representation: **(b) Delta-side advisory**

Soft-warnings and escalation tiers are a **Delta-side concept that never enters
the signed policy.** They are modeled in Delta types only (`BudgetPolicy.warnings`);
**only the hard cap serializes** into a `budget_limit` record. F-008 and Sentinel
see the cap and nothing else.

Rejected alternatives:

- **(a) express within the locked variant using existing fields** — *impossible.*
  `BudgetLimitPolicy` is closed (`additionalProperties:false`) with no
  metadata / threshold / action field. There is literally no field to hold a
  warning. (a)'s "recommend if the fields exist" precondition fails.
- **(a-variant) multiple `budget_limit` records at lower caps** — *rejected.* A
  second, lower `budget_limit` is an actual **throttle** at that level, not a
  *warning*: the gateway would enforce it as a hard cap. `budget_limit` has no
  "warn-only" mode, so this would change enforcement semantics and mislead an
  operator who asked for a notification, not a cap.
- **(c) any new policy field** — *rejected.* The schema is locked; a new field is
  a v2 negotiation, out of scope.

**Warning basis — both/either (per the cap basis).** A warning tier's threshold
is **`percent` XOR `absolute cents`** (exactly one, enforced by a validator).
Soundness rule so ordering is well-defined and a tier is meaningful:

- All tiers within one `BudgetPolicy` share **one basis** (homogeneous; a mix of
  percent and absolute tiers in the same policy is rejected — there is no sound
  total order across the two without resolving percent against a live spend
  number, which is D-005's job, not D-002's).
- Tiers are **strictly ascending** by their basis value, no duplicates.
- A `percent` threshold is an integer in `[1, 99]` (100% **is** the hard cap, not
  a warning).
- An `absolute cents` basis is allowed **only** when the cap has a
  `limit_cost_cents`, and every `threshold_cost_cents` must be **`<
  cap.limit_cost_cents`** — a warning at or above the cap is over-permissive and
  meaningless.

**Escalation — threshold + advisory action.** Each tier carries a `WarningAction`
advisory label (`notify` / `alert` / `page`). This is a **Delta-advisory label
only**: Sentinel never sees it, no component acts on it. See the honesty boundary
below.

### Fork 2 — Scope granularity: **(tenant, team, project, agent) tuples** (inherited)

Budget scope is the four-ID identity tuple, exactly as D-001 Fork 1a fixed it. The
Delta `BudgetScope` enum (`tenant|team|project|agent`) already maps **1:1** to the
locked variant's `scope` enum and to the `events.schema.json` identity fields. A
Delta-native scope grammar was rejected at D-001 as a lossy translation; nothing
in D-002 needs one. **How it resolves against F-008:** the four body IDs on a
`budget_limit` record are a **cross-check only, not authoritative** — F-008
resolves the authoritative tenant/team/project scope **server-side from the
verified signature** and **rejects** any record whose body IDs disagree with the
signature-resolved scope (`policy.schema.json` description; mirrors the
`openapi.yaml` `id_context_mismatch` rejection). D-002 therefore **cannot widen a
budget's reach by setting body IDs**: the `scope` enum picks the *granularity*,
but the *authoritative identity* comes from the signature F-008 verifies. The
`scope` value never grants reach the signature does not authorize.

### Fork 3 — Window semantics: **fixed calendar windows `{hourly, daily, monthly}`** (inherited)

The reset window is the locked `period` enum exactly (`hourly|daily|monthly`),
inherited from D-001's `BudgetPeriod`. **Rolling windows are rejected:** a rolling
window needs a continuously-evaluated spend series (a ledger read), which is a
D-003/D-005 capability the contracts layer has not built. D-002 ships only the
window set the locked variant and D-001's `TimeWindow` already support.

---

## Warning / escalation posture — what F-008 enforces vs what is Delta-advisory

| Concept | Lives where | Serialized to F-008? | Enforced by Sentinel? |
|---|---|---|---|
| Hard cap (tokens/cost, period, scope) | `BudgetConcept` (D-001), embedded in `BudgetPolicy` | **Yes** (`budget_limit`) | Yes (F-008 intake + gateway throttle) |
| Soft-warning thresholds | `BudgetPolicy.warnings` (Delta type) | **No** | **No** |
| Escalation tier / `WarningAction` | `BudgetWarningTier.action` (Delta type) | **No** | **No** |
| `policy_id` / `policy_version` / `effective_from` | `BudgetPolicy` envelope | Yes | Yes (replay/rollback defense) |
| `signature` | supplied at emit (not held in the domain) | Yes | Yes (F-008 verifies) |

The emit path (`BudgetPolicy.to_policy_payload`) builds the `budget_limit` record
**from the embedded `BudgetConcept` alone**; warnings are dropped *by
construction*. Because the locked variant is `additionalProperties:false`, even an
accidental leak of a warning key would **fail** validation — so the drop is both
deliberate and contract-guarded. A dedicated test asserts no `warnings` /
`threshold_percent` / `threshold_cost_cents` / `action` key appears in the emitted
record.

---

## Honesty boundary (mandatory)

D-002 ships the **policy shape and its emit path only.** It does **not** enforce a
budget, throttle an agent, send a notification, or page anyone.

- **Soft-warnings and escalation are advisory.** Sentinel never receives them and
  nothing acts on them. The wiring that turns a warning tier into an actual
  notification or throttle is **D-005** (budget engine). Until then,
  `BudgetPolicy.warnings` is a declared *intent*, not an enforced behavior. Code,
  docstrings, and this ADR say so in plain language — no "escalation blocks
  spend" or "warns the operator" claim, because D-002 wires nothing.
- **The hard cap is a client-side cost estimate basis**, not an authoritative
  bill (`max_cost_cents_per_period` is an estimate; D-001 Fork 3).
- **Signing/intake is F-008.** D-002 does not sign and does not verify; it emits a
  record whose `signature` is supplied by the caller. A syntactically valid
  signature is not a verified one — runtime verification is F-008's.
- This is *risk reduction* through structural integrity and an honest emit
  contract, not a guarantee of financial enforcement.

---

## Threat model (with test paths)

| # | Vector | Defense | Test |
|---|---|---|---|
| 1 | **Schema drift** — D-002 silently mutates the LOCKED `policy.schema.json` | emit reuses D-001's builder; the round-trip test reads the real file and asserts the `LOCKED at F-008` marker; `git diff` of the file is empty | `test_budget_policy_emit.py`, STEP 9 `git diff` |
| 2 | **Warning leak into the signed policy** — an advisory tier reaches F-008 as if enforced | emit serializes the cap only; locked variant `additionalProperties:false` rejects any extra key; test asserts no warning key in the record | `test_budget_policy_emit.py` |
| 3 | **Float smuggling** — a monetary field accepts a float and exactness is lost | `threshold_cost_cents` + cap use `bounded_count` (rejects `float`/`bool`/`NaN`/`Inf`); wire schema field is `integer` | `test_budget_policy.py` |
| 4 | **Cross-tenant scope widening** — body IDs / `scope` used to widen a budget's reach | scope is a *granularity* enum; F-008 resolves authoritative identity from the verified signature and rejects body-ID mismatch (Fork 2); D-002 documents and tests scope→4-ID 1:1, never reach-granting | `test_budget_policy.py`, ADR Fork 2 |
| 5 | **Over-permissive policy** — a cap that limits nothing, or a warning at/above the cap | `BudgetConcept` at-least-one-of (D-001) rejects an empty cap before emit; warning validator rejects `threshold ≥ cap` and out-of-range percent | `test_budget_policy.py` |
| 6 | **Unsound warning order** — mixed-basis or unordered tiers create ambiguous/forgeable thresholds | validator: homogeneous basis, strictly ascending, no duplicates, XOR per tier | `test_budget_policy.py` |
| 7 | **JSON Schema permissiveness** — a missing `additionalProperties:false` or unbounded field in the Delta wrapper schema opens a smuggling/DoS channel | every object closed + every field bounded; extra-key / out-of-range payloads rejected | `test_budget_policy_schema.py` |
| 8 | **Implied enforcement** — the model implies it enforces warnings/budgets | ADR + docstrings state advisory-only; escalation carries a label, not a behavior; enforcement is D-005 | `test_budget_policy.py`, this ADR |

---

## Consequences

**Positive:** the budget loop gains an operator-facing policy document (cap +
advisory warnings) without the locked Sentinel contract moving a byte; the emit
path reuses D-001's proven builder (DRY); warnings are advisory and clearly
labelled, so no dishonest enforcement claim; the Delta wrapper schema is closed
and bounded like D-001's; the design is purely additive.

**Negative / accepted:** warnings/escalation do nothing until D-005 wires them
(declared intent, not behavior); mixed percent/absolute tiers in one policy are
disallowed (homogeneous basis — a small expressiveness cost for a sound order);
no rolling windows (deferred to D-003/D-005); the wrapper schema cannot express
the cross-field warning invariants (homogeneous/ascending/below-cap) — those are
Pydantic-validator-enforced, exactly as D-001's balance/sum invariants are.

**Out of scope (explicit):** budget enforcement / throttling / notification
(D-005), ledger posting + DDL + migration (D-003), signing and runtime signature
verification + scope-resolve-and-reject (F-008), any edit to
`policy.schema.json`, rolling windows, multi-currency.

---

## Rollback

D-002 is purely additive inside `Delta/`: one new module
(`src/delta/budget_policy.py` + an `__init__` export), one new Delta-side schema
(`contracts/delta-budget-policy.schema.json`), new tests, this ADR, and the
security audit. It adds **no migration, no DDL**, touches **no** Sentinel code,
and leaves `Anoryx-Sentinel/contracts/policy.schema.json` **and** D-001's
`Delta/contracts/delta-financial.schema.json` byte-for-byte unchanged. Rollback =
revert the single squashed D-002 commit; nothing depends on it yet, so the revert
is clean and total.
