# D-002 Security Audit — Delta Budget Policy Schema

**Auditor:** Anoryx Sentinel independent Security Auditor (arms-length red-team)
**Date:** 2026-06-26
**Worktree:** `E:/Anoryx-EcoSystem/worktrees/d-002`
**Scope under audit (new in D-002):**
- `Delta/src/delta/budget_policy.py`
- `Delta/contracts/delta-budget-policy.schema.json`
- `Delta/src/delta/__init__.py` (exports only)
- `Delta/tests/test_budget_policy.py`, `test_budget_policy_emit.py`, `test_budget_policy_schema.py`
- `Delta/docs/adr/0002-delta-budget-policy-schema.md`

**Reused (D-001, shipped — read, not the delta):** `attribution.py::budget_concept_to_policy_payload`, `budget.py::BudgetConcept`, `money.py` (`bounded_count`/`reject_non_integer`/`require_aware_utc`), `identifiers.py::UuidStr`.
**Hard contract:** `Anoryx-Sentinel/contracts/policy.schema.json` (LOCKED `BudgetLimitPolicy`).

---

## Threat model of the change

The new trust boundary D-002 introduces is an **emit seam**: `BudgetPolicy.to_policy_payload()` produces a dict that, after an external signer attaches a signature, becomes a policy record F-008 will treat as authoritative budget enforcement. The two interesting input surfaces are (a) operator-supplied `BudgetPolicy` fields (cap, warnings, envelope) and (b) the `signature` argument at emit. The danger classes are: drifting/forging the LOCKED schema, leaking advisory warnings into the signed record (privilege confusion — Delta "intent" masquerading as enforced policy), float/precision smuggling into money, scope-widening via body IDs, and over-permissive output. D-002 does no network/file/subprocess I/O, makes no LLM calls, and adds no third-party dependency, so SSRF / path traversal / command injection / insecure-deserialization / prompt-injection / supply-chain surfaces are not present in the changed production code.

All findings below were validated by executing the actual d-002 code (path-forced to the worktree, confirmed `delta.__file__` = `...worktrees/d-002/Delta/src/delta/__init__.py`), not by reading alone.

---

## Attack results (per requested vector)

**1. LOCKED-schema integrity — PASS.**
`git -C E:/Anoryx-EcoSystem/worktrees/d-002 diff --stat -- Anoryx-Sentinel/contracts/policy.schema.json` is **empty**; full `git diff HEAD -- Anoryx-Sentinel/` is empty. The only tracked change in the whole worktree is `+10` lines in `Delta/src/delta/__init__.py` (exports). The LOCKED file is byte-identical to HEAD. Emit output validated **byte-valid** against the unmodified file with a real Draft 2020-12 validator (format-checked): 0 errors. Emit key set is exactly the LOCKED `BudgetLimitPolicy` shape — `{policy_type, tenant_id, team_id, project_id, agent_id, policy_id, policy_version, effective_from, signature, period, scope, max_cost_cents_per_period}`. No drift, no in-place mutation.

**2. Float / bool / NaN / Inf in monetary fields — PASS.**
Every smuggling attempt rejected with `ValidationError`/`ValueError`: `threshold_cost_cents` = NaN, Inf, 1.5, `True`, `"500"`; `threshold_percent` = 50.0, `True`; `cap.limit_cost_cents` = NaN/Inf/1.5; `cap.limit_tokens=True`; `policy_version` = 1.0/NaN/True. `reject_non_integer` (`money.py:41`) explicitly rejects `bool` (int subclass) and `float` before Pydantic coercion, and the before-validators in `budget_policy.py:77-97` route through `bounded_count`/`reject_non_integer`. No float reaches the cap or the emitted record.

**3. Scope spoofing / cross-tenant widening — PASS (and honest).**
The four body IDs are carried verbatim into the emitted record (`attribution.py:76-82`); the `scope` enum only selects granularity. `budget_policy.py` does not claim the body scope is authoritative. ADR-0002 Fork 2 and the LOCKED schema description both state body IDs are **cross-check only** and F-008 resolves the authoritative scope server-side from the verified signature and rejects mismatches. D-002 cannot widen reach by setting body IDs — the signature it does not produce is the authority. Wrapper-schema scope enum is closed (`global`/`root` rejected). Honest and correct.

**4. Over-permissive output — PASS.**
- A cap that limits nothing cannot be constructed (`BudgetConcept._at_least_one_limit`, `budget.py:67`), so no `BudgetPolicy` can wrap it and no record without a limit field can be emitted (would also fail the LOCKED `anyOf`).
- Both limit fields are bounded `[0, max]`; a 0-cost cap emits `max_cost_cents_per_period: 0` — the **strictest** budget (zero spend), not "no limit". There is no path to an unbounded/absent limit.
- Warning at the cap (`==`) and above the cap (`>`) are both rejected (`_warnings_sound`, `budget_policy.py:183`). A 0-cost cap with an absolute warning is rejected (threshold must be `>=1` and `< cap == 0`, impossible).

**5. Warning leak into the signed record — PASS.**
`to_policy_payload` passes only `self.cap` + envelope to the D-001 builder, which constructs a fixed dict of known keys (`attribution.py:74-92`). Live emit with both percent and absolute warnings present produced **zero** advisory keys (`{warnings, threshold_percent, threshold_cost_cents, action}` ∩ record = ∅). `to_policy_payload(..., warnings=...)` raises `TypeError` (no injection kwarg). Each call returns an isolated dict (mutating one does not affect the next). The LOCKED `additionalProperties:false` is a second guard, but the drop is by construction.

**6. Honest escalation claim — PASS.**
Module docstring (`budget_policy.py:12-19`), `WarningAction` docstring (51-57), `BudgetPolicy`/`to_policy_payload` docstrings, and ADR-0002 "Honesty boundary" consistently state warnings/escalation are **Delta-advisory only**, Sentinel never sees or enforces them, and the wiring is deferred to D-005. No "blocks spend" / "warns the operator" / "enforces escalation" language. Consistent with the ecosystem honest-language rule.

**7. JSON Schema permissiveness (Delta wrapper) — PASS.**
Recursive audit of `delta-budget-policy.schema.json`: every object closed (`additionalProperties:false`), including both `BudgetWarningTier.oneOf` branches; no unbounded string (all carry `maxLength`/`pattern`/`enum`/`format`), no unbounded array (`warnings.maxItems:64`), no unbounded integer (all carry `maximum`). Live rejections confirmed: extra key at top/cap/tier level; tier matching both or neither `oneOf` branch; 65 tiers; 65-char `agent_id`; 1000-char and lowercase `currency`; `policy_version > 2**53-1`; `limit_cost_cents > 1e11`; `limit_tokens > 1e12`; unknown `scope`/`action`. No smuggling or DoS channel found.

**8. Secrets / PII — PASS.**
Heuristic scan (passwords/keys/tokens/PEM/AWS keys/SSN patterns) over all six new files: no matches. Fixtures use synthetic UUIDs (`12121212-…`), the slug `gateway-core`, and a dummy JWS `aaaa.bbbb.cccc`. No real credentials or PII.

**Semgrep** (`p/python p/security-audit p/secrets`, `--severity=ERROR`, `--no-git-ignore`) on `budget_policy.py`: **0 ERROR-severity findings**.

---

## Findings

No High or Critical findings in this pass. No Medium. The items below are **Informational** — none is a defect in shipped code, none requires escalation; they are recorded for D-005 and CI hygiene.

| # | Severity | File:line | Issue | Exploit path | Fix |
|---|----------|-----------|-------|--------------|-----|
| I-1 | Info | `Delta/tests/test_budget_policy_emit.py` (`_locked_policy_schema_path`) | The "LOCKED schema" used for the byte-validity proof is resolvable via the `SENTINEL_POLICY_SCHEMA_PATH` env var. | A CI/dev environment that sets this var to a permissive copy would let the emit test pass against a non-canonical schema, weakening the test's tamper-evidence. Not reachable from production code; mitigated because the test still asserts `$id == "sentinel:policy:v1"` and `"LOCKED at F-008" in raw`, and the authoritative drift guard is the STEP-9 `git diff` of the real file. | Accepted as-is (mirrors the D-001 `test_budget_variant_roundtrip.py` idiom); the in-repo default path + lock-marker asserts + `git diff` gate bind the proof to the committed contract. |
| I-2 | Info | `Delta/src/delta/budget_policy.py:99-121`, ADR Fork 1 | A `percent`-basis warning is accepted on a token-only cap and on a 0-cost cap; "percent of what" (tokens vs cost vs live spend) is not pinned at this layer. | No security impact — warnings are never serialized and never reach Sentinel. But D-005, which will resolve percent against live spend, must define the reference base explicitly and honestly so a `50%` tier on a 0/token-only cap is not silently meaningless. | Deferred to D-005: document and validate the percent reference base when enforcement is wired; no change needed in D-002. |
| I-3 | Info | `Delta/src/delta/budget_policy.py:43` vs `Delta/src/delta/attribution.py:31` | `MAX_POLICY_VERSION` is duplicated as a literal in two modules (both `9007199254740991`, matching the LOCKED `maximum`). | A future edit to one literal but not the other could let `BudgetPolicy` construct a version the emit builder then rejects (fail-closed, not a bypass). Drift is currently caught because the emit builder re-validates the bound. | Accepted (defense-in-depth): the emit builder re-validates the bound, so any drift fails closed (an unemittable record), never a bypass. Both literals are pinned to the LOCKED schema `maximum` with a cross-referencing comment. |

Note on `currency`: the wrapper schema requires `currency` on `BudgetConcept`, but emit deliberately omits it (the LOCKED `BudgetLimitPolicy` has no currency field; `additionalProperties:false` would reject it). This is intended single-currency behavior inherited from D-001 Fork 4, not a D-002 defect.

---

## Verdict

**PASS-WITH-NOTES.**

No High or Critical findings in this pass; no Medium. The LOCKED `policy.schema.json` is byte-identical (empty diff), the emit output is byte-valid against the unmodified contract, advisory warnings provably do not leak into the signed record, float/bool/NaN/Inf are rejected on every monetary path, the Delta wrapper schema is fully closed and bounded, the scope-authority model honestly defers to F-008's signature resolution, and no secrets/PII are present. Semgrep ERROR pass is clean. The three Informational notes (I-1 test env override, I-2 percent reference base for D-005, I-3 duplicated version constant) are non-blocking and require no human escalation.
