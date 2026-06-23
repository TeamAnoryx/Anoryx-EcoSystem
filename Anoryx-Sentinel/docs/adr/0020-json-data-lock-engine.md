# ADR-0020 — JSON Data-Lock Engine (F-017)

- **Status:** Proposed
- **Date:** 2026-06-23
- **Deciders:** (data-lock owner / implementer), persistence (migrations `0022` widening `ck_policies_policy_type` + `ck_pv_policy_type`, `0023` widening `ck_eal_event_type`; `_VALID_POLICY_TYPES` + `events_audit_log` constants), api-architect (contract — `policy.schema.json` `data_lock` payload, `events.schema.json` 4 new variants, `ids.md` `data-lock` principal slug; **no new `openapi.yaml` endpoint, no new error_code** — non-stream withhold mutates the body in place, fail-closed block reuses `policy_blocked`), security-auditor (arms-length gate — a data-lock that **leaks on error** is the worst outcome; fail-open is the headline risk), Affu (solo founder & product owner — resolved the STEP-0 forks during planning, approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0007 (F-005 hooks — F-017 **reuses** `HookRegistry` + the `PostResponseHook` contract + the dedicated-detector-slot pattern introduced by F-016's `run_code_scan`; existing detector logic unchanged), ADR-0009 (F-008 policy — F-017 **reuses** `PolicyRepository.get_active_policies_for_scope` with a new `policy_type="data_lock"`; engine unchanged), ADR-0005/0006 (tenant isolation / RLS Option α — config read + event write under the caller's existing tenant session; **no new bypass**), ADR-0006 (gateway — F-017 attaches inside the existing `create_chat_completion` handler only; **no new endpoint, no reordered middleware, no changed error envelope**), ADR-0003/0004 (append-only hash-chained audit — F-017 **appends** 4 new event variants via the existing writer; rows never mutated), F-004/F-014 identity (F-017 **reads** the server-resolved principal; **no new auth model**). Governed by `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/policy.schema.json`, `contracts/ids.md`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-017 — a **post-response data-lock detector** that lets a tenant declare, via F-008 policy, that specific **fields in the assistant's JSON output** are **locked until a server-evaluated condition** (time / permission) is met. When the condition is unmet, the field's **value is withheld** (replaced with a placeholder) before the response is returned. It is the **first conditional, field-level access control on response content** — a conditional sibling of PII masking.

> Honest-language note (per CLAUDE.md): this document says "risk reduction" and "withheld until condition," never "unbreakable," "guaranteed confidential," or "zero-leak." F-017 raises the cost of a locked field reaching a caller who should not yet see it; it operates only on JSON-structured assistant output (stated scope §8) and is fail-closed by design.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

- **Hook framework** (ADR-0007): `src/orchestration/hooks/base.py` — `PostResponseHook.inspect(content, ctx) -> DetectorResult(action: "pass"|"mask"|"block", event, modified_payload, defer_emit)`. `src/orchestration/registry.py` runs the chain **fail-safe** (unexpected exception → BLOCK). F-016 added a **dedicated single-detector slot** (`_code_scan_detector` + `run_code_scan()`), *excluded* from the per-chunk streaming chain because it needs the **complete** body. F-017 reuses that exact slot pattern.
- **Withhold mechanism** (ADR-0007 SEC-ENT rework): `src/gateway/routes/chat_completions.py:438-500` — on a secret finding, `_redact_in_place(parsed_completion_dict, fn)` walks the **parsed** structure and replaces string leaves, then `json.dumps` → `Response`. F-017 reuses this parsed-structure-then-reserialize mechanism for field-level withholding.
- **Per-tenant policy** (ADR-0009): `PolicyRepository.get_active_policies_for_scope(tenant_id, policy_type)` — RLS-scoped read returning rows whose `policy_payload` (Text JSON) the caller parses. F-016's `src/code_scan/config.py` is the precedent loader (`get_tenant_session(tenant_id)` → parse). F-017 adds `policy_type="data_lock"`.
- **Principal** (ADR-0006/0017): `HookContext.tenant_context` exposes the four server-resolved IDs (`tenant_id / team_id / project_id / agent_id`) + `virtual_key_id`. Data-plane callers are **virtual API keys with no role/scope** — only these identity IDs. F-014 RBAC roles exist only for admin/operator principals on `/admin/*`, never on `/v1`.
- **Events 4-site discipline**: `VALID_EVENT_TYPES` (`events_audit_log.py:40`) + `ACTION_TAKEN_BY_EVENT_TYPE` (`:104`) + `ck_eal_event_type` CHECK (`:291`, widened DROP+ADD per migration) + `contracts/events.schema.json`. **Migration head = `0021`** (F-016 merged to main, PR #21).
- **The F-016 CRIT-2 precedent** (`docs/audit/f-016-security-audit.md`): F-016 shipped a new `policy_type="code_scan"` that was **never registered** in `_VALID_POLICY_TYPES` nor the two DB CHECK constraints → every policy write was rejected → the detector was a **permanent production no-op**, masked by tests that stubbed the config load. *"A security control that cannot be turned on is indistinguishable from one that is absent."* F-017's STEP 2 exists specifically to not repeat this.

### 1.2 Decision (one paragraph)

We add a **`src/data_lock/` package** providing a **6th `PostResponseHook`** (`DataLockDetector`, `detector_slug="data-lock"`) in a **dedicated registry slot** (`_data_lock_detector` + `run_data_lock()`, excluded from the per-chunk chain because withholding requires the **complete** JSON). It: (1) loads a **default-OFF, per-tenant** `data_lock` F-008 policy whose payload is a **bounded** list of rules `{field_path, condition}`; (2) for a **non-streamed** response, parses each assistant `message.content` **that is itself a JSON document**, resolves each rule's **bounded dotted-path** selector, evaluates the rule's **server-authoritative** condition (**TIME** via the server clock only; **PERMISSION** via an identity-attribute allow-list over the server-resolved `team_id/project_id/agent_id`), and **withholds** (replaces the value with a placeholder) every field whose condition is unmet — re-serializing via the existing parsed-structure path; (3) **fails CLOSED** at two tiers (§4): a per-field unevaluable condition → that field **stays withheld**; a config-load/parse error where the ruleset cannot be enumerated → the **whole response is blocked** (`policy_blocked` 403); (4) for a **streamed** response, since a field cannot be withheld from bytes already on the wire, a request is **fail-closed blocked** before the first byte whenever the tenant has ≥1 active data_lock rule; (5) is registered as `policy_type="data_lock"` in `_VALID_POLICY_TYPES` **and** both DB CHECK constraints via a **reversible migration `0022`**, proven by a **non-stubbed persist→load test** *before* enforcement is built; (6) emits **4 new event variants** (`field_locked` / `field_unlocked` / `lock_condition_denied` / `data_lock_error`) added **4-site** with reversible migration `0023`, reusing existing nullable audit columns and **never recording a field value**. **No `/v1` auth, no F-003/F-003b/F-004/F-005/F-008/F-012a/F-014 engine logic, no error envelope, and no endpoint is modified** — F-017 is purely additive.

### 1.3 What changes vs what is frozen

| Frozen (MUST NOT change) | Changes (F-017) |
|---|---|
| ADR-0007 hook framework, existing 5 detectors | **Reused.** Add a 6th `PostResponseHook` in a dedicated slot; register in `build_default_registry`. |
| ADR-0006 middleware order, `/v1` endpoints, `Error.error_code` enum | **Unchanged.** Fail-closed block reuses `policy_blocked` (403); non-stream withhold mutates the body. No new error_code, no new endpoint. |
| ADR-0009 policy engine | **Reused.** New `policy_type="data_lock"`; no new config system. |
| ADR-0005/0006 RLS role/GUC model | **Reused.** Config read + event write under the caller's tenant session. No new bypass. |
| F-004 / F-014 identity | **Read only.** "Permission" = identity-attribute match on the server-resolved principal. No new auth model, no role on virtual keys. |
| ADR-0003/0004 append-only audit | **Appended to.** 4 new event variants via the existing writer; rows never mutated; never the field value. |
| F-004/F-005 PII masking, F-016 code-scan | **Unchanged.** F-017 is a distinct conditional withhold; it does not alter masking or scanning. |

---

## 2. Decision: the posture is inverted from F-016 — FAIL CLOSED

F-016's scanner reads attacker-influenceable input and therefore **fails to WARN** (a scanner DoS must not become a weaponizable block). **F-017 is the opposite.** A data-lock is an **access control on confidential output**: if it cannot decide whether a field may be released, the only safe answer is **do not release it**. This aligns with Sentinel CLAUDE.md rule 5 ("on ANY inspection/policy error → BLOCK"). Three consequences, recorded so no one re-derives the wrong posture:

1. The default on **any** error/timeout/ambiguity is **withhold** (or block), **never** release. Fail-open here = a confidential field leaking — the worst outcome (R1).
2. Conditions are **server-authoritative and non-forgeable** (R2). Time is the server clock; permission is the server-resolved principal. A caller-supplied claim/header/body field **never** influences a release. Adversarially tested (vectors 2, 3).
3. F-017 makes **no** confidentiality guarantee for non-JSON output. It withholds fields in **JSON-structured** assistant content only (§8); prose that embeds a "locked" value is out of scope and stated as such.

---

## 3. Decision: the forks (Affu-resolved at STEP 0)

**Fork 1 — the lock semantic (resolved (a) WITHHOLD/MASK; this was the no-default gate).** "Locked" = the field's **value** is replaced with a withheld placeholder in the response while the condition is unmet; released (passed through) once met. **Field-level** granularity — never reject the whole payload (that was rejected option (b); (c) hold-for-later-release is a stateful workflow, rejected as a much larger feature). Reuses the F-005 masking-action path. **Fail-closed is structural**, not advisory (§4).

**Fork 2 — payload location (resolved: RESPONSE only).** Locks apply to fields **inside the assistant `message.content` when it parses as a JSON document** (JSON-mode / structured output / tool-call arguments). Response-envelope fields (`id`, `model`, `usage`, `choices` structure) are **never** touched — withholding them would break the OpenAI contract. Request-side withholding is out of scope (it overlaps PII masking-up and does not fit a withhold-from-caller semantic).

**Fork 3 — permission source (resolved: identity-attribute allow-list).** Data-plane callers are virtual API keys with **no role/scope** — only server-resolved `tenant_id/team_id/project_id/agent_id`. `tenant_id` is trivially the caller's own (policies are already tenant-scoped). A PERMISSION condition therefore carries an **allow-list** over `team_id`/`project_id`/`agent_id`; the field is released iff the caller's **server-resolved** ID is in the allow-set. **No new auth model**; **no caller-supplied value is ever trusted** (R2).

**Fork 4 — approval condition (resolved: DEFERRED).** v1 supports **TIME + PERMISSION** only. Approval (locked until an out-of-band human approval) is a **stateful workflow** (pending→approved, an approver, a release action, retention) — a predicate it is not — and is documented as a later feature.

**Fork 5 — field selector dialect (resolved: bounded dotted-path).** `a.b.c` for objects, `a.b[].c` for "every element of an array". **Bounded** (R7): `MAX_RULES`, `MAX_PATH_DEPTH`, `MAX_PATH_SEGMENTS`, and a payload-size / node-count cap on traversal. A JSONPath subset (wildcards/filters) was rejected for v1 as a larger, riskier parser surface.

**Git base (operational).** F-016 (PR #21) merged to main during planning (head `0021`); F-017 branches **clean off current main** with F-016 present. Migrations are `0022` (policy_type) + `0023` (events); head-pin test bumps `0021 → 0023`.

---

## 4. Decision: fail-closed is two-tier (R1 — the load-bearing design)

> A data-lock that releases on error is worse than no lock. F-017 never releases a field on error.

| Failure | Tier | Action |
|---|---|---|
| A matched field's **condition** is malformed / unevaluable (bad `unlock_at`, clock issue, unknown condition type) | **per-field** | That field **stays withheld** (`field_locked` / `lock_condition_denied` emitted). Other fields evaluate normally. |
| The **config/ruleset cannot be enumerated** — DB/session error, unparseable `policy_payload` (we cannot know which fields are locked) | **whole-response** | **Block** the entire response with `policy_blocked` (403) + `data_lock_error`. Releasing here would be fail-open because the lock set is unknown. |
| The assistant `message.content` is **not JSON** | n/a (stated scope) | No field matches → pass. Prose is out of scope (§8). |
| The response is **streamed** and the tenant has ≥1 active rule | pre-flight | **Block** before the first byte (§5). |

The empty-result vs exception distinction is the crux: `get_active_policies_for_scope` returning **`[]`** (tenant never opted in) is a **successful** load → `armed=False` → cheap pass; an **exception** during load → the loader **raises** (it does **not** swallow to disabled the way `code_scan/config.py` does) → the detector blocks. This is the precise inversion of F-016 and is empirically tested by vector 1 (forced error → field withheld, `data_lock_error` audited).

---

## 5. Decision: streaming is fail-closed (R1, R5 — honest limitation)

A streamed response commits the 200 + bytes to the client **before** the complete JSON exists, so a field **cannot** be selectively withheld mid-stream — and we cannot know whether a rule matches until the JSON is complete. The only honest, leak-free posture is: **when the tenant has ≥1 active `data_lock` rule, a `stream=true` request is blocked** (`policy_blocked` 403, or an `SSEErrorEvent` if detected after headers commit) at a **pre-flight** check before the first byte. Tenants using data-lock issue **non-streamed** requests. Buffer-then-withhold (restoring streaming) was rejected for v1 (latency + memory + complexity). This is stated everywhere a streamed-lock might be assumed; **no** streamed-withhold guarantee is claimed.

---

## 6. Decision: the policy_type registration plan (R3 — the CRIT-2 countermeasure, done FIRST)

Built and proven in **STEP 2, before any enforcement**, so the feature cannot ship inert:

1. Add `"data_lock"` to `_VALID_POLICY_TYPES` (`policy_repository.py:33`).
2. Widen **both** `ck_policies_policy_type` (`policy.py:92`) and `ck_pv_policy_type` (`policy.py:155`) — DROP+ADD, the established 0008/0015/0020/0021 pattern.
3. Reversible migration **`0022_data_lock_policy_type.py`** (clone of `0021`).
4. The `data_lock` payload schema added to `contracts/policy.schema.json` (api-architect) so signed intake (`policy/intake.py` → `validate_policy_record`) accepts it.
5. **Non-stubbed persist→load test** (vectors 5, 6): `save_new_version`/`upsert_policy('data_lock', …, signature=<valid>)` against the **real** DB → real `get_active_policies_for_scope` load → rule parsed enabled; alembic upgrade↔downgrade round-trip. **No `load_data_lock_config` / repository patching.** This is the test F-016 lacked.

---

## 7. Decision: selector + condition bounds + non-forgeability (R2, R7)

| Bound / guard | Control |
|---|---|
| Rule count | `MAX_RULES` per policy; excess → fail-closed parse rejection. |
| Path depth / segments | `MAX_PATH_DEPTH`, `MAX_PATH_SEGMENTS`; over-deep path → rule rejected (fail-closed). |
| Traversal | Bounded node-count / depth walk over the parsed JSON (no unbounded recursion; deep-nesting / huge-payload DoS guard — vector 11). |
| TIME condition | `datetime.now(timezone.utc)` **only**; `unlock_at` is a server-compared ISO-8601 instant. A caller-supplied time field is never read (vector 3). |
| PERMISSION condition | Allow-list matched against `ctx.tenant_context.{team,project,agent}_id` **only**; never a header/body/claim (vector 2). |
| Determinism | A multi-field payload either withholds **every** unmet matching field or fails closed for the whole response — never a half-applied transform that releases a field that should be locked (R5, vector 4). |

---

## 8. Decision: honest scope (stated explicitly)

- The lock semantic is **exactly withhold** (Fork 1 (a)) — no creep into reject/hold.
- **Approval is deferred** (Fork 4); v1 = time + permission.
- The selector is a **bounded dotted-path** (Fork 5); no JSONPath.
- **Response-only** (Fork 2); request fields are not locked.
- Locking applies only to **JSON-structured assistant content**; **prose that embeds a locked value is out of scope** and is not withheld.
- **No new auth model** — "permission" is identity-attribute matching on the existing principal.
- **Streaming is blocked** for tenants with active rules, not withheld (§5).
- **Fail-closed** everywhere (§4).

---

## 9. Decision: events (4-site) + audit (R4)

Four variants, added 4-site (`VALID_EVENT_TYPES` + `ACTION_TAKEN_BY_EVENT_TYPE` + `ck_eal_event_type` via migration `0023` + `contracts/events.schema.json`):

| event_type | action_taken | meaning |
|---|---|---|
| `field_locked` | `blocked` | a field value was withheld (time-not-yet / generic) |
| `lock_condition_denied` | `blocked` | a PERMISSION allow-list did not match the caller |
| `data_lock_error` | `blocked` | fail-closed: config/ruleset unevaluable → whole response blocked |
| `field_unlocked` | `logged` | a matched field's condition was met → released (informational) |

All four `action_taken` values (`blocked`/`logged`) already exist in `ck_eal_action_taken` → **that constraint is unchanged**. Audit payloads carry **metadata only**, reusing existing nullable columns — field path → `pattern_name`, condition type → `violation_type`, rule/policy id → `policy_id` — and **never the field value** (CLAUDE.md rule 6). Events are stamped with the caller's real tenant/team/project (RLS-scoped; vectors 9, 10). **No new columns.**

---

## 10. Threat model → test map (≥12 vectors, empirical)

| # | Vector | Test (non-stubbed where marked) |
|---|---|---|
| 1 | lock-engine error → field withheld, NOT released; `data_lock_error` audited | `test_lock_engine_error_keeps_field_locked` |
| 2 | caller-supplied permission claim/header/body does NOT unlock | `test_caller_cannot_forge_permission_unlock` |
| 3 | caller-supplied time cannot satisfy a time-lock (server clock only) | `test_time_condition_uses_server_clock` |
| 4 | multi-field payload: all matching locked or fail-closed; never half-released | `test_no_partial_leak_multifield` |
| 5 | **NON-STUBBED** real `upsert_policy('data_lock')` → real load → enabled | `test_data_lock_policy_persists_and_loads` |
| 6 | migration widens both constraints; reversible round-trip | `test_migration_widens_policy_type_constraints` |
| 7 | field withheld before condition met, released/handled after | `test_locked_field_withheld_until_condition` |
| 8 | non-locked fields pass through unchanged | `test_unmatched_fields_untouched` |
| 9 | every lock/unlock/deny in the append-only log, tenant-scoped | `test_lock_action_audited` |
| 10 | tenant A's rules/state invisible to B | `test_lock_rules_tenant_scoped` |
| 11 | pathological nesting / huge payload capped, no DoS | `test_deep_nested_payload_bounded` |
| 12 | **NON-STUBBED e2e**: real persist → real load → real payload through the real hook → field actually withheld (ZERO stubs on config/load/persist/enforcement) | `test_real_path_end_to_end_nonstubbed` |

---

## 11. Rollback

- **Disable without deploy:** set `enabled:false` (or remove the `data_lock` policy) per tenant → `armed=False` → cheap pass. Default-OFF means non-adopters are never affected.
- **Migrations:** `0023` then `0022` `downgrade` restore the prior `ck_eal_event_type` (0021 set) and the prior three-+code_scan policy_type set; loss-free (no pre-F-017 row uses the new values). Round-trip verified at STEP 10.
- **Code:** the detector is import-guarded in `build_default_registry` (like code_scan); removing the `[data-lock]` extra / package → the slot is `None` → `run_data_lock` is a no-op. `/v1` behavior reverts to F-016 exactly.

---

## 12. Consequences

- **Positive:** first conditional field-level access control on response content; reuses F-005/F-008/identity with no new subsystem or auth; fail-closed by construction; CRIT-2 trap closed up front; no contract-breaking changes; clean rollback.
- **Negative / accepted:** streamed requests are blocked for data-lock tenants (honest §5); a DB/config-load outage blocks responses for a tenant whose rule set cannot be read (the fail-closed cost, consistent with the existing DB-down→fail-closed audit posture); prose-embedded locked values are out of scope; permission granularity is limited to identity IDs (no RBAC on the data plane until a future auth model).
