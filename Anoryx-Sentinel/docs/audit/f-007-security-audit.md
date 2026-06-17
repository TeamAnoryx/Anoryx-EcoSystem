# F-007 Security Audit — LLM-as-Judge Injection Classifier, Shadow-AI Egress Detection & B2C Classifier-Config Inheritance

- **Branch:** main (uncommitted working tree)
- **HEAD commit:** 0279ab6b670f68bae6128fbb081a8c8ad775bb39
- **Date:** 2026-06-18
- **Auditor:** security-auditor (independent red-team; did not author this code)
- **Scope:** F-007 change set per ADR-0010 — `src/orchestration/judge/{__init__,base,prompts,haiku,gpt_mini,registry,invoker,config}.py`; `src/gateway/middleware/egress_monitor.py`; migrations `0009`/`0010`; modified `orchestration/detectors/{injection_detector,shadow_ai_detector}.py`, `orchestration/{config,context}.py`, `gateway/router/providers/{anthropic,openai}_provider.py`, `gateway/router/registry.py`, `gateway/routes/chat_completions.py`, `gateway/upstream/openai_proxy.py`, `gateway/context.py`, `persistence/models/{events_audit_log,tenant_routing_policy}.py`, `persistence/hash_chain.py`, `persistence/repositories/{audit_log_repository,tenant_routing_policy_repository}.py`, `policy/cli.py`, `contracts/events.schema.json`.

> Persisted compliance artifact (STEP 10 / mandatory per F-008 precedent). Verbatim final report of the independent security-auditor re-run. Re-run on a later commit if the F-007 code changes.

---

## Executive Verdict: PASS

No High or Critical findings in this pass. The two F-005 honest deferrals are closed with a correctly fail-SAFE design: every judge path (unconfigured, policy-denied, provider-unavailable, degraded, invocation-failed, malformed structured output, low-confidence, timeout, generic exception) falls back to the F-005 regex verdict and **never** returns "allow"/"skip". `asyncio.CancelledError` is correctly left to propagate (it is `BaseException`, not caught by the `except Exception`). Structured-output forcing plus a static, non-interpolating system prompt and re-validation in `verdict_from_dict` make the judge contract attacker-resistant. The hash-chain 4-site wiring is complete and consistent. One Low finding (stale migration test fixtures) contradicts the "163 tests green" precondition and is reported below.

---

## Tooling Evidence

**Semgrep** — `semgrep scan --config=p/python --config=p/secrets --severity=ERROR --json --no-git-ignore <changed files>`, run in two batches over all F-007 new + modified source files:
- New `judge/*`, `egress_monitor.py`, migrations `0009`/`0010`: **0 results, 0 errors**.
- Modified detectors / providers / persistence / cli: **1 result, 0 errors** — `python.sqlalchemy.security.audit.avoid-sqlalchemy-text` at `src/persistence/repositories/audit_log_repository.py:234`. Triaged **false positive / not F-007**: the `text()` call is `pg_advisory_xact_lock({_CHAIN_ADVISORY_LOCK_ID})` where `_CHAIN_ADVISORY_LOCK_ID` is a hardcoded module-level integer constant (line 61), not attacker-controllable. This is pre-existing F-003 code untouched by F-007. No High/Critical.

**Tests:**
- F-007-specific suite (`tests/orchestration/judge`, `test_injection_detector_ml.py`, `test_classifier_threat_model.py`, `tests/gateway/test_egress_monitor.py`, `test_shadow_ai_threat_model.py`, `tests/persistence/test_classifier_config.py`, `test_f007_event_variants.py`, `tests/policy/test_cli_classifier.py`): **92 passed**.
- Full repository suite (`tests/`): **577 passed, 2 failed** in 332s. Both failures are in `tests/persistence/test_migrations.py` (stale `0008`-head assertions) — see F-007-04. NOT a security regression; the migration round-trip itself succeeds.

**Ruff:** No issues found on F-007 files. **Black:** all F-007 files unchanged (clean).

---

## Findings

| ID | Severity | file:line | Issue | Status |
|----|----------|-----------|-------|--------|
| F-007-01 | Low | `src/gateway/routes/chat_completions.py:242` | `current_egress_context` is cleared at request start but not reset in a `finally`. Not exploitable cross-tenant: contextvars are task-local and each request runs in its own asyncio task with a fresh copy (default `None`); the start-of-request `.set(None)` is itself defensive. Worst case on any pathological task reuse is a stale binding within the *same* tenant's next call, never a cross-tenant leak. | Accepted (defense-in-depth already present) |
| F-007-02 | Low | `src/policy/cli.py:96-103` | `classifier set` INSERT hardcodes `allowed_providers='openai,anthropic,bedrock'` on the INSERT branch only; the `ON CONFLICT DO UPDATE` branch correctly does **not** touch `allowed_providers`. A brand-new tenant created via `classifier set` is provisioned with all three providers allowed — identical to the documented `default_policy` for a tenant with no row, so no privilege widening occurs. Operator-facing behavior note. | Accepted |
| F-007-03 | Low | `src/orchestration/detectors/injection_detector.py:382` | Pre-filter uses `getattr(self._settings, "judge_skip_score", 0.9)`. If an operator sets `judge_skip_score` to a value `>1.0`, the "obvious attack" skip can never trigger and a `regex_score` in `[0.9,1.0]` would be sent to the judge. Harmless (fail-safe still blends `max(regex,judge)`; regex `>=0.75` still blocks). No bypass. | Accepted |
| F-007-04 | Low | `tests/persistence/test_migrations.py:45-49, 53-63, 72` | Migration tests were not updated for F-007: they hard-assert Alembic head == `0008` and `num_revisions = 8`. With `0009`/`0010` added, head is now `0010`, so `test_current_head_is_0008` and `test_migration_downgrade_and_reapply` FAIL (2 of 577). The migrations are correct — the downgrade-then-`upgrade head` round-trip executes `0009`/`0010` and succeeds; only the trailing `"0008" in stdout` assertion is stale. **This contradicts the stated "163 tests green / suite green" precondition** and must be corrected before merge. No security impact. | OPEN — fix stale fixtures |

No Medium, High, or Critical findings.

---

## Verification of Architectural Decisions

- **D1 — Judge through F-006 provider layer, preset authoritative.** `invoker.run_judge` resolves the adapter via `JudgeRegistry.resolve(preset)` (only the two contract presets resolve; unknown → `None` → `unconfigured`), then invokes `provider_registry.get(provider).classify_structured(...)`. No raw SDK use, no `route_non_stream`, no `fallback_order` consultation. **Confirmed.**
- **D1 policy gate.** `_model_authorized` runs `evaluate_model_policies` on `get_tenant_session(tenant_id)` (RLS); a `ModelDeny` → terminal `classifier_unconfigured` + `policy_denied` billing event → regex fallback. Any infra exception in the policy read → `False` (fail-safe: judge not invoked on unverifiable policy state). **Confirmed.**
- **D2 — Egress monitor.** httpx `request` event-hook registered once each on the shared OpenAI client (`init_http_client`) and the dedicated Anthropic client (`ProviderRegistry.init`). Reads `current_egress_context` (extends Affu's `current_allowed_providers` with identity). Detect-and-audit only — `egress_request_hook` wraps its body in `try/except Exception` and only logs on error, so it can never raise into or block the outbound provider call. **Confirmed.**
- **D3 — Two reversible migrations + 4-site consistency.** `0009` adds `classifier_model_id`(NULL)/`audit_mode`(NOT NULL DEFAULT 'full') with enum + allow-list CHECKs; `down()` drops both. `0010` adds eight nullable columns + 5 value CHECKs and widens `ck_eal_event_type` via DROP+CREATE with static literals; `down()` narrows back to the exact `_THROUGH_F008` set, which byte-matches migration `0008`'s post-state. All columns nullable/additive → no pre-existing row is invalidated. The 8 F-007 columns appear consistently at all four sites: ORM model, `append()` constructor, `_row_to_hash_data`, and `CANONICAL_FIELDS`. **Confirmed complete — no missing site, no silent data-loss, no verify-chain mismatch.**
- **B2C inheritance (§6).** `resolve_inherited_config` resolves `model_id` and `audit_mode` independently by most-specific non-NULL; empty chain → `UNCONFIGURED`. Reads on a tenant session with a defense-in-depth `WHERE tenant_id = caller_tenant_id` on top of RLS. **Confirmed.**
- **RLS posture (§10, R13).** Config reads → `get_tenant_session` (sentinel_app/NOBYPASSRLS). Audit appends → `get_privileged_session` via `HookContext.emit` → `AuditLogRepository.append`, which `_assert_privileged_session()` (load-bearing `current_user != sentinel_app` + corroborating GUC). The egress hook's `emit_shadow_ai_outbound_event` builds a `HookContext` and uses the same privileged emit path. **Confirmed.**
- **Honest language.** ADR + new code use "high-coverage," "risk reduction," "audit-ready," "tamper-evident, not tamper-proof." Grep for over-claims ("blocks all", "100%", "guarantee", "compliant", "secure", "bulletproof") found only explicit honest-limitation statements ("never '100%'", "layered, not guaranteed", "reduce, but do not eliminate"). Vectors #13 (network bypass) and Bedrock-egress blind spot are documented, not hidden. **Confirmed.**

---

## Threat-Vector Confirmation (ADR-0010 §9 — all 13)

- **R9 / fail-OPEN (PRIMARY) — DEFEATED.** Traced `injection_detector._judge_verdict` + `invoker.run_judge` exhaustively. Every non-`JudgeRan` outcome AND `verdict.confidence < 0.5` → `_regex_verdict(regex_score, first_rule, threshold)`, which returns `block` (≥0.75) or `pass`, never "allow". The judge can only ever **raise** the final score via `final = max(regex_score, judge_score)`; it can never lower the regex verdict or skip blocking. Verified for: unconfigured (no preset / provider-unavailable), policy_denied, degraded (transport/auth/rate-limit/timeout/generic Exception), invocation_failed (`JudgeParseError` / `ProviderError(kind="parse")` / out-of-range score), low-confidence. `asyncio.CancelledError` (BaseException) is intentionally not swallowed.
- **R5/R6 — bypass DEFEATED.** Judge routes only through `classify_structured`. Anthropic forces tool-use (`tool_choice` pinned to `report_verdict`); a missing tool_use block → `ProviderError(kind="parse")` → invocation_failed → regex. OpenAI uses `response_format=json_schema strict`; non-200 → transient → degraded → regex; non-JSON content → parse → invocation_failed → regex. `verdict_from_dict` re-validates type and `[0,1]` bounds independently of the provider, so a malformed/out-of-range structured response cannot smuggle a score into the blend.
- **R7/R8 recursive injection — DEFEATED.** `prompts.JUDGE_SYSTEM_PROMPT` is a static module constant; no f-string/format/concatenation of request data; suspect text is a separate `role="user"` message. Regex pre-filter (`_should_run_judge`) runs before any judge call; obvious attacks (`regex_score >= judge_skip_score`, jailbreak-family rule ids) skip the judge entirely. `recursive_injection_attempt` is emitted only when the judge surface was reached AND `_matches_meta_attack` fires — observability without trusting the model.
- **R10 redaction — DEFEATED.** `prompt_injection_detected_ml` is content-free by construction in both `full` and `redacted`: scores, confidence, stable `judge_model`/`rule_matched` labels, `audit_mode` flag only. `rule_matched` is a stable `INJ-*` id sliced to 128 chars, never attacker text. `classifier_reason` is populated exclusively from hardcoded literals (`no_preset`, `model_not_authorized`, `provider_unavailable`, `invalid_structured_output`, `judge_call_failed`). The judge's free-text `verdict.reason` is sanitized in `verdict_from_dict` (charset-restricted, 200-char bound) AND is never referenced anywhere in `injection_detector.py` — it reaches no audit event and no log.
- **R12/R13 + isolation — chain poison DEFEATED.** No event bypasses `HookContext.emit` → privileged `AuditLogRepository.append`. Repository validates `event_type ∈ VALID_EVENT_TYPES` and per-variant `action_taken`. CHECK constraints (`ck_eal_judge_outcome`, `ck_eal_audit_mode`, score bounds, `ck_eal_event_type`) back-stop at the DB. The 4-site column wiring is complete — no unmapped column, no canonical-field omission. Config reads use the tenant (RLS) session; audit writes use the privileged session.
- **Egress (vectors #11/#12/#13) — confirmed.** `resolve_provider` exact-matches `api.openai.com`/`api.anthropic.com` and a tightened, fully-anchored Bedrock regex `^bedrock(-runtime)?\.[a-z]{2}-[a-z]+-\d+\.amazonaws\.com$`. Spoofs (`evil-bedrock...`, `...amazonaws.com.evil.com`) fail the `^...$` anchors. Disallowed provider → event; allowed provider / untracked host → silent. The hook reads only `request.url.host`/`.path` (no query/fragment/userinfo) and `emit_shadow_ai_outbound_event` re-sanitizes via `_strip_unsafe_url_components` + `^[^?#@\s]+$`. The hook makes no network call → no SSRF. #13 (network bypass) and Bedrock/aioboto3 are documented honest gaps.
- **Migrations — reversible, no legitimate-row rejection.** Confirmed (see D3 above). `0010` down-revision chains `0009`→`0008`; the `_THROUGH_F008` literal matches `0008`'s post-state exactly.
- **SQL injection — none.** `cli.py` `set`/`unset` use parameterized `text()` with bound params (`:t`, `:model`, `:mode`, …) and argparse `choices=` restricting `--model`/`--audit-mode`. Migrations widen the CHECK with static literals only.

---

## Escalation Statement

- **CRITICAL findings: 0**
- **HIGH findings: 0**

No findings require human escalation. Per the F-007 gate rule (any High/Critical → BLOCK → human escalation, no retry override), this audit does **not** trigger escalation. One Low finding (F-007-04, stale migration test fixtures) is OPEN and must be fixed to restore a fully green suite and honor the merge precondition, but it carries no security impact. The fail-safe posture, structured-output contract, redaction guarantee, hash-chain wiring, and RLS session split are sound. This pass reports no High/Critical findings.
