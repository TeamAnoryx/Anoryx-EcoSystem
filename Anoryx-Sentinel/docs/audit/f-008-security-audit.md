# F-008 Security Audit — Policy Intake & Enforcement

**Branch:** `task/F-008-policy-engine` | **HEAD commit:** `17d185ee16b04df04dd014cb342cb4058c658689` | **Date:** 2026-06-17 | **Auditor:** security-auditor (Opus, independent red-team) | **Scope:** F-008 (Policy Intake & Enforcement) — `src/policy/*`, F-006 integration (`src/gateway/router/selection.py`, `src/gateway/routes/chat_completions.py`), `src/persistence/repositories/policy_repository.py`, migrations 0004/0008, and the threat-model/signature test suites.

> Persisted compliance artifact. This is the verbatim final report of the independent security-auditor re-run mandated as STEP 10 / Condition 1 of the F-008 review. Re-run on a later commit if the policy code changes.

## Executive Verdict: **PASS**

No High or Critical findings in this pass. The prior CRITICAL (signature covered only the 8 scope claims, leaving enforcement fields tamperable) is confirmed remediated by the full-record `policy_hash` content binding (`crypto.policy_content_hash`), independently reproduced under direct probing. Tooling and runtime evidence:
- **Semgrep** (`p/python`, `p/security-audit`, `p/secrets`, `--severity=ERROR`): 101 rules across 29 files, **0 findings, 0 errors**; re-run on the 5 core files (`crypto.py`, `intake.py`, `enforcement.py`, `cli.py`, `schema_validator.py`) also 0/0.
- **Tests:** 80/80 pass (`tests/policy/*` 73 + `tests/gateway/router/test_policy_enforcement.py` including threat #14). The 16-vector adversarial suite + the new accept-path atomicity test are green.
- **Manual exploit probing:** algorithm confusion, signature edge cases, content-hash tamper/downgrade, wildcard-tenant widening, deny precedence, specificity, and budget n-scaling all fail closed (evidence below).

## Findings

| ID | Severity | file:line | Issue | Status |
|----|----------|-----------|-------|--------|
| F-008-A1 | INFO | `src/policy/intake.py:184-185` | Scope-mismatch path logs `signature_scope`/`body_scope` (disputed tenant/team/project/agent UUIDs) to structured logs keyed by `request_id`. These are internal stable IDs, not PII or secrets, and Decision B explicitly authorizes routing raw disputed IDs to structured logs (never to the hash chain). No signature bytes, key material, payload, or message content is logged anywhere in the module. | accepted-risk (by design, Decision B) |
| F-008-A2 | LOW | `pyproject.toml:26` | `python-jose[cryptography]>=3.3,<4` is a declared runtime dependency with a CVE history (alg-confusion CVE-2024-33663, DoS CVE-2024-33664). Verified **not imported anywhere in `src/`** — appears only in egg-info packaging metadata; F-008 crypto uses `cryptography` directly. Pre-existing and entirely outside the F-008 diff. | open (out-of-scope, broader-codebase supply-chain note) |
| F-008-A3 | INFO | `docs/adr/0009-policy-intake-enforcement.md` §12.1 | Canonicalization is `json.dumps(sort_keys, compact, utf-8)`, not JCS RFC 8785. Non-exploitable within the shipped Python signer/verifier pair (CLI signs and intake verifies with the identical function — byte-for-byte match, confirmed by probe C5). A cross-language signer mismatch fails **closed** (every policy rejected on `content_hash`). Documented coupling constraint, not a bug. | accepted-risk (documented, future Delta owns JCS migration) |
| F-008-A4 | INFO | `src/policy/enforcement.py:177-207` | `budget_period_used` casts `event_timestamp` (String(64)) to timestamptz in SQL; a malformed/naive value would misbucket. The audit emitter is the sole writer and always emits canonical RFC3339-UTC ('Z'). No attacker write path to this column (audit rows are append-only via the privileged chain). | accepted-risk (sole-writer invariant) |

No CRITICAL, HIGH, or MED findings.

## Verification of Architectural Decisions

### Decision A — Wildcard convention (all-zero UUID for team/project sub-tenant; `tenant_id` wildcard PROHIBITED)
**Holds.** The wildcard-tenant gate (`intake.py:155`) is evaluated on the **verified claims** (authoritative), before scope resolution. A signed wildcard `tenant_id` is hard-rejected as `wildcard_tenant` with SYSTEM_TENANT_ID attribution. At enforcement, `model_matches_scope` requires `view.tenant_id == scope.tenant_id` exactly — tenant is never wildcard-matchable, so even a hypothetically-persisted wildcard tenant could not widen cross-tenant.
- Tests: `test_wildcard_tenant_id_rejected` (both `test_threat_model.py` and `test_intake_signature.py`).
- Probes: **D1** legal sub-tenant wildcards (team/project = zero-UUID, agent = `all-agents`) round-trip cleanly; **D2** body-tenant→wildcard after signing is caught as `tenant_id` scope mismatch (never reaches the claims-based wildcard gate); **D3** a directly-signed wildcard tenant is caught by step-4; **B1** a model policy signed for tenant B cannot match a tenant-A request (`model_matches_scope == False`).

### Decision B — Audit attribution 3-case (schema/signature-fail → system tenant; scope-mismatch w/ valid sig → signature-resolved tenant; raw disputed IDs NEVER hash-chained)
**Holds.** `_audit_reject` writes `system_scope()` for schema/signature/claims-incomplete/wildcard-tenant rejections, and the **signature-resolved** `resolved` scope for body-disagreement scope mismatches and replays. Raw disputed body IDs go only to structured logs (`intake.py:180-186`), never into `build_policy_event`.
- Tests: `test_forged_signature_rejected` (asserts `tenant_id == SYSTEM_TENANT_ID`), `test_cross_tenant_scope_widening_rejected` (asserts `event.tenant_id == signed_tenant`, the signature tenant, not the body), `test_wildcard_tenant_id_rejected` / `test_additional_properties_poisoning_rejected` (SYSTEM_TENANT_ID).
- Confirmed `build_policy_event` only ever receives `scope` from `system_scope()` or signature-`resolved` — the untrusted `record[...]` body IDs are never an argument to the chained event builder.

### Decision C — Signature covers the FULL record via `policy_hash` (prior CRITICAL)
**Holds — prior CRITICAL is genuinely remediated.**
- **(i) Non-scope enforcement-field tamper rejected:** `policy_content_hash` (SHA-256 over canonical record minus `signature`) is bound into the signed claims (`CONTENT_HASH_CLAIM`); `intake.py:194` rejects any body whose recomputed hash ≠ the signed claim. Tests `test_enforcement_field_tamper_rejected` (emptying `denied_model_ids` — the exact prior CRITICAL repro) and `test_budget_ceiling_tamper_rejected` (inflating `max_tokens_per_period`) both assert `dimension == "content_hash"` and non-persistence. Probe **C3** independently confirms hash mismatch on enforcement-field tamper.
- **(ii) Downgrade (strip `policy_hash` claim) rejected:** `intake.py:138-141` rejects if `CONTENT_HASH_CLAIM not in claims`. Probe **C4** confirms a validly-re-signed payload lacking `policy_hash` is rejected at step 3b.
- **(iii) Canonicalization deterministic across signer (cli.py) and verifier (intake.py):** both call the identical `crypto.policy_content_hash` / `canonical_claims`. Probe **C5** confirms `hash(record) == hash(signed_record)` (signature field excluded both sides). Probe **C2** confirms `policy_hash` is not itself a body field (no circular-hash defect).

## 16-Vector Coverage Confirmation

All 16 vectors are exercised and prove the attack fails (typed rejection + correct audit event + no state poisoning). Intake #1–#12 and #16 in `tests/policy/test_threat_model.py`; enforcement #13 (deny precedence) and #15 (period boundary) in the same file; **#14 (budget exhaustion mid-stream)** in `tests/gateway/router/test_policy_enforcement.py::test_budget_exhaustion_mid_stream_terminates` (yields `policy_blocked` frame, closes WITHOUT `[DONE]`).

Independent probing reproduced the key crypto/enforcement vectors directly: **A1/A2/A5** alg `none`/`HS256`/missing all rejected *before* any key use (alg pinned first); **A3/A4** 63-/65-byte sigs rejected pre-curve as "must be 64 raw bytes"; **A6** degenerate `(r=0,s=0)` raw sig rejected as `InvalidSignature` (no crash); **B2** deny precedence (`model_denied`) over a same-scope allow; **B3** most-specific allow wins; **B4** budget scope=agent rejects mismatched agent; **B5** strict `>` budget boundary (used+est==max is OK, >max is Exceeded); **E1–E3** n-scaling in `_prompt_token_proxy` coerces `n∈{0,None,-5}` to 1 (no zero/negative under-count bypass).

**Additional fail-closed posture verified:** missing verifying key → every intake `RejectedSignature` (`test_no_verifying_key_fail_closed`); set-but-unreadable key → `PolicyKeyError` at startup (load-once, no TOCTOU); accept-path audit-append failure rolls the policy INSERT back atomically and **propagates** (not swallowed) — `test_audit_append_failure_on_accept_rolls_back_policy` asserts `RuntimeError` raised + `max_version is None`. Reject-path audit runs best-effort in a nested SAVEPOINT so a transient failure cannot poison the caller's transaction while preserving the rejection outcome. Replay/rollback defended at intake (`get_max_version`, strict `<=`) AND by the DB `BEFORE INSERT` monotonicity trigger (migration 0004). No deserialization/`eval`/`exec`/`subprocess`/`yaml.load`/`pickle` in the policy module; all SQL is ORM-parameterized or static `text()` constants (no event-data interpolation); migration 0008 only widens a CHECK constraint with static literals.

## Escalation Statement

**CRITICAL count: 0. HIGH count: 0.** No finding escalates to human per policy. The single prior CRITICAL is confirmed already-remediated-in-`17d185e` (full-record `policy_hash` binding) and re-verified by both the shipped test vectors and independent adversarial probing. One LOW (`python-jose` unused dependency, F-008-A2) is a pre-existing broader-codebase supply-chain note outside the F-008 change set and does not block this feature.

This code is not called "secure." There are **no High/Critical findings in this pass**, the fail-closed posture is intact across every probed boundary, and the three architectural decisions are enforced in code — not merely asserted.
