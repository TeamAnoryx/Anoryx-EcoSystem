# O-004 Policy Distribution Engine — Independent Security Audit

- **Auditor role:** Independent red-team security auditor (did NOT write this code).
- **Commit:** `aabd70b` on `task/O-004-distribution`
- **Scope:** 22 files; `git diff origin/main...HEAD`
- **ADR:** `Anoryx-AI-Orchestrator/docs/adr/0004-policy-distribution-engine.md`
- **Risk tier:** HIGH (policies flow into Sentinel's enforcement path) — audit depth doubled.
- **Date:** 2026-06-30

## Top line

**No High or Critical findings in this pass.** The non-stubbed allow/deny e2e was re-run independently on a fresh Postgres and passes. Engine liveness (not fail-open), RLS cross-tenant isolation, audit append-only/hash-chain, bounded retries, fail-closed auth, and the locked `policy_type` closed set were all independently verified. Findings are LOW/INFO only, all within explicitly documented O-006/O-008 deferrals.

> Note: a subsequent independent code review additionally flagged a HIGH contract-conformance defect — `distribution_id` was emitted as a 32-char `uuid4().hex` instead of the RFC-4122 `format: uuid` the contract mandates. That is a wire-format defect, not a security finding, and was fixed (`str(uuid.uuid4())`) before merge; it does not change any verdict in this report.

---

## Part 1 — Independent e2e re-run (the gate)

**Environment (isolated):** `postgres:16-alpine` container `anoryx_o004_audit` on a verified-free port (the task-suggested 5544 was occupied by a parallel session's Postgres; recreated on a free port — constraint honored: distinct name + distinct, non-colliding port). Two DBs: `orchestrator_ci` + `sentinel_ci`. Installed `Anoryx-AI-Orchestrator[dev]` + `Anoryx-Sentinel` runtime (Sentinel `[dev]` is uninstallable on Windows: `semgrep` refuses to build — see INFO-3).

**Targeted distribution suite** (`tests/integration/test_distribution_e2e.py tests/integration/test_distribution_chain.py tests/unit/test_distribution_*.py`):

```
32 passed in 66.47s
```

All 4 e2e cases (allow→enforce-allow+deny, deny→enforce-deny, HTTP submit→202→BackgroundTask→distribute→enforce, forged-signature→failed) + the chain tamper-evidence test + 27 unit tests passed. **0 skips** in the DB-backed set (the Sentinel DB was reachable, so nothing degraded to skip).

**Whole suite** (`pytest tests -q`):

```
108 passed, 2 skipped in 62.34s
```

The 2 skips are the pre-existing win32 ingest skips (expected). No regression.

### Non-stubbed confirmation — PASS

The only faking anywhere is the pure `_aggregate_state` unit test. The distribution call is the real engine `drive_distribution` → `_distribute_to_target` → `httpx.AsyncClient().post(url, json=signed_record)` to a **real ephemeral loopback uvicorn server** (`host=127.0.0.1, port=0`, real socket). That server runs the test shim, whose single route calls Sentinel's **real** `intake_policy(raw_body)` with `session=None` — intake opens its own privileged Sentinel session and runs the real ES256 verify → 8-claim scope cross-check → full-record content-hash check → replay defense → persist+audit. The shim re-implements **no** verification. The allow/deny assertion calls Sentinel's **real** `evaluate_model_policies` against the persisted policy via a dedicated `sentinel_app` (NOBYPASSRLS) engine with the tenant GUC set.

### Verify-unchanged + forged rejection — PASS

The allow test asserts `persisted_sig == signed["signature"]`: the bytes Sentinel persisted are byte-identical to what was signed → the ES256 JWS verifies unchanged. The forged test flips one base64url char in the JWS mac; Sentinel returns `RejectedSignature` → shim maps to a permanent 403 → engine records target+parent `failed` with `attempt_count == 1` (no retry storm) and the forged policy is never persisted.

---

## Part 2 — Threat model T1–T8

| # | Threat | Verdict | Evidence |
|---|--------|---------|----------|
| **T1** | Forged-signature pass-through | **PASS** | Orchestrator never trusts the signature; forwards byte-identical. Sentinel `intake_policy` does ES256 verify + scope + content-hash. Forged → permanent 403 → target `failed`, not persisted. Empirically reproduced. |
| **T2** | Stale/rollback replay | **PASS** | Replay defense is Sentinel's (`version <= current_max` → `RejectedReplay` → shim 409, permanent). Orchestrator forwards; every submission (incl. rejected) is recorded in the tamper-evident chain. |
| **T3** | Spoofed-Sentinel target | **PASS** | URLs resolve **only** from `ORCH_DISTRIBUTION_TARGETS` config: `base_url = settings.targets.get(sentinel_id)`. Request `targets[].sentinel_id` only *filters*; a `sentinel_id` not in the config map → `unknown_target` failure, **no HTTP call**. No attacker-controlled URL ever reaches httpx. `sentinel_id` is regex-bounded. No SSRF. mTLS peer-auth of Sentinel deferred to O-008 (documented). |
| **T4** | Partial-distribution illusion | **PASS** | Per-target independent state; `_aggregate_state` never returns `distributed` unless **all** targets distributed. Mixed/pending → `partial`/`failed`. GET surfaces each target's state. |
| **T5** | Retry amplification (DoS) | **PASS** | Bounded in-process loop with exponential backoff. Permanent 4xx (non-429) breaks immediately (no retry). `max_attempts` floor `>= 1` (config + DB CHECK). Forged test confirmed `attempt_count==1` on a 403. |
| **T6** | Audit tampering | **PASS** | `distribution_audit_log` BEFORE UPDATE/DELETE deny-triggers block even the **superuser** owner. App role has SELECT-only grant. `validate_distribution_chain` recomputes the SHA-256 chain and is **fail-loud** under a non-BYPASSRLS role. Tamper-then-restore test passes. Genesis domain-separated from the ingest chain. |
| **T7** | Cross-tenant leakage | **PASS (DB-level)** | `orchestrator_app` is `rolbypassrls=False, rolsuper=False`. No GUC → **0** rows (fail-closed). GUC=tenant-A → sees only A's rows, **0** of tenant-B's. `tenant_id` is server-resolved from `policy.tenant_id`, never a header. See LOW-1 re: the coarse-grained GET (documented O-006). |
| **T8** | NUL-byte poison | **PASS** | `_contains_nul` recursively rejects `\x00` anywhere in the policy → 422 before persist. Unit-tested. Deterministic terminal disposition, no 503 retry storm. |

### Engine inert / fail-open (the recurring trap) — PASS
- No `session.begin()` wraps an autobegun tenant session anywhere. Tenant writes use `get_tenant_session(...)` with **no** nested begin. The only `.begin()` calls are on the **privileged** session for audit, which does not autobegin — correct.
- Connectivity catch is narrow: `_DB_CONNECTIVITY_ERRORS = (OperationalError, InterfaceError, TimeoutError, OSError)`, caught only around the per-target call. `InvalidRequestError`/`ProgrammingError` (double-begin/logic defects) are deliberately outside this family → they raise out of the BackgroundTask rather than failing open. No broad `except Exception` / bare `except` anywhere in `distribution/` (grep-confirmed).
- **Liveness proof:** the allow/deny e2e actually persisted + enforced the policy → the engine is demonstrably not inert on a real DB.

### policy_type enum widening (CRIT-2 class) — PASS
- Migration CHECK `ck_pd_policy_type` lists exactly the **six** locked values, membership-only.
- No file in the diff touches `_VALID_POLICY_TYPES` or `policy.schema.json` (**zero** `Anoryx-Sentinel/` files changed). The six migration values match the locked schema's six `const`s exactly.

### Auth bypass — PASS
- **Inbound fail-closed:** missing/non-`Bearer `/empty → 401; `service_token is None` → can never match → 401; mismatch → 403; compare is `hmac.compare_digest`. Unit-tested.
- **Outbound no-token:** `sentinel_admin_token is None` → target `failed` with `no_admin_token` — never skipped or treated as success.

### Secret / PII leakage — PASS
- No `print()` in any new src file. Engine logs only `distribution_id`, `sentinel_id`, and a short `last_error` code. The admin token appears only in the outbound `Authorization` header, never logged. `signed_record`/`signature`/policy field values are never logged.
- No SQL injection: all runtime SQL is parameterized; the GUC set is parameterized. String-built SQL is confined to the migration (fixed constants) and the test-only SCRAM provisioner.

### Honesty boundaries — PRESENT (verbatim)
Pass-through signing (Fork A), mTLS→O-008 (Fork B), distributed≠applied (Fork E), partial surfaced (Fork C), and "the shipped Sentinel-side HTTP policy-intake route does not exist → shim is test-only" (Fork F) are all present in the ADR.

---

## Findings

| Sev | File | Issue | Exploit path | Fix |
|-----|------|-------|--------------|-----|
| **LOW-1** | `distribution/router.py` GET handler | GET derives `tenant_id` from the row itself, then re-reads under that tenant's session. The "RLS-confirmed" docstring overstates isolation: it does not bind the read to a caller-tenant. Any holder of the single shared service token can read any distribution's metadata (policy_id, sentinel_ids, states, timestamps). | A second trusted peer that later receives the coarse-grained bearer could enumerate another tenant's distribution metadata. No policy content or signature is in the response body. Today the only authenticated caller is the trusted submitter, so there is no per-tenant credential to leak across. | Bind the GET to a caller-tenant claim when per-tenant authz (O-006) lands; meanwhile soften the docstring so it does not imply per-caller isolation. Explicitly deferred to O-006. |
| **LOW-2** | `distribution/router.py` inbound | `policy.tenant_id` is accepted from a single coarse-grained service-token holder. | A service-token holder can store a distribution row under any `tenant_id`. Downstream-mitigated: Sentinel re-verifies ES256 + scope, so a `tenant_id` not matching the signed claims is rejected (`RejectedScopeMismatch`); a non-Delta attacker cannot forge a valid signature. The trusted submitter is authorized for all tenants by design. | Per-tenant inbound authz (O-006). Acceptable for the documented interim coarse-grained model. |
| **INFO-1** | ADR §3.2.4 vs `engine.py` | ADR said "schedule a retry after exponential backoff" (implying re-queued tasks); implementation uses a bounded in-process loop (safer). | None. | Doc/impl wording aligned (done). |
| **INFO-2** | `0002_…py`, `distribution_audit_log.py` comments | Comments said `tenant_id` is "NULL — chain is global", but the append path always writes the real `tenant_id` (so RLS SELECT scopes audit rows per-tenant; the hash binds it consistently). | None. | Comment corrected (done). |
| **INFO-3** | env/platform | Semgrep cannot run on this Windows host — upstream `semgrep` refuses to install. | None — auditing constraint, not a code defect. | Compensated by manual SAST-style review of all 22 changed files; CI runs the Linux lane. |

No Medium, High, or Critical security findings.

---

## Verdict

**AUDIT: CLEAN**

No High/Critical findings. The change implements the O-001 distribution seam with genuinely non-stubbed real-crypto verification + real enforcement, structurally-enforced RLS isolation, superuser-proof append-only audit with a fail-loud hash chain, bounded non-amplifying retries, fail-closed inbound/outbound auth, the locked six-value `policy_type` closed set untouched, and zero secret/PII logging. The residual items are LOW/INFO and fall squarely inside the explicitly documented O-006 (per-tenant authz) and O-008 (mTLS) deferrals.
