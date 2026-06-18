# F-009 Extended Adversarial Security Audit — Anoryx Sentinel

**Scope C** | Branch `task/F-009-observability-native` | Governing doc: `docs/adr/0011-rate-limiting-observability.md` | Contracts: `contracts/events.schema.json`, `contracts/openapi.yaml`

> Audit performed by the `security-auditor` agent (Opus), extended adversarial. This document records the original verdict **and** the resolution of all conditions (see the "Conditions Resolution" addendum at the end).

## Executive Verdict (initial): PASS-WITH-CONDITIONS

No High or Critical findings. No rate-limit bypass, no information disclosure, no cardinality DoS, no span/Redis-injection leakage was exploited. Semgrep (`p/python`, `p/security-audit`, `p/secrets`) returned **0 findings, 0 scan errors** across all changed Python files (full-severity sweep also 0).

Two Medium defects raised as merge conditions: (M1) the documented "unauthenticated Prometheus scrape" `/metrics` endpoint is **unreachable** (HTTP 400 — not exempted from tenant-header/auth gates; R5 falsified); (M2) an **audit-emit span double-execution** defect in `middleware/audit.py` (the STEP-8 HIGH-1 bug class; the `check_ran` guard was not applied to the three `audit.py` emitters).

## Findings Table

| # | Severity | Location | Issue | Exploit / Failure Scenario | Recommended Fix |
|---|----------|----------|-------|----------------------------|-----------------|
| M1 | Medium | `src/gateway/main.py:250-253`; `middleware/auth.py:63`; `middleware/tenant_context.py:50` | `/metrics` documented (ADR §5/R5, openapi `security: []`) as unauthenticated, but `metrics_path` is NOT in `_AUTH_EXEMPT_PATHS` of TenantContext/Auth middleware. | `GET /metrics` with no headers returns **HTTP 400 `missing_required_header`**; Prometheus cannot scrape. R5 guarantee false; primary observability surface non-functional (over-gated, opposite of disclosure). | Add `settings.metrics_path` to `_AUTH_EXEMPT_PATHS` in auth.py + tenant_context.py (+ RequestValidation if it path-gates). Test: no-header `GET /metrics` → 200 + CONTENT_TYPE_LATEST. |
| M2 | Medium | `middleware/audit.py:233-241, 337-345, 410-419` | Audit-emit span wrapper re-executes `_do_append()` on any exception from inside the span (no `check_ran` guard, unlike rate_limit + selection). | With `enable_otel=True`, if `_do_append()` raises mid-transaction the outer `except` runs it a SECOND time (duplicate/inconsistent audit rows, or masked transient failure on the terminal record). Reached on every 4xx/5xx via `emit_terminal_record`. Weakens audit-chain integrity. | Apply the `check_ran` guard pattern to all three emitters; re-run only if span setup failed before append ran. Test: failing `append` under a recording span → append called exactly once. |
| L1 | Low | `redis_client.py:130-174`; `rate_limit.py:566-622` | `rate_limit_redis_error` fully declared (schema, model, migration 0011, contract) but **never emitted**. ADR §7/D6 specifies it per distinct Redis error on the admission path. | No security impact; promised per-error forensic trail does not exist. | Emit `rate_limit_redis_error` per distinct Redis error on the admission path, or update ADR + remove the variant. |
| L2 | Low | `pyproject.toml:29-30` | `opentelemetry-instrumentation-fastapi/httpx >=0.45b0` have NO upper bound (unlike api/sdk `<2`, prometheus `<1`). | Supply-chain drift: a future/compromised major could be pulled unreviewed. | Add upper bounds consistent with the api/sdk pins. |
| L3 | Low | `rate_limit.py:397` (`_span.record_exception`) | Span records the propagating exception. Today only benign `GatewayError` propagates and spans are NOT exported (F-009 no-op sink). | Latent: once F-010 wires OTLP export, a future refactor letting `RedisConnectionError` (message may contain `redis://user:pass@host`) reach `record_exception` would export the connection string. | Restrict span exception recording to class/module (mirror the `str(exc)`-never rule), or strip messages in a SpanProcessor when F-010 adds an exporter. |
| L4 | Low | `rate_limit.py:266-289` (`_get_team_rpm_limit`) | Team-tier limit cache is populated ONLY via `_set_team_rpm_limit()` (tests); production has no DB read of `tenant_routing_policy.team_rpm_limit`. | Team tier (D3) inert in production regardless of DB config — a configured per-team cap is silently not enforced. (NB: contradicts Affu's locked decision that `check_rate_limit` reads `team_rpm_limit` from the resolved routing policy → treated as must-fix.) | Wire the runtime DB read of `team_rpm_limit` via the tenant routing policy repo (tenant session, TTL cache). |

## Per-Attack-Vector Results

1. **Rate-limit bypass under Redis outage — NOT EXPLOITED.** ZADD-inside-EXEC + compensating ZREM (all admitted tiers compensated on reject); legacy single-lock path; RPM/burst boundary equivalence hand-traced; γ fallback sets degraded True only on the hot path (health loop is the sole clearer), continues enforcing, never fails open-without-fallback nor fully closed; STEP-8 HIGH-1 `check_ran` fix verified (check runs exactly once, rejection not retried). Tests V1/V4/V7/V8.
2. **/metrics information disclosure — NOT EXPLOITED (disclosure); R5 design claim FALSIFIED (M1).** Output is bounded metric families over a dedicated registry; every label is a server-side constant/enum (provider literal, status_class from ERROR_TABLE, route literal, outcome 5-slug enum); no prompt/key/PII/conn-string can enter. Separately over-gated (400 to anon scrape) — M1.
3. **Cardinality DoS — NOT EXPLOITED.** No label derives from attacker input; per-tenant gated (default False) + server-resolved tenant_id only; `record_rate_limit_decision` applies no tenant label. V14: constant series 1→1000 tenants, render <2s.
4. **OTel span data leakage — NOT EXPLOITED.** Attributes = tier/tenant_id(UUID)/path/result/request_id/provider only; no virtual_key_id plaintext (SHA-256 helper available); no exporter in F-009; enable_otel=False strict no-op. Forward-looking L3.
5. **Redis injection / SSRF — NOT EXPLOITED.** redis_url env-only (never per-request); keys from server-resolved UUIDs/slugs, namespaced; RESP bulk strings (no protocol injection); errors carry class[:64]/module[:128] only, never str(exc). V17.
6. **Audit integrity — HOLDS** (+ dead variant L1 + span defect M2). System events use WILDCARD_UUID + agent_id='rate-limiter'; in-request events use real IDs; clients never reach the privileged emitter (no forgery path); 3 variants stay action_taken='logged', no new column; 4-site consistency verified; migration 0011 reversible.
7. **Honest language — PASS.** "detect-and-audit," "risk reduction," "client-side cost estimate," explicit deferrals; no "blocks all"/"100%"/"compliant".

## Residual / Honest Limitations
- Per-worker γ duplication (degraded/recovered may emit up to N times per transition) — accepted, ADR §3.
- Redis-down emit is best-effort (structlog WARNING + future OTel span are the durable signals).
- No live-Redis test executed in this audit pass (reasoned via mocked threat-model suite + code reading; `test_redis_integration.py` requires a live instance).
- Span export deferred to F-010 (L3 latent until then).
- The auditor does not certify the code as "secure"; no High/Critical in this pass.

**F-009 SECURITY VERDICT (initial): PASS-WITH-CONDITIONS — Critical: 0, High: 0, Med: 2, Low: 4**

---

## Conditions Resolution (post-audit)

All 6 findings (M1, M2, L1–L4) were remediated in the STEP-9 pass. L4 was treated as must-fix because it contradicted Affu's locked decision ("check_rate_limit reads team_rpm_limit from the resolved routing policy").

| # | Resolution | Verification |
|---|-----------|--------------|
| M1 | `metrics_path` added to the auth-exempt set in both `auth.py` and `tenant_context.py` via a settings-reading helper (`_get_auth_exempt_paths()`), so a custom `METRICS_PATH` is honoured. | Test: anonymous `GET /metrics` → 200 + `text/plain` exposition; `/v1/*` still require auth; `/health` still exempt. |
| M2 | `check_ran`/`_append_ran` guard applied to all three audit emitters (`emit_terminal_record`, `emit_routing_decision`, `emit_rate_limit_event`); re-run only when span SETUP failed before append ran. | Test: failing `append` under a recording span → `append` called exactly once for each emitter. |
| L1 | `rate_limit_redis_error` now emitted on the admission path, debounced **per distinct error class per outage**, carrying `redis_error_class` + `redis_error_module` (never `str(exc)`); reset on recovery. | Test: 2 distinct error classes → 2 `rate_limit_redis_error` + 1 `rate_limit_degraded`; same class twice → 1; recovery resets debounce. |
| L2 | Added `<1` upper bound to `opentelemetry-instrumentation-fastapi` and `-httpx` in `pyproject.toml`. | Imports verified under the pinned range. |
| L3 | Span records `error.type` + `error.module` + `set_status(ERROR)` instead of `record_exception(exc)` — the exception message (which may contain `redis://user:pass@host`) is never captured on a span. | Test: Redis-error span carries only the class name, not the connection string. |
| L4 | `_get_team_rpm_limit` now reads `tenant_routing_policy.team_rpm_limit` at runtime via the tenant routing policy repo on a tenant session (RLS), mirroring F-007 `get_classifier_config`; cache-first, DB on miss, any read error → `None` (team tier no-op, request proceeds). | Test: DB value enforced; `None` → no-op; repo error → no-op + no raise; result cached. |

**Re-verification:** +22 remediation tests; full gateway suite **296 passed, 0 regressions**; ruff + black clean. Cross-area full-suite + coverage + alembic round-trip + semgrep + live-Redis integration are run at STEP 10.

**F-009 SECURITY VERDICT (final, conditions resolved): PASS — Critical: 0, High: 0, Med: 0 open (2 resolved), Low: 0 open (4 resolved).**
