# ADR-0011 — Redis-Backed Rate Limiting & Observability Primitives (F-009)

- **Status:** Proposed
- **Date:** 2026-06-18
- **Deciders:** gateway-core / platform-infra (owner / implementer), api-architect (contract / `events.schema.json` + `contracts/ids.md`), security-auditor (extended-adversarial gate), Affu (solo founder & product owner — approved the γ fallback, γ cardinality, the team-tier opt-in refinement, and the Option-3 system-ID convention during planning; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Extends ADR-0004 (persistence / hash-chain audit), ADR-0005 (tenant isolation / RLS Option α — audit writes privileged), ADR-0006 (gateway pipeline — F-009 **swaps the rate-limit storage backend, not the pipeline placement**: rate limiting stays at step 6, called from `routes/chat_completions.py:257`), ADR-0007 (orchestration hooks — unchanged), ADR-0008 (F-006 router — unchanged), ADR-0009 (F-008 policy intake — unchanged; F-009 **reuses the `WILDCARD_UUID` reserved-ID convention** from §4/§7 for a third documented purpose), ADR-0010 (F-007 classifier — unchanged; F-009 only **observes** judge/shadow-AI emit sites with counters). Governed by `contracts/events.schema.json`. The contracts **win over this ADR on any conflict**.
- **Feature:** F-009 — replace the per-worker in-process rate limiter with a Redis-backed distributed limiter (failure mode γ), and add Sentinel's first observability primitives (Prometheus metrics + OpenTelemetry tracing) ahead of F-010 deployment.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

The rate limiter (`src/gateway/middleware/rate_limit.py`) is **in-process only**.
`check_rate_limit(virtual_key_id, tenant_id, is_stream) -> (limit, remaining,
reset_epoch)` keeps dual-scope sliding windows (`_key_windows`, `_tenant_windows`)
as `deque[float]` under a single `asyncio.Lock`, plus a per-tenant concurrent-stream
counter. The F-004 **MED-1 TOCTOU fix** makes admission atomic: the check **and** the
counter increment happen under the same lock, so concurrent callers cannot both pass
before either has incremented. The module documents an honest Phase-0 limitation: with
N workers the effective global limit is N × RPM and the stream cap is per-worker. The
limiter is **called as a function** at ADR-0006 pipeline step 6 inside the route
handler — it is **not** an ASGI middleware, so its placement is a call-site, not a
middleware-stack position.

Sentinel has **no observability primitives today**: no `/metrics` endpoint, no
`src/gateway/observability/`, no Prometheus or OpenTelemetry wiring. `structlog`
(`gateway/logging.py`) is configured with `merge_contextvars` (a ready hook for
trace-id injection) and a secret-redaction processor. `pyproject.toml` already pins
`redis>=5.0,<6`, `opentelemetry-api>=1.24,<2`, and `opentelemetry-sdk>=1.24,<2`;
`prometheus-client` and `opentelemetry-instrumentation-fastapi` are **absent**. There
is no `docker-compose.yml`.

The single-table append-only `events_audit_log` (ADR-0004) carries the four stable
IDs + per-variant nullable columns + a SHA-256 hash chain. Migration `0010` (F-007) is
the current head; the `_set_event_type_check()` DROP+ADD helper is the established
pattern for widening `ck_eal_event_type` (introduced in `0008`). ADR-0009 §4 reserves
`WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"` with a **dual** documented
purpose: (a) the sub-tenant wildcard for model policies, and (b) the system-scoped
audit owner for pre-verification rejections (§7).

### 1.2 Decision (one paragraph)

We make Redis the **primary** rate-limit backend using **sorted-set sliding windows**
(`ZREMRANGEBYSCORE` + `ZADD` + `ZCARD` + `ZCOUNT` + `EXPIRE` in one `MULTI/EXEC`
pipeline = atomic admission, with a compensating `ZREM` on rejection — preserving the
F-004 MED-1 TOCTOU guarantee distributively), keyed per **virtual key**, per **tenant**,
and — new — per **team** (a third tier, opt-in per tenant via a new nullable
`tenant_routing_policy.team_rpm_limit` column; NULL ⇒ the team window is a no-op, so
default behavior is byte-identical to F-004). **Failure mode γ** is non-negotiable: on
`RedisConnectionError`/`TimeoutError` the limiter falls back to the **preserved**
in-process path (`_legacy_check_rate_limit`, the current logic verbatim), emits
`rate_limit_degraded`, and continues to enforce per-worker; a 5 s background health
loop pings Redis and, on recovery, resumes the Redis path and emits
`rate_limit_recovered`. We never fail-open without fallback and never fail-closed. We
add a **Prometheus** `/metrics` endpoint (unauthenticated, read-only, same process —
R5) with **tiered cardinality γ**: aggregate labels by default, per-tenant labels
gated behind `ENABLE_PER_TENANT_METRICS` (default `False`) with a documented linear
storage-cost warning. We add **OpenTelemetry** spans (W3C propagation, FastAPI + httpx
auto-instrumentation, manual spans at five boundaries, trace-id injected into
structlog) but wire **no export backend** (deferred to F-010); a span/export failure
never affects request success (R8). Persistence adds **one reversible migration**
(`0011`): widen `ck_eal_event_type` with **three** new variants (`rate_limit_degraded`,
`rate_limit_recovered`, `rate_limit_redis_error`) and add the `team_rpm_limit` column.
A `docker-compose.yml` adds a `redis:7-alpine` service; a Grafana dashboard JSON ships
under `deploy/`.

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-009) |
|---|---|
| ADR-0006 middleware order + rate-limit placement at step 6 (`chat_completions.py:257`) — R2 | `check_rate_limit()` internals: Redis primary + preserved legacy fallback; same signature/return |
| F-005 hook chain, F-006 router, F-007 classifier, F-008 intake logic — R2 | Observed read-only via Prometheus counters at existing emit sites (no semantic change) |
| F-004 MED-1 TOCTOU atomic-admission guarantee — R1 | Re-realized in Redis (ZADD-inside-EXEC + compensating ZREM) and retained on the legacy path |
| The in-process limiter logic | Preserved verbatim as `_legacy_check_rate_limit` (γ fallback), not deleted |
| `policy.schema.json` (LOCKED at F-008) | Untouched |
| Existing `events.schema.json` variants | THREE new variants ADDED (api-architect); 4-site wiring |
| Hash-chain algorithm + `events_audit_log` columns | No new event-table columns; the 3 variants use `action_taken='logged'` only |
| `WILDCARD_UUID` value + its two ADR-0009 purposes | A **third** documented purpose added (system-emitted events) |
| Default rate-limit behavior (key + tenant) | Identical when `team_rpm_limit IS NULL` (team tier is a no-op until configured) |

---

## 2. Decision D1: Redis sorted-set sliding window (atomic admission)

Each tier is a Redis sorted set whose **score is the admission timestamp in
milliseconds** (`int(time.time()*1000)` — wall-clock, comparable across workers; the
legacy fallback keeps `time.monotonic()`, which is correct only intra-process). Key
namespaces:

```
sentinel:rl:vk:{virtual_key_id}
sentinel:rl:team:{tenant_id}:{team_id}     # written only when team_rpm_limit IS NOT NULL
sentinel:rl:tenant:{tenant_id}
```

Admission for a tier is one `pipeline(transaction=True)` (`MULTI/EXEC`):

```
now_ms = int(time.time()*1000); cutoff = now_ms - 60000; member = f"{now_ms}:{uuid4().hex}"
ZREMRANGEBYSCORE  key  -inf  {cutoff}          # evict entries older than the 60 s window
ZADD              key  {now_ms}  {member}       # record this request
ZCARD             key                           # -> rpm_count (includes this request)
ZCOUNT            key  {now_ms-1000}  {now_ms}  # -> burst_count in the last 1 s
EXPIRE            key  61                        # idle keys self-expire (memory bound)
```

Because `ZADD` precedes `ZCARD` **inside the same `EXEC`**, there is no
read-check-then-write gap: Redis serializes the transaction, so no concurrent admission
sees an intermediate state. This is the distributed re-realization of the F-004 MED-1
guarantee (R1). If a tier is over `rpm_limit` (or `burst_count > burst`), the request is
rejected and a compensating `ZREM key {member}` immediately removes the just-added
member (globally unique → safe). **Burst** within the window is enforced by `ZCOUNT`
(O(log N)), mirroring the in-process `sum(... >= now-1s)` check.

**Concurrent-stream cap.** The per-tenant stream counter moves to an atomic Redis
`INCR`/`DECR` on `sentinel:rl:streams:{tenant_id}` with the same admission-time-increment
discipline (MED-1). On the legacy path the existing `_stream_counters` + `stream_slot()`
logic is used verbatim.

---

## 3. Decision D2: Failure mode γ — degraded fallback + health-loop recovery

A per-worker module flag `_redis_degraded` selects the path. It is mutated **only** by
the health loop (single writer; multi-reader hot path — safe under single-threaded
asyncio, no hot-path lock).

- **On `RedisConnectionError`/`TimeoutError` in the admission path:** set
  `_redis_degraded = True`, fall back to `_legacy_check_rate_limit` (in-process windows),
  and emit `rate_limit_degraded` **debounced** (once per outage transition) carrying the
  **failing request's real four IDs** and the Redis **error class** (`type(exc).__name__`),
  never the message. Enforcement continues per-worker during the outage.
- **Health loop** (`asyncio.Task`, 5 s interval, started/cancelled in `_lifespan`,
  stored on `app.state.redis_health_task`): pings Redis (2 s timeout). The flag is the
  edge-detector — `healthy→fail` sets `True` (emit `rate_limit_degraded` once if the
  transition was first observed by the loop); `fail→healthy` sets `False` and emits
  `rate_limit_recovered` once, then the Redis path resumes.
- **Honest limitation (documented):** each worker has its own flag and loop, so a
  degraded/recovered event may be emitted up to N times (worker count) per transition;
  downstream consumers must tolerate duplicates. If Redis itself is down, the
  `rate_limit_degraded` Redis-Streams emit also fails — the durable signals are then the
  structlog warning and the OTel span event. This is inherent (you cannot reliably
  report "Redis is down" to Redis) and is the reason the audit/Streams emit is
  best-effort while the structlog line is guaranteed.

γ is **non-negotiable** (R3): never fail-open without the in-process fallback, never
fail-closed (a Redis blip must not break Sentinel).

---

## 4. Decision D3: Three-tier rate limiting (key < team < tenant), team opt-in

Three independent sliding windows; **all must permit; the strictest governs**. Limits:
`virtual_key` and `tenant` use the existing `rate_limit_rpm`/`rate_limit_burst`; the
**team** tier reads `tenant_routing_policy.team_rpm_limit` (new nullable column).

- **Default = None ⇒ no-op.** When `team_rpm_limit IS NULL` the team window is neither
  written nor checked, so default behavior is byte-identical to F-004 (key + tenant).
  This follows the F-007 **config-gated-abstraction** pattern: the code path, the metric
  label, and the test ship now; activation is per-tenant. (Rationale: defaulting the
  team limit to `rate_limit_rpm` would make it a dead always-permit path identical to
  the tenant cap.)
- The `team_rpm_limit` lookup is cached per `(tenant_id, team_id)` with a short TTL to
  avoid a DB read per request; reads use a tenant session (RLS, F-003b).

### Tier semantics (canonical)

> **virtual key < team < tenant.** All three windows must permit the request; the
> strictest wins. The team tier is **opt-in per tenant** via
> `tenant_routing_policy.team_rpm_limit` (INTEGER, NULL = disabled). With no team limit
> configured, behavior equals F-004's key + tenant enforcement.

---

## 5. Decision D4: Prometheus metrics (`/metrics`) with tiered cardinality γ

`src/gateway/observability/metrics.py` defines the registry and the exposition route.
**Default metric set (no per-tenant labels):**

| Metric | Type | Labels |
|---|---|---|
| `sentinel_requests_total` | Counter | `provider`, `status_class` |
| `sentinel_request_duration_seconds` | Histogram | `route`, `provider` |
| `sentinel_rate_limit_decisions_total` | Counter | `outcome` ∈ {admitted, rate_limited_key, rate_limited_team, rate_limited_tenant, rate_limited_degraded} |
| `sentinel_pii_blocks_total` | Counter | — |
| `sentinel_policy_violations_total` | Counter | `policy_type` |
| `sentinel_audit_write_failures_total` | Counter | `component` (closes the F-008 follow-up debt) |
| `sentinel_judge_invocation_total` | Counter | `preset`, `outcome` |
| `sentinel_judge_latency_seconds` | Histogram | `preset` |
| `sentinel_shadow_ai_detected_outbound_total` | Counter | — |
| `sentinel_classifier_degraded_total` | Counter | — |
| `sentinel_redis_health` | Gauge | — (1 healthy / 0 degraded) |

All default label sets are bounded in the single digits and **do not grow with tenant
count**. Counters are incremented **alongside** existing emit sites (`pii_detector.py`,
`judge/invoker.py`, `shadow_ai_detector.py`, `egress_monitor.py`, the `context.py`
audit-failure path, `router/registry.py`, and the rate-limit decision points) — a pure
addition, no behavior change (R2).

**Per-tenant gate (γ).** When `ENABLE_PER_TENANT_METRICS=true`, a `tenant_id` label is
added to the tenant-scoped series only, using the **server-resolved** `tenant_id` from
`TenantContext` (never a client header — that would be an unbounded-cardinality vector).
A startup warning is logged. The config docstring states: *"this increases Prometheus
storage cost linearly with tenant count; enable only when operationally needed."*

**`/metrics` is unauthenticated and read-only (R5).** Prometheus scrapes it; corporate
networks firewall the endpoint. It MUST contain no secrets, virtual keys, prompt
content, or PII (R9) — proven empirically (vector #9). It is the **only** new HTTP
endpoint F-009 adds.

---

## 6. Decision D5: OpenTelemetry tracing (spans only; export deferred)

`src/gateway/observability/tracing.py` configures a `TracerProvider` with **no export
backend** (a no-op / console sink); F-010 wires OTLP. Auto-instrumentation:
`FastAPIInstrumentor().instrument_app(app)` and `HTTPXClientInstrumentor().instrument()`
are registered once in `create_app()` after all middleware is added (the instrumentor
sits **outside** the middleware stack — no order change, R2). Manual `INTERNAL` spans
(context managers inside existing function bodies, not new middleware) at five
boundaries: `rate_limit_check`, `policy_evaluation`, `judge_invocation`,
`provider_call`, `audit_emit`. The current span's trace-id is injected into structlog
via the existing `merge_contextvars` hook so every structured log line correlates to a
trace.

**Span hygiene (R8/R9):** spans carry `tier`/`result`/`tenant_id`(UUID)/`request_id`
only — **never** `virtual_key_id` in plaintext (it is an auth credential; use a SHA-256
prefix if correlation is needed). OTel instrumentation MUST NOT change request
semantics: an export or span failure leaves the request succeeding.

---

## 7. Decision D6: Event variants (3) + the system-ID convention

Three new variants, all `action_taken='logged'` (so `ck_eal_action_taken` is
**unchanged**), reusing existing columns (no new event-table column):

| event_type | emitted from | IDs | carries (in the Redis-Streams JSON) |
|---|---|---|---|
| `rate_limit_degraded` | admission path / health loop, on Redis failure | **real** four IDs of the triggering request (in-request); `WILDCARD_UUID` + `agent_id='rate-limiter'` when emitted from the loop | `redis_error_class`, `redis_error_module` (never the message) |
| `rate_limit_recovered` | health loop, on Redis recovery | `WILDCARD_UUID` tenant/team/project + `agent_id='rate-limiter'` | — |
| `rate_limit_redis_error` | admission path, per distinct Redis error (forensic) | real four IDs | `redis_error_class`, `redis_error_module` |

**Redis error class is carried only in the Streams event JSON and the OTel span event —
never in an `events_audit_log` column.** We do not add a column (constraint) and do not
overload F-007's `classifier_reason` (semantic conflation). The audit row is the
control-plane record (event_type + `action_taken='logged'` + four IDs + timestamps);
`request_id` is the forensic join-key. We never serialize `str(exc)` (it may contain a
host/port/credential).

### Reserved IDs (third documented use of `WILDCARD_UUID`)

> `WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"` (defined ADR-0009 §4). F-009
> adds a **third** documented purpose to the two in ADR-0009 §4/§7:
>
> 1. sub-tenant wildcard for model policies (ADR-0009 §4);
> 2. system-scoped audit owner for **pre-verification** policy rejections (ADR-0009 §7);
> 3. **(new)** system-scoped audit owner for **system-emitted events** with no request
>    context — `rate_limit_recovered` (and `rate_limit_degraded`/`rate_limit_redis_error`
>    when emitted by the background health loop).
>
> The `agent_id` dimension is a **slug**, not a UUID, so it uses the reserved slug
> **`rate-limiter`** (mirroring the `all-agents` slug asymmetry noted in ADR-0009 §4).
> `tenant_id` as `WILDCARD_UUID` here denotes "the Sentinel system itself," consistent
> with §7; it is a system attribution, never a cross-tenant grant. `contracts/ids.md` is
> updated (api-architect) to document this third use with a cross-reference to ADR-0009.

Emission reuses the established privileged-session path
(`emit_routing_decision` precedent, `gateway/middleware/audit.py:187`):
`async with get_privileged_session() as session: async with session.begin(): await
AuditLogRepository(session).append(stamped)` (R6 — hash-chained).

---

## 8. Decision D7: Persistence (one reversible migration) + 4-site consistency

**`0011_observability_events`** (`down_revision="0010"`):

- Widen `ck_eal_event_type` via the `_set_event_type_check()` DROP+ADD helper (the
  `0008`/`0010` pattern) with the three new variants:
  `_WITH_F009 = _THROUGH_F007 + ",'rate_limit_degraded','rate_limit_recovered','rate_limit_redis_error'"`.
- `op.add_column('tenant_routing_policy', sa.Column('team_rpm_limit', sa.Integer(),
  nullable=True))` + `ck_trp_team_rpm_limit` CHECK `team_rpm_limit IS NULL OR
  team_rpm_limit > 0` (0 would silently block all team traffic).
- `down()`: drop the `tenant_routing_policy` column + its CHECK, then narrow
  `ck_eal_event_type` back to `_THROUGH_F007`. Loss-free for pre-existing rows
  (CHECK only widens an allowed set; the new column is nullable). Round-trip verified at
  STEP 10: `upgrade head → downgrade -1 → upgrade head`.

**No new variant columns on `events_audit_log`** — the three variants reuse
`action_taken='logged'` only.

**4-site consistency** (the F-006 anti-pattern guard): the three variants land in
lockstep across `events_audit_log.VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`
(each → `{"logged"}`), the `ck_eal_event_type` CHECK, and `contracts/events.schema.json`.

### R7 deviation note (explicit, Affu-authorized)

R7 reads "no new tables; migration 0011 only widens the CHECK constraint." The **hard**
rule — *no new tables* — is satisfied. The "only widens the CHECK" wording is
**superseded** by Affu's team-tier refinement, which requires one **nullable** column
(`team_rpm_limit`) on the **existing** `tenant_routing_policy` table. This is the minimal
change that realizes the opt-in team tier without a new table or a policy-contract change,
and it is fully reversible. Recorded here for the security-auditor and PR gates.

---

## 9. Threat Model — 17 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting correct behavior **and** the correct
audit event **and** no state corruption — not merely "raises." Test files:
`tests/gateway/test_rate_limit_threat_model.py` (1–8, 15, 16, 17),
`tests/gateway/test_metrics_threat_model.py` (9–11, 14),
`tests/gateway/test_tracing.py` (12–13).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | TOCTOU / race on admission | ZADD-inside-EXEC + compensating ZREM (D1) | 50 concurrent, limit 5 → exactly 5 admitted |
| 2 | Redis outage mid-flight | γ fallback to in-process (D2) | in-memory limit still enforces |
| 3 | Redis recovery | health loop resumes Redis path (D2) | primary resumes; `rate_limit_recovered` emitted |
| 4 | Distributed attack, one tenant | tenant-tier ZSET (D1) | 100 concurrent virtual keys → tenant cap holds across all |
| 5 | Key reused across teams | per-team key namespace (D3) | per-team limits not shared |
| 6 | Slow Redis (> 2 s) | connect/socket timeout → fallback (R10) | timeout triggers γ fallback |
| 7 | Window-boundary double-admit | sliding-window scores (D1) | 23:59:59 + 00:00:01 bucketed correctly |
| 8 | Burst within window | `ZCOUNT` 1 s burst check (D1) | burst enforced even when rpm not exceeded |
| 9 | `/metrics` info disclosure | redaction by construction (D4, R9) | no API keys / virtual keys / prompts / PII |
| 10 | Per-tenant labels leaking by default | gate default `False` (D4, R4) | no `tenant_id` labels present |
| 11 | Per-tenant enable | flag path (D4) | `tenant_id` labels present + startup warning logged |
| 12 | Trace context to provider | W3C propagation via httpx instrumentation (D5) | trace-id injected into outbound provider request |
| 13 | Audit-in-span correlation | trace-id in structlog + `audit_emit` span (D5) | audit emission carries the current trace-id |
| 14 | Cardinality bomb | bounded label sets; gated per-tenant (D4) | 1000 tenants → `/metrics` response time + memory bounded |
| 15 | Team tier stricter than tenant | three-window strictest-wins (D3) | team limit governs when tighter |
| 16 | Recovery event identity | `WILDCARD_UUID` + `agent_id='rate-limiter'` (D6) | recovery event uses system IDs |
| 17 | Degraded event identity / leak | real IDs + error class only (D6) | degraded event carries real IDs; no conn-string leak |

---

## 10. Alternatives Considered & Honest Deferrals

- **Fail-closed on Redis outage — REJECTED.** Blocking all traffic during a Redis blip
  turns a dependency hiccup into a Sentinel outage. γ (fallback + degraded event) keeps
  the gateway enforcing (per-worker) and observable. (R3.)
- **Per-tenant metric labels by default — REJECTED.** Linear cardinality growth with
  tenant count harms Prometheus and Grafana; most operators do not need per-tenant
  granularity. Gated behind a flag with a documented cost warning (γ). (R4.)
- **Fixed-window `INCR`/`EXPIRE` rate limiting — REJECTED.** Fixed windows admit up to
  2× the limit at a boundary (the classic burst-at-reset flaw). Sorted-set sliding
  windows are accurate at the cost of more memory per key (bounded by `EXPIRE`). (D1.)
- **`team_rpm_limit` default = `rate_limit_rpm` — REJECTED (Affu).** Identical to the
  tenant cap, so the team window would always permit — a dead path. Default `None`
  (opt-in) makes the tier real only when configured.
- **Redis error class in an `events_audit_log` column — REJECTED.** Adds a column
  (constraint) or overloads `classifier_reason`. The Streams event JSON + OTel span
  carry the forensic class; the audit row stays a clean control-plane record (D7/§7).
- **A `RedisRateLimitMiddleware` class — REJECTED.** The limiter is a function at step 6;
  converting it to middleware would change the pipeline shape (R2). We refactor the
  function internals only.
- **Deferral — no OTel export backend in F-009.** Spans are emitted to a no-op sink;
  OTLP export, collector, and sampling are F-010 (deployment) concerns. The
  instrumentation hooks ship now so F-010 is configuration-only.
- **Deferral — Bedrock egress monitoring** remains the F-007 carryover (aioboto3 is not
  on the httpx event-hook path); unchanged by F-009.

---

## 11. Contract Changes

**`contracts/events.schema.json` (api-architect, STEP 5):** add three closed,
fully-bounded variants to `oneOf` — `rate_limit_degraded`, `rate_limit_recovered`,
`rate_limit_redis_error`. Each carries the four stable IDs + `event_id` /
`event_timestamp` / `request_id` + `action_taken` (enum `["logged"]`) + bounded optional
forensic fields (`redis_error_class`, `redis_error_module` —
`maxLength`-bounded strings) where applicable. **No existing variant changes.**

**`contracts/ids.md` (api-architect, STEP 5):** document the **third** use of
`WILDCARD_UUID` (system-emitted events) with the `agent_id='rate-limiter'` slug and a
cross-reference to ADR-0009 §4/§7.

> **Process note (mirrors ADR-0009 §13 / ADR-0010 §13):** edits to `contracts/` are gated
> by `.claude/hooks/protect-paths-and-secrets.sh`, which authorizes the write only when
> the agent identity is `api-architect`. STEP 5 dispatches the api-architect agent; if
> the env identity is not provisioned, the patch is recorded for verbatim re-apply under
> that identity. The protection logic is never modified or weakened.

**`contracts/policy.schema.json`:** **not touched** (LOCKED at F-008).

---

## 12. Consequences

### 12.1 Positive
- Rate limiting becomes **distributed and accurate** (sliding window), closing the
  per-worker N × RPM honest gap for the common (Redis-healthy) case.
- The gateway becomes **operationally observable** (metrics + traces) ahead of F-010,
  including a metric that **closes the F-008 audit-write-failure debt**.
- γ keeps Sentinel enforcing and auditable through Redis outages; recovery is automatic
  and audited.
- The team tier ships as a config-gated abstraction with **zero** default behavior
  change.

### 12.2 Negative / costs
- **Redis is now a runtime dependency.** Ops must run and monitor it; a Prometheus
  scrape config is required. Mitigated by γ (graceful degradation) and the
  `sentinel_redis_health` gauge.
- `/metrics` is unauthenticated — it **must** be network-isolated (firewalled), not on
  the public listener. Documented; enforced operationally, verified content-clean (R9).
- Per-tenant metrics, when enabled, grow cardinality linearly — documented, gated, and
  cardinality-bounded by test #14.
- One coordinated migration + three coordinated event sites (mitigated by 4-site
  discipline + round-trip and INSERT-per-variant tests).

### 12.3 Rollback
- **Per-tenant:** set `team_rpm_limit = NULL` → the team tier reverts to a no-op
  immediately.
- **Observability:** `ENABLE_OTEL=false` disables tracing; the `/metrics` route is
  additive and inert if unscraped.
- **Migration:** `0011` downgrades by dropping the `team_rpm_limit` column + CHECK and
  reverting `ck_eal_event_type` to the F-007 set (only narrows an allowed set — no
  pre-existing row violates it). Verified at STEP 10.
- **Whole feature:** revert `task/F-009-observability-native`; the Redis path,
  observability primitives, and team tier are additive and the legacy in-process limiter
  is retained as the fallback, so reverting restores F-004 behavior exactly.
