# ADR-0029 — Performance Hardening (F-023)

- Status: Accepted (implemented)
- Date: 2026-07-07
- Builds on: ADR-0008 (F-006 router — `selection.py::_enforce_policies_pre_request`,
  the hot-path call site), ADR-0009 (F-008 policy intake/enforcement —
  `evaluate_model_policies`, `load_active_budgets`), ADR-0011 (F-009 Redis pool +
  fail-safe γ pattern this ADR reuses), ADR-0005 (persistence — the two-engine
  `sentinel_app` / privileged split this ADR tunes one side of).
- Scope: **internal performance optimization only.** No `contracts/` change — a
  cache that returns the exact same decision `evaluate_model_policies()` would
  have computed is not a new API surface, event shape, or policy semantic.

## Context

Roadmap F-023: "Load testing vs p95<200ms, profile-guided optimization,
connection pooling audit, policy-eval cache." Profiling the live proxy path
(`gateway/router/selection.py::_enforce_policies_pre_request`, invoked on every
`/v1/chat/completions` request before routing) found two things:

1. **Every request pays 2-4 sequential DB SELECTs for F-008 model-policy
   evaluation** (`policy/enforcement.py::evaluate_model_policies` — deny-list,
   allow-list, and conditionally approval-list + a `model_inventory` row), even
   though a tenant's active model policies change only on an operator's F-008
   intake action — orders of magnitude less often than request volume.
2. **The `sentinel_app` DB engine's pool (`pool_size=5, max_overflow=10` = 15
   total connections) under-provisions the perf budget's own 100-concurrent
   load test** — requests beyond 15 in flight queue on pool checkout, which
   inflates p95 independent of DB or provider latency.

## Decision

### 1. Policy-eval cache (`src/policy/eval_cache.py`)

Cache the **model decision** (`ModelAllow` / `ModelDeny`) that
`evaluate_model_policies()` computes, keyed by
`(tenant_id, team_id, project_id, agent_id, model_id)`, in the Redis pool F-009
already maintains (`gateway/redis_client.py` — one shared pool, no second
connection pool introduced).

**Explicitly NOT cached:** `load_active_budgets()` / `budget_period_used()`. A
budget's "used" total changes on every usage event; caching it would let a
tenant burn past `budget_limit` before the ceiling caught up. Only the model
allow/deny/approval decision — which is a pure function of the *policy rows*,
not of request volume — is cacheable.

**Invalidation — version counter, not TTL-primary:**
Every accepted F-008 policy write of a decision-relevant type
(`model_allowlist` / `model_denylist` / `model_approval` — `policy/intake.py`)
increments a per-tenant Redis counter (`INCR sentinel:polcache:v:{tenant_id}`).
The cache key embeds that counter, so a write orphans every previously-cached
decision for that tenant in one O(1) command — no pattern `SCAN`/`DEL` (ADR-0011
already ruled out unbounded/blocking Redis commands on shared infrastructure).
A short TTL (`policy_eval_cache_ttl_seconds`, default **5s**) is a **backstop
only**, bounding staleness in the unlikely case the invalidating `INCR` is
missed (e.g. a direct DB write outside `intake.py`) — it is not the primary
invalidation mechanism, and honest language: this is a bounded-staleness cache,
not an instantly-consistent one.

**Fail-safe posture (CLAUDE.md §5, mirrors ADR-0011 γ):** every Redis
operation in `eval_cache.py` is wrapped so a connection error, timeout, or
decode failure is treated as a **cache miss** — the caller falls through to
the same `evaluate_model_policies()` DB call that ran unconditionally before
this change. A cache-miss path can only ever *repeat* work that was already
safe; it can never synthesize an ALLOW. Cache *writes* and *invalidations* are
best-effort and swallow their own errors (logged, `redis_error_class` only —
no connection strings) rather than fail the request or the policy write.
When `redis_client.is_degraded()` is already true (F-009's health-loop
verdict), every `eval_cache` function short-circuits to a miss without
attempting a Redis round trip at all — on the request hot path, blocking up to
the pool's socket timeout on a call already known to fail would itself violate
the p95 budget this cache exists to protect.

**Call-site change** (`gateway/router/selection.py::_enforce_policies_pre_request`):
look up the cached decision before opening the tenant DB session; on a hit,
skip straight to the (always-live) budget load; on a miss, evaluate as before
and write the result back. Two call sites (`route_non_stream`, `route_stream`)
now thread `settings` through so the TTL is configurable, not hardcoded.

### 2. Connection-pool audit (`src/persistence/database.py`)

The `sentinel_app` engine (all tenant request traffic) pool is now tunable via
`DB_APP_POOL_SIZE` (default **20**, was hardcoded 5), `DB_APP_MAX_OVERFLOW`
(default **20**, was hardcoded 10), and `DB_APP_POOL_TIMEOUT` (default **10s**,
was the SQLAlchemy default of 30s — a saturated pool now fails fast with a 500
rather than hanging near the request's own timeout budget). Operators running
multiple `SENTINEL_WORKERS` must size these against their Postgres
`max_connections` budget (`workers × (pool_size + max_overflow)`); the default
of 40 per worker is sized for the perf budget's single-worker,
100-concurrent-request load test, not a blanket recommendation for every
deployment topology.

The **privileged** engine (`pool_size=2, max_overflow=3`) is unchanged — audit
conclusion: it is correctly sized already (chain ops are advisory-lock
serialized; admin/migration use is rare and never on the request hot path).

The Redis pool (`redis_pool_size`, F-009) was already explicit and correctly
provisioned; the audit found no change needed there.

### 3. Live-path load test (`tests/gateway/test_live_path_latency_perf.py`)

A new pytest-marked (`@pytest.mark.perf`, excluded from the default `pytest`
run via `addopts = "-m 'not perf'"` so normal CI stays fast and non-flaky — run
explicitly via `pytest -m perf tests/gateway/`) harness drives a REAL uvicorn
server on loopback (not httpx's in-process `ASGITransport` — several gateway
middleware layers subclass Starlette's `BaseHTTPMiddleware`, which raises a
spurious "cancel scope in a different task" error under `ASGITransport` at
high in-process concurrency; a real server + real HTTP client sidesteps that
harness artifact) with **100 concurrent** `/v1/chat/completions` requests
against a mocked upstream provider — the perf-load-engineer budget is
explicitly "added latency" (Sentinel's own overhead), not upstream provider
latency, which Sentinel does not control. The DB session is a `MagicMock`
whose `execute()` answers every query with zero rows (same repository-boundary
stub `tests/gateway/conftest.py` uses elsewhere) — this exercises the REAL
`_enforce_policies_pre_request` / `evaluate_model_policies` / `eval_cache` code
path on a cache MISS, not a bypass of it, so the test also stands as a
load-bearing regression check on this ADR's own cache-miss code. Asserts
p95 < 200ms; failure message reports p50/p95/p99.

**Measured, disclosed honestly:** on this repo's sandboxed dev/CI-authoring
environment (a single, resource-constrained CPU core, one uvicorn worker, no
multi-process scaling), p95 stays well under budget through the tens of
concurrent requests but exceeds it at the full 100-concurrent mark — the
per-request CPU-bound cost (Pydantic validation, four stacked
`BaseHTTPMiddleware` layers, structlog serialization) is served by a single
asyncio event loop, so latency scales with concurrency roughly linearly on one
worker rather than staying flat. This is a single-worker capacity
characteristic, not a defect in this ADR's cache/pool changes — production
scales via `SENTINEL_WORKERS` / Helm replica count (ADR-0027), neither
exercised by this test. Recorded here rather than hidden: re-run this test
against your target deployment's actual worker topology for the authoritative
budget verdict — exactly why it stays a `perf`-marked, explicitly-invoked test
and not a blocking CI assertion on arbitrary/shared hardware.

## Honest limitations

- The eval cache's staleness window is bounded by the 5s TTL backstop, not
  zero — a policy change is enforced immediately in the overwhelmingly common
  case (the version-bump path) but the fail-safe design deliberately tolerates
  up to 5s of staleness in the rare invalidation-miss case, rather than making
  the request path depend on invalidation always succeeding.
- The load test measures gateway-added latency with a stubbed upstream and
  stubbed DB/Redis, matching perf-load-engineer's own stated method — it is
  **not** an end-to-end production latency measurement against real
  Postgres/Redis/upstream-provider network hops.
- Pool-size defaults are a starting point sized for the stated 100-concurrent
  budget, not a capacity-planning guarantee for arbitrary production load;
  operators must tune `DB_APP_POOL_SIZE`/`DB_APP_MAX_OVERFLOW` against their
  own `max_connections` and worker count.
- The load test's own p95 verdict is single-worker/single-host dependent (see
  above) — it validates the harness and the code path, not a universal PASS at
  100 concurrent on every deployment. Multi-worker capacity validation is
  future work, not claimed as done here.
