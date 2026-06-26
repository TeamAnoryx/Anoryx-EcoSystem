"""Redis-backed distributed rate limiter with γ in-process fallback (F-009, ADR-0011).

Decision D1 — Redis ZSET sliding window (atomic admission):
  Three independent tiers; ALL must permit; strictest governs.
  Key namespaces:
      sentinel:rl:vk:{virtual_key_id}
      sentinel:rl:team:{tenant_id}:{team_id}   (only when team_rpm_limit IS NOT NULL)
      sentinel:rl:tenant:{tenant_id}
  One MULTI/EXEC pipeline per tier:
      ZREMRANGEBYSCORE  key  -inf  {now_ms - 60000}
      ZADD              key  {now_ms}  {member}       <- precedes ZCARD (MED-1 D1)
      ZCARD             key                           <- rpm_count (includes this request)
      ZCOUNT            key  {now_ms - 1000}  {now_ms}  <- burst_count last 1 s
      EXPIRE            key  61
  On rejection: compensating ZREM key {member} (globally unique member → safe).
  Wall-clock ms scores: cross-worker comparable (unlike monotonic).

Decision D2 — Failure mode γ:
  _redis_degraded flag (single-writer: health loop in redis_client.py).
  On RedisConnectionError / TimeoutError in the primary path:
    → set degraded (via redis_client), fall back, emit rate_limit_degraded (debounced).
  Health loop (redis_client.py) detects recovery → emit rate_limit_recovered.
  γ: NEVER fail-open w/o fallback, NEVER fail-closed.

Decision D3 — Three-tier (key < team < tenant), team opt-in:
  team_rpm_limit from tenant_routing_policy (nullable). None = no-op.
  Lookup cached in _team_limit_cache[(tenant_id, team_id)] with 60 s TTL.

MED-1 (TOCTOU fix, F-004):
  Redis path: ZADD-inside-EXEC is atomic (no read-check-write gap). Compensating ZREM
  on rejection preserves the guarantee distributively.
  Legacy path: entire check+increment under _lock (unchanged).

Stream cap:
  Redis: atomic INCR/DECR on sentinel:rl:streams:{tenant_id}.
  Legacy: existing _stream_counters + stream_slot() logic (verbatim).

NEVER:
  - Key on IP/X-Forwarded-For.
  - Log redis_url, passwords, or str(exc) (may contain host/port/credentials).
  - Change the function signature or the call-site in chat_completions.py.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from gateway.config import get_settings
from gateway.exceptions import GatewayError
from gateway.observability.metrics import record_rate_limit_decision

log = structlog.get_logger(__name__)


def _get_tenant_session(tenant_id: str):
    """Thin wrapper around get_tenant_session for patchability in tests (L4).

    Defined at module level so tests can patch
    gateway.middleware.rate_limit._get_tenant_session without importing
    persistence.database into the test module.
    """
    from persistence.database import get_tenant_session

    return get_tenant_session(tenant_id)


async def emit_rate_limit_event(event_type: str, **kwargs) -> None:  # type: ignore[override]
    """Module-level wrapper around audit.emit_rate_limit_event.

    Defined here so tests can patch gateway.middleware.rate_limit.emit_rate_limit_event
    without needing to import gateway.middleware.audit in test code. The _handle_redis_error
    function calls this wrapper (not the audit module directly), making debounce-emit
    tests simple.
    """
    from gateway.middleware.audit import emit_rate_limit_event as _audit_emit

    await _audit_emit(event_type, **kwargs)


def get_tracer(name: str):
    """Module-level wrapper around observability.tracing.get_tracer (L3 / patchability).

    Defined here so tests can patch gateway.middleware.rate_limit.get_tracer.
    Returns None if OTel is unavailable so callers fall back to untraced path (R8).
    """
    try:
        from gateway.observability.tracing import get_tracer as _real_get_tracer

        return _real_get_tracer(name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Legacy in-process state — PRESERVED VERBATIM for γ fallback (ADR-0011 D2)
# ---------------------------------------------------------------------------

# Per-key and per-tenant sliding windows: deque of timestamps (float, monotonic).
# Each entry is the time a request was admitted.
_key_windows: dict[str, deque[float]] = {}
_tenant_windows: dict[str, deque[float]] = {}

# Per-tenant concurrent-stream counter.
# MED-1: incremented ATOMICALLY at admission time inside check_rate_limit()
# when is_stream=True. stream_slot() only decrements on exit.
_stream_counters: dict[str, int] = {}

# A single asyncio lock protects all mutable state above.
# Using one lock keeps the implementation simple for Phase 0 single-process.
_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Team-limit cache (D3) — maps (tenant_id, team_id) → (rpm_limit | None, expiry_mono)
# ---------------------------------------------------------------------------
_team_limit_cache: dict[tuple[str, str], tuple[int | None, float]] = {}
_TEAM_LIMIT_CACHE_TTL: float = 60.0  # seconds

# Redis key namespace (ADR-0011 D1)
_KEY_PREFIX = "sentinel:rl:vk:"
_TENANT_PREFIX = "sentinel:rl:tenant:"
_TEAM_PREFIX = "sentinel:rl:team:"
_STREAM_PREFIX = "sentinel:rl:streams:"

_WINDOW_MS: int = 60_000  # 60 s sliding window
_BURST_MS: int = 1_000  # 1 s burst window
_EXPIRE_S: int = 61  # idle key TTL

# ---------------------------------------------------------------------------
# Degraded-event debounce — emit once per outage, not per request
# ---------------------------------------------------------------------------
_degraded_emitted: bool = False

# L1: rate_limit_redis_error debounce — emit once per DISTINCT error class per
# outage (forensic; ADR-0011 §7/D6). Bounded cardinality: Redis exception class
# names are a very small closed set. Reset by mark_recovered() alongside
# _degraded_emitted so a new outage re-emits all error classes seen again.
_redis_error_classes_emitted: set[str] = set()


def _evict_old_entries(window: deque[float], now: float, window_seconds: float = 60.0) -> None:
    """Remove entries older than window_seconds from the sliding window."""
    cutoff = now - window_seconds
    while window and window[0] < cutoff:
        window.popleft()


# ---------------------------------------------------------------------------
# Legacy in-process implementation — PRESERVED VERBATIM (γ fallback)
# ---------------------------------------------------------------------------


async def _legacy_check_rate_limit(
    virtual_key_id: str,
    tenant_id: str,
    is_stream: bool = False,
) -> tuple[int, int, int]:
    """In-process sliding-window rate check (verbatim F-004 logic).

    This function is the EXACT original check_rate_limit body, renamed for use
    as the γ fallback when _redis_degraded is True. It MUST NOT be modified
    without also verifying MED-1 is preserved.
    """
    settings = get_settings()
    rpm = settings.rate_limit_rpm
    burst = settings.rate_limit_burst
    max_streams = settings.max_concurrent_streams_per_tenant
    window_seconds = 60.0

    now = time.monotonic()
    epoch_now = int(time.time())

    async with _lock:
        # --- Sliding-window rate check (per-key) ---
        key_window = _key_windows.setdefault(virtual_key_id, deque())
        _evict_old_entries(key_window, now, window_seconds)

        # --- Sliding-window rate check (per-tenant) ---
        tenant_window = _tenant_windows.setdefault(tenant_id, deque())
        _evict_old_entries(tenant_window, now, window_seconds)

        key_count = len(key_window)
        tenant_count = len(tenant_window)

        # Burst cap: also enforce that we haven't admitted burst requests in
        # the last second (short-term burst bound within the window).
        now_minus_1s = now - 1.0
        key_burst = sum(1 for t in key_window if t >= now_minus_1s)
        tenant_burst = sum(1 for t in tenant_window if t >= now_minus_1s)

        over_key_rpm = key_count >= rpm
        over_tenant_rpm = tenant_count >= rpm
        over_key_burst = key_burst >= burst
        over_tenant_burst = tenant_burst >= burst

        if over_key_rpm or over_tenant_rpm or over_key_burst or over_tenant_burst:
            # Compute retry_after: time until the oldest entry falls off the window.
            oldest_key = key_window[0] if key_window else now
            oldest_tenant = tenant_window[0] if tenant_window else now
            oldest = min(oldest_key, oldest_tenant)
            retry_after = max(1, int(window_seconds - (now - oldest)) + 1)
            log.info(
                "rate_limit_exceeded",
                virtual_key_id=virtual_key_id,
                tenant_id=tenant_id,
                key_count=key_count,
                tenant_count=tenant_count,
            )
            raise GatewayError("rate_limit_exceeded", retry_after=retry_after)

        # MED-1 FIX: Atomic stream-cap check AND increment under the SAME lock.
        # Previously: check only READ the counter; increment happened later in
        # stream_slot(). This created a TOCTOU window where concurrent requests
        # could all pass the check before any had incremented.
        # Fix: if is_stream and within cap, increment NOW before releasing lock.
        if is_stream:
            current_streams = _stream_counters.get(tenant_id, 0)
            if current_streams >= max_streams:
                log.info(
                    "concurrent_stream_limit_exceeded",
                    tenant_id=tenant_id,
                    current_streams=current_streams,
                    max_streams=max_streams,
                )
                raise GatewayError("rate_limit_exceeded", retry_after=5)
            # Atomically reserve the slot.
            _stream_counters[tenant_id] = current_streams + 1

        # Admit the request — record the timestamp in both windows.
        key_window.append(now)
        tenant_window.append(now)

        # LOW-1: Prune dict entries whose deques are empty after eviction.
        # After appending the current timestamps the active key/tenant windows
        # are guaranteed non-empty, so _prune_empty_windows() safely removes
        # ONLY the stale entries for other (now-inactive) keys/tenants.
        # This bounds dict memory growth from distinct keys/tenants that have
        # not generated traffic within the sliding window.
        _prune_empty_windows()

        remaining = max(0, rpm - len(key_window))
        reset_epoch = epoch_now + int(window_seconds)
        return rpm, remaining, reset_epoch


# ---------------------------------------------------------------------------
# Redis primary path helpers (D1)
# ---------------------------------------------------------------------------


async def _redis_admit_tier(
    client,
    key: str,
    rpm: int,
    burst: int,
) -> tuple[bool, str]:
    """Attempt admission for one tier via MULTI/EXEC.

    Returns (admitted: bool, member: str).
    member is the globally-unique ZADD member; callers use it for compensating ZREM.

    The pipeline is transaction=True (MULTI/EXEC). ZADD precedes ZCARD inside EXEC
    so Redis serializes the entire block — no concurrent worker sees an intermediate
    state (D1 / MED-1 distributed realization).
    """
    now_ms = int(time.time() * 1000)
    cutoff = now_ms - _WINDOW_MS
    burst_cutoff = now_ms - _BURST_MS
    member = f"{now_ms}:{uuid.uuid4().hex}"

    pipe = client.pipeline(transaction=True)
    pipe.zremrangebyscore(key, "-inf", cutoff)
    pipe.zadd(key, {member: now_ms})  # score = timestamp ms
    pipe.zcard(key)  # rpm_count (includes this request)
    pipe.zcount(key, burst_cutoff, now_ms)  # burst_count in last 1 s
    pipe.expire(key, _EXPIRE_S)
    results = await pipe.execute()

    # results[2] = ZCARD, results[3] = ZCOUNT
    rpm_count = int(results[2])
    burst_count = int(results[3])

    admitted = rpm_count <= rpm and burst_count <= burst
    return admitted, member


async def _redis_zrem(client, key: str, member: str) -> None:
    """Compensating ZREM: remove the just-added member on rejection.

    Member is globally unique (timestamp + uuid4 hex) — safe to remove
    even in a distributed environment.
    """
    try:
        await client.zrem(key, member)
    except Exception as exc:
        log.warning(
            "redis_zrem_failed",
            redis_error_class=type(exc).__name__,
            key=key,
        )


def _get_team_rpm_limit_cached(tenant_id: str, team_id: str) -> int | None | type(...):
    """Return cached team_rpm_limit, or Ellipsis (sentinel) on cache miss/expiry.

    Returns Ellipsis when the cache has no valid entry (caller must do DB read).
    Returns None when cache holds a confirmed "no limit" value.
    Returns int when cache holds a configured limit.
    """
    entry = _team_limit_cache.get((tenant_id, team_id))
    if entry is None:
        return ...  # cache miss
    limit, expiry = entry
    if time.monotonic() > expiry:
        del _team_limit_cache[(tenant_id, team_id)]
        return ...  # expired
    return limit  # may be None (cached no-limit) or int (cached limit)


async def _fetch_team_rpm_limit_from_db(tenant_id: str, team_id: str) -> int | None:
    """Read team_rpm_limit from tenant_routing_policy via a tenant session (RLS).

    L4 fix (Affu locked decision): check_rate_limit() reads team_rpm_limit from
    the tenant's resolved routing policy. Mirrors get_classifier_config from
    F-007 — tenant session (RLS), defense-in-depth tenant predicate.

    Reads the ORM row directly via SQLAlchemy select (same session pattern as
    TenantRoutingPolicyRepository) so we can access the nullable team_rpm_limit
    column that is not surfaced on EffectiveRoutingPolicy.

    On any read failure: treats as None (team tier no-op) and never fails the
    request. Result is cached for _TEAM_LIMIT_CACHE_TTL seconds.

    get_tenant_session is imported lazily and stored as a module-level reference
    (_get_tenant_session) so tests can patch gateway.middleware.rate_limit._get_tenant_session.
    """
    limit: int | None = None
    try:
        from sqlalchemy import select
        from sqlalchemy.exc import (
            InterfaceError,
            OperationalError,
        )
        from sqlalchemy.exc import (
            TimeoutError as SATimeoutError,
        )

        from persistence.models.tenant_routing_policy import TenantRoutingPolicy

        # get_tenant_session autobegins (it runs set_config before yielding), so an
        # explicit `session.begin()` here would raise InvalidRequestError — the F-007
        # double-begin class (ADR-0026), which the old broad `except` swallowed into a
        # silent team-tier no-op on every real-DB request. This is a read; use the
        # autobegun transaction directly (no begin/commit needed).
        async with _get_tenant_session(tenant_id) as session:
            stmt = select(TenantRoutingPolicy.team_rpm_limit).where(
                TenantRoutingPolicy.tenant_id == tenant_id
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            # row is the scalar team_rpm_limit value (int or None)
            limit = int(row) if row is not None else None
    except (OperationalError, InterfaceError, SATimeoutError, OSError) as exc:
        # ADR-0026 Fork 1 (+ audit High): a genuine DB-connectivity error — a down DB
        # surfaced as a builtin OSError (ConnectionRefusedError / socket.gaierror / the
        # builtin TimeoutError from command_timeout), a connection loss, or a
        # pool-checkout timeout (sqlalchemy.exc.TimeoutError) — is a DELIBERATE, bounded
        # fail-open: the team tier no-ops while the Redis tenant/vkey tiers still cap (a
        # rate limiter is an availability control; failing it closed on a Postgres blip
        # would be a self-inflicted DoS). The set excludes InvalidRequestError /
        # ProgrammingError so a begin()-class logic defect raises loudly instead of
        # silently disabling the tier. Do NOT cache on a connectivity error — let the
        # next request retry rather than poison the TTL.
        log.warning(
            "team_rpm_limit_db_read_failed",
            tenant_id=tenant_id,
            # L3 pattern: error type only, never the message (may contain credentials).
            error_class=type(exc).__name__,
        )
        return None

    # Cache the result (including None = "no limit configured") so subsequent
    # requests within the TTL skip the DB round-trip.
    _team_limit_cache[(tenant_id, team_id)] = (limit, time.monotonic() + _TEAM_LIMIT_CACHE_TTL)
    return limit


async def _get_team_rpm_limit_async(tenant_id: str, team_id: str) -> int | None:
    """Return the team_rpm_limit for (tenant_id, team_id), reading DB on cache miss.

    Cache-first; falls back to DB on miss or expiry. On DB read failure returns
    None (team tier no-op) so the request is never blocked by a DB hiccup (L4).
    """
    cached = _get_team_rpm_limit_cached(tenant_id, team_id)
    if cached is not ...:
        return cached  # type: ignore[return-value]
    return await _fetch_team_rpm_limit_from_db(tenant_id, team_id)


def _get_team_rpm_limit(tenant_id: str, team_id: str) -> int | None:
    """Synchronous cache-only read — returns None on cache miss (legacy callers).

    Used only by tests and legacy sync callers. Async callers in the admission
    path use _get_team_rpm_limit_async() which does the DB read on cache miss.
    """
    cached = _get_team_rpm_limit_cached(tenant_id, team_id)
    if cached is ...:
        return None
    return cached  # type: ignore[return-value]


def _set_team_rpm_limit(tenant_id: str, team_id: str, limit: int | None) -> None:
    """Populate the team limit cache (used by tests and the DB lookup path)."""
    _team_limit_cache[(tenant_id, team_id)] = (limit, time.monotonic() + _TEAM_LIMIT_CACHE_TTL)


# ---------------------------------------------------------------------------
# Public entry point (ADR-0006 step 6 — signature FROZEN)
# ---------------------------------------------------------------------------


async def check_rate_limit(
    virtual_key_id: str,
    tenant_id: str,
    is_stream: bool = False,
    *,
    # Optional: pre-resolved team_id for D3 team tier. When None the team tier
    # is a no-op (consistent with team_rpm_limit IS NULL default).
    team_id: str | None = None,
    # Optional: real request_id from request.state for degraded-event attribution.
    # When None a synthetic fallback is generated (see _handle_redis_error).
    request_id: str | None = None,
) -> tuple[int, int, int]:
    """Check and record a request against the rate limits.

    Returns (limit, remaining, reset_epoch_seconds) for the governing window.
    Raises GatewayError("rate_limit_exceeded") with retry_after set if over limit.

    PRIMARY PATH (Redis healthy):
      Three independent ZSET sliding windows (D1). Strictest governs.
      ZADD-inside-EXEC preserves MED-1 TOCTOU guarantee distributively.

    FALLBACK PATH (_redis_degraded=True, γ):
      Falls back to _legacy_check_rate_limit (in-process, F-004 verbatim).
      Falls back silently after a debounced rate_limit_degraded emit.

    MUST be called AFTER auth has resolved virtual_key_id and tenant_id.
    NEVER keyed on IP address.
    """
    import gateway.redis_client as rc

    # F-009 D5: INTERNAL span covering the full rate-limit check (both paths).
    # Attributes per R9: tier/result/tenant_id(uuid)/request_id — NEVER virtual_key_id.
    # Failure never propagates (R8).
    #
    # HIGH-1 guard: _do_check() executes EXACTLY ONCE per call to check_rate_limit.
    # The span wrapper's outer `except Exception` re-runs the check ONLY when the
    # span SETUP failed before _do_check() ever ran (check_ran remains False).
    # Once _do_check() has started (check_ran=True), any exception it raises
    # (GatewayError rate_limit_exceeded, Redis error, etc.) propagates directly
    # without a retry — preventing a double-ZADD / double-admission on rejection.

    # get_tracer is the module-level wrapper — patchable in tests (L3).
    _tracer = get_tracer("sentinel.rate_limit")

    async def _do_check() -> tuple[int, int, int]:
        if rc.is_degraded():
            return await _legacy_check_rate_limit(virtual_key_id, tenant_id, is_stream)

        settings = get_settings()
        rpm = settings.rate_limit_rpm
        burst = settings.rate_limit_burst
        max_streams = settings.max_concurrent_streams_per_tenant

        try:
            return await _redis_primary_check(
                virtual_key_id=virtual_key_id,
                tenant_id=tenant_id,
                team_id=team_id,
                is_stream=is_stream,
                rpm=rpm,
                burst=burst,
                max_streams=max_streams,
            )
        except (RedisConnectionError, RedisTimeoutError) as exc:
            await _handle_redis_error(
                exc,
                virtual_key_id=virtual_key_id,
                tenant_id=tenant_id,
                request_id=request_id,
            )
            # γ: fall back to in-process
            return await _legacy_check_rate_limit(virtual_key_id, tenant_id, is_stream)

    if _tracer is None:
        return await _do_check()

    # HIGH-1: guard flag — True once _do_check() has been invoked (regardless of
    # outcome). The outer except only retries when False (span setup failed before
    # the check ran).
    check_ran = False
    # Resolve SpanKind.INTERNAL lazily — safe if OTel is unavailable (R8).
    _span_kind = None
    try:
        from opentelemetry.trace import SpanKind as _SpanKind

        _span_kind = _SpanKind.INTERNAL
    except Exception:
        pass

    try:
        _start_kwargs = {"kind": _span_kind} if _span_kind is not None else {}
        with _tracer.start_as_current_span("rate_limit_check", **_start_kwargs) as _span:
            try:
                # R9: tenant_id is a UUID (not PII); tier and path label the scope.
                _span.set_attribute("tier", "multi")
                _span.set_attribute("tenant_id", tenant_id)
                _span.set_attribute("path", "redis" if not rc.is_degraded() else "legacy")
                check_ran = True
                result = await _do_check()
                _span.set_attribute("result", "admitted")
                return result
            except Exception as _exc:
                _span.set_attribute("result", "rejected")
                # L3: record only error TYPE — never the exception message or
                # full object. A RedisConnectionError message can contain
                # redis://user:pass@host — never capture it on a span (R9).
                _span.set_attribute("error.type", type(_exc).__name__)
                _span.set_attribute("error.module", type(_exc).__module__)
                try:
                    from opentelemetry.trace import StatusCode

                    _span.set_status(StatusCode.ERROR, type(_exc).__name__)
                except Exception:
                    pass  # R8: OTel status call must never affect request path.
                raise
    except Exception:
        # R8: if span context itself failed BEFORE _do_check() ran, run the check
        # untraced. If _do_check() already ran and raised, propagate without retry.
        if check_ran:
            raise
        return await _do_check()


async def _redis_primary_check(
    *,
    virtual_key_id: str,
    tenant_id: str,
    team_id: str | None,
    is_stream: bool,
    rpm: int,
    burst: int,
    max_streams: int,
) -> tuple[int, int, int]:
    """Execute the Redis primary admission path (D1, D3).

    All three tiers evaluated independently. If any tier rejects, we issue
    compensating ZREMs for all admitted tiers before raising.
    """
    import gateway.redis_client as rc

    pool = rc.get_pool()
    if pool is None:
        raise RedisConnectionError("pool not initialised")

    client = AsyncRedis(connection_pool=pool)

    try:
        return await _run_redis_admission(
            client=client,
            virtual_key_id=virtual_key_id,
            tenant_id=tenant_id,
            team_id=team_id,
            is_stream=is_stream,
            rpm=rpm,
            burst=burst,
            max_streams=max_streams,
        )
    finally:
        await client.aclose()


async def _run_redis_admission(
    *,
    client,
    virtual_key_id: str,
    tenant_id: str,
    team_id: str | None,
    is_stream: bool,
    rpm: int,
    burst: int,
    max_streams: int,
) -> tuple[int, int, int]:
    """Core admission logic with compensating ZREM on rejection.

    Evaluates tiers in order: virtual-key → team (if configured) → tenant.
    All must admit; strictest remaining count governs.
    """
    vk_key = f"{_KEY_PREFIX}{virtual_key_id}"
    tenant_key = f"{_TENANT_PREFIX}{tenant_id}"

    # Track admitted (key, member) pairs for compensating ZREM on rejection.
    admitted_members: list[tuple[str, str]] = []

    # --- Tier 1: virtual key ---
    vk_admitted, vk_member = await _redis_admit_tier(client, vk_key, rpm, burst)
    if not vk_admitted:
        # Not admitted — do not add to admitted list, raise directly.
        log.info(
            "rate_limit_exceeded",
            tier="virtual_key",
            virtual_key_id=virtual_key_id,
            tenant_id=tenant_id,
        )
        # F-009: record decision metric (pure addition — R2).
        record_rate_limit_decision("rate_limited_key", tenant_id=tenant_id)
        raise GatewayError("rate_limit_exceeded", retry_after=60)
    admitted_members.append((vk_key, vk_member))

    # --- Tier 2: team (opt-in, D3) ---
    # L4: read team_rpm_limit via DB (tenant session / RLS) on cache miss.
    team_rpm: int | None = None
    if team_id is not None:
        team_rpm = await _get_team_rpm_limit_async(tenant_id, team_id)
        if team_rpm is not None:
            team_key = f"{_TEAM_PREFIX}{tenant_id}:{team_id}"
            team_admitted, team_member = await _redis_admit_tier(client, team_key, team_rpm, burst)
            if not team_admitted:
                # Compensate admitted tiers
                for k, m in admitted_members:
                    await _redis_zrem(client, k, m)
                log.info(
                    "rate_limit_exceeded",
                    tier="team",
                    tenant_id=tenant_id,
                    team_id=team_id,
                )
                # F-009: record decision metric (pure addition — R2).
                record_rate_limit_decision("rate_limited_team", tenant_id=tenant_id)
                raise GatewayError("rate_limit_exceeded", retry_after=60)
            admitted_members.append((team_key, team_member))

    # --- Tier 3: tenant ---
    tenant_admitted, tenant_member = await _redis_admit_tier(client, tenant_key, rpm, burst)
    if not tenant_admitted:
        # Compensate admitted tiers
        for k, m in admitted_members:
            await _redis_zrem(client, k, m)
        log.info(
            "rate_limit_exceeded",
            tier="tenant",
            tenant_id=tenant_id,
        )
        # F-009: record decision metric (pure addition — R2).
        record_rate_limit_decision("rate_limited_tenant", tenant_id=tenant_id)
        raise GatewayError("rate_limit_exceeded", retry_after=60)
    admitted_members.append((tenant_key, tenant_member))

    # --- Concurrent-stream cap (atomic INCR/DECR, MED-1 D1) ---
    if is_stream:
        stream_key = f"{_STREAM_PREFIX}{tenant_id}"
        settings = get_settings()
        max_streams = settings.max_concurrent_streams_per_tenant
        current = await client.incr(stream_key)
        if current > max_streams:
            # Undo the INCR and compensate ZSETs
            await client.decr(stream_key)
            for k, m in admitted_members:
                await _redis_zrem(client, k, m)
            log.info(
                "concurrent_stream_limit_exceeded",
                tenant_id=tenant_id,
                current_streams=current,
                max_streams=max_streams,
            )
            raise GatewayError("rate_limit_exceeded", retry_after=5)

    # All tiers admitted. F-009: record decision metric (pure addition — R2).
    record_rate_limit_decision("admitted", tenant_id=tenant_id)

    # Compute governing remaining from virtual-key tier.
    # ZCARD after admission already accounts for this request.
    now_ms = int(time.time() * 1000)
    cutoff = now_ms - _WINDOW_MS
    try:
        vk_count = await client.zcount(vk_key, cutoff, now_ms)
    except Exception:
        vk_count = 0
    remaining = max(0, rpm - int(vk_count))
    reset_epoch = int(time.time()) + 60

    # Strictest remaining: if team tier is tighter, use its remaining count.
    if team_rpm is not None and team_id is not None:
        team_key = f"{_TEAM_PREFIX}{tenant_id}:{team_id}"
        try:
            team_count = await client.zcount(team_key, cutoff, now_ms)
        except Exception:
            team_count = 0
        team_remaining = max(0, team_rpm - int(team_count))
        remaining = min(remaining, team_remaining)

    return rpm, remaining, reset_epoch


async def _handle_redis_error(
    exc: Exception,
    *,
    virtual_key_id: str,
    tenant_id: str,
    request_id: str | None = None,
) -> None:
    """On RedisConnectionError/TimeoutError: set degraded flag + debounced emits.

    LOW-2: request_id is the real request_id from request.state when available.
    When None, a synthetic fallback is generated so the forensic join-key is
    consistent across workers for the same outage.

    MED-1 (single-writer contract): this hot-path function may only SET degraded
    to True. Clearing the flag (True → False) is the health loop's EXCLUSIVE
    responsibility (redis_client._health_loop). This ensures a single writer
    controls recovery and avoids the race where two concurrent hot-path requests
    disagree on degraded state during a transient blip.

    L1: Also emits rate_limit_redis_error (forensic) debounced per distinct error
    class per outage (ADR-0011 §7/D6). Bounded — Redis exception class names are a
    small closed set; never emitted unboundedly per request.
    """
    global _degraded_emitted, _redis_error_classes_emitted

    import gateway.redis_client as rc

    error_class = type(exc).__name__
    error_module = type(exc).__module__[:128]
    # Hot path: may only set True (degrade). Only the health loop clears to False.
    rc._set_degraded(True)

    log.warning(
        "redis_rate_limit_error_fallback",
        redis_error_class=error_class,
        tenant_id=tenant_id,
    )

    # F-009: record degraded-path decision metric (pure addition — R2).
    record_rate_limit_decision("rate_limited_degraded", tenant_id=tenant_id)

    # LOW-2: use real request_id when available; synthetic fallback otherwise.
    effective_request_id = request_id or _request_id_for_degraded(virtual_key_id, tenant_id)

    # Emit rate_limit_degraded once per outage transition (debounced).
    if not _degraded_emitted:
        _degraded_emitted = True
        # Best-effort emit — if this fails (Redis still down) we log and continue.
        try:
            await emit_rate_limit_event(
                "rate_limit_degraded",
                request_id=effective_request_id,
                tenant_id=tenant_id,
                redis_error_class=error_class,
                redis_error_module=error_module,
            )
        except Exception:
            log.error(
                "rate_limit_degraded_emit_failed",
                redis_error_class=error_class,
            )

    # L1: Emit rate_limit_redis_error once per DISTINCT error class per outage.
    # Forensic signal (ADR-0011 §7/D6). Bounded cardinality — never per-request.
    if error_class not in _redis_error_classes_emitted:
        _redis_error_classes_emitted.add(error_class)
        try:
            await emit_rate_limit_event(
                "rate_limit_redis_error",
                request_id=effective_request_id,
                tenant_id=tenant_id,
                redis_error_class=error_class,
                redis_error_module=error_module,
            )
        except Exception:
            log.error(
                "rate_limit_redis_error_emit_failed",
                redis_error_class=error_class,
            )


def mark_recovered() -> None:
    """Reset the degraded-event debounce so the next outage emits again.

    Called by redis_client._health_loop after a fail→healthy transition so that
    a SECOND Redis outage following a recovery correctly emits rate_limit_degraded
    again (MED-1 / MED-2 debounce reset).

    Also resets the per-error-class debounce set (L1) so a new outage re-emits
    all distinct error classes observed during it.

    This is the ONLY external writer of _degraded_emitted / _redis_error_classes_emitted.
    The health loop is the single recovery authority (single-writer contract, ADR-0011 D2).
    """
    global _degraded_emitted, _redis_error_classes_emitted
    _degraded_emitted = False
    _redis_error_classes_emitted = set()


def _request_id_for_degraded(virtual_key_id: str, tenant_id: str) -> str:
    """Generate a synthetic request_id for degraded events triggered in-request.

    In real call sites the request_id comes from request.state. Here we do not
    have access to the HTTP request — use a deterministic placeholder so the
    forensic join-key is consistent across workers for the same outage.
    """
    # Use a UUID5 namespace to make it deterministic but unique per (vk, tenant) pair.
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"degraded:{tenant_id}:{virtual_key_id}"))


# ---------------------------------------------------------------------------
# stream_slot — PRESERVED VERBATIM for legacy path; also used for Redis path teardown
# ---------------------------------------------------------------------------


@asynccontextmanager
async def stream_slot(tenant_id: str) -> AsyncIterator[None]:
    """Context manager that holds a concurrent-stream slot for tenant_id.

    MED-1: The counter was already incremented atomically by check_rate_limit()
    at admission time. This context manager only DECREMENTS on exit — it does
    NOT increment on entry (that would double-count and undo the MED-1 fix).

    Decrement is guaranteed via finally (close / complete / error / disconnect
    all decrement, ADR-0006 Decision 5, threat #4).

    LOW-1: After decrement, if the counter reaches 0 the dict entry is pruned.

    Redis path: DECR the Redis stream key. Legacy path: decrement _stream_counters.
    """
    import gateway.redis_client as rc

    try:
        yield
    finally:
        if rc.is_degraded():
            # Legacy path
            async with _lock:
                count = _stream_counters.get(tenant_id, 1)
                new_count = max(0, count - 1)
                if new_count == 0:
                    # LOW-1: prune zero-counter entries to prevent unbounded dict growth.
                    _stream_counters.pop(tenant_id, None)
                else:
                    _stream_counters[tenant_id] = new_count
        else:
            # Redis path: DECR atomic stream counter.
            stream_key = f"{_STREAM_PREFIX}{tenant_id}"
            pool = rc.get_pool()
            if pool is not None:
                try:
                    client = AsyncRedis(connection_pool=pool)
                    try:
                        val = await client.decr(stream_key)
                        if val <= 0:
                            await client.delete(stream_key)
                    finally:
                        await client.aclose()
                except Exception as exc:
                    log.warning(
                        "stream_slot_redis_decr_failed",
                        redis_error_class=type(exc).__name__,
                    )
            else:
                # Pool gone (shutdown race); fall back to legacy decrement.
                async with _lock:
                    count = _stream_counters.get(tenant_id, 1)
                    new_count = max(0, count - 1)
                    if new_count == 0:
                        _stream_counters.pop(tenant_id, None)
                    else:
                        _stream_counters[tenant_id] = new_count


def _prune_empty_windows() -> None:
    """Evict stale entries and prune empty sliding-window deques (LOW-1 helper).

    Called under _lock from _legacy_check_rate_limit() after the current key/tenant
    timestamps have been appended. Iterates ALL key/tenant windows, evicts
    stale timestamps (older than 60 s), and removes any window whose deque is
    empty after eviction. This bounds dict memory for inactive key/tenant strings.

    O(N) over the total number of tracked keys/tenants — acceptable because:
    - Phase 0 is single-process with a moderate number of tenants.
    - Called once per request; the dominant cost is the upstream round-trip.
    - Redis-backed distributed limiting in F-010 will replace this entirely.

    Must be called while _lock is held (caller's responsibility).
    """
    now = time.monotonic()
    window_seconds = 60.0

    # Evict + prune key windows.
    stale_keys = []
    for k, w in _key_windows.items():
        _evict_old_entries(w, now, window_seconds)
        if len(w) == 0:
            stale_keys.append(k)
    for k in stale_keys:
        del _key_windows[k]

    # Evict + prune tenant windows.
    stale_tenants = []
    for k, w in _tenant_windows.items():
        _evict_old_entries(w, now, window_seconds)
        if len(w) == 0:
            stale_tenants.append(k)
    for k in stale_tenants:
        del _tenant_windows[k]


def reset_state_for_testing() -> None:
    """Clear all in-process rate-limit state (test helper only)."""
    global _degraded_emitted, _redis_error_classes_emitted
    _key_windows.clear()
    _tenant_windows.clear()
    _stream_counters.clear()
    _team_limit_cache.clear()
    _degraded_emitted = False
    _redis_error_classes_emitted = set()

    # Also reset redis_client module flag so each test starts clean.
    try:
        import gateway.redis_client as rc

        rc._reset_for_testing()
    except ImportError:
        pass
