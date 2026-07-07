"""Redis connection pool + health-loop for distributed rate limiting (F-009, ADR-0011).

policy/eval_cache.py (F-023, ADR-0029) also reuses this same pool + the
is_degraded() flag for its policy-decision cache — no second Redis connection
pool is created for it.

Single entry points:
  - init(settings)   — called from _lifespan startup; stores pool on app.state.
  - shutdown()       — called from _lifespan teardown; closes pool + cancels health task.

Module-level flag _redis_degraded is the γ edge-detector:
  - True  → Redis unreachable; rate limiter falls back to _legacy_check_rate_limit.
  - False → Redis healthy; primary path active.

The flag is mutated ONLY by the health loop (single writer, asyncio single-threaded;
no hot-path lock needed). The hot path in rate_limit.py reads it without locking.

Background health loop (5 s interval):
  - Pings Redis with a 2 s timeout.
  - healthy→fail: sets _redis_degraded=True + emits rate_limit_degraded (debounced,
    once per outage transition).
  - fail→healthy: sets _redis_degraded=False + emits rate_limit_recovered (once).

Honest limitation (ADR-0011 §3): each worker has its own flag and loop; degraded /
recovered events may be emitted up to N times (worker count). Downstream consumers
MUST tolerate duplicates. If Redis is down the audit emit itself fails — structlog
WARNING + OTel span event are the durable fallback signals.

NEVER log: connection strings, passwords, or raw exception messages (may contain
host/port/credentials). Log only redis_error_class = type(exc).__name__.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog
from redis.asyncio import ConnectionPool
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

if TYPE_CHECKING:
    from gateway.config import GatewaySettings

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

# The single connection pool shared by all rate-limit callers in this process.
_pool: ConnectionPool | None = None

# γ degraded flag — single writer (health loop), many readers (hot path).
_redis_degraded: bool = False

# The background health-loop asyncio.Task — stored here so _lifespan can cancel it.
_health_task: asyncio.Task | None = None

# Sentinel request_id used by the health loop when no in-flight request triggered the event.
_SYSTEM_REQUEST_ID = "00000000-0000-0000-0000-000000000000"

# ---------------------------------------------------------------------------
# Flag accessors (for test isolation and rate_limit.py)
# ---------------------------------------------------------------------------


def is_degraded() -> bool:
    """Return True when Redis is considered unhealthy (γ path active)."""
    return _redis_degraded


def _set_degraded(value: bool) -> None:
    """Mutate the degraded flag.

    Single-writer contract (MED-1 / ADR-0011 D2):
      - The HOT PATH (rate_limit._handle_redis_error) may call this with
        value=True only (degrade on Redis error).
      - Clearing to False (recovery) is the health loop's EXCLUSIVE responsibility.
        Only _health_loop() calls _set_degraded(False) to avoid a race where
        concurrent hot-path requests disagree on degraded state during recovery.
    """
    global _redis_degraded
    _redis_degraded = value


# ---------------------------------------------------------------------------
# Pool accessors
# ---------------------------------------------------------------------------


def get_pool() -> ConnectionPool | None:
    """Return the active connection pool, or None if not initialised."""
    return _pool


async def get_client() -> AsyncRedis:
    """Return a Redis client from the pool.

    Callers must use this as an async context manager:
        async with (await get_client()) as client:
            ...

    Raises RuntimeError if the pool has not been initialised.
    """
    if _pool is None:
        raise RuntimeError("Redis pool not initialised — call redis_client.init() first")
    return AsyncRedis(connection_pool=_pool)


# ---------------------------------------------------------------------------
# Health loop
# ---------------------------------------------------------------------------

_HEALTH_LOOP_INTERVAL_S: float = 5.0
_HEALTH_PING_TIMEOUT_S: float = 2.0


async def _health_loop() -> None:
    """Background 5 s edge-detector: emit once per degraded/recovered transition.

    Runs forever until cancelled. Catches all exceptions so a transient error in
    the emit path never crashes the loop.
    """
    global _redis_degraded
    while True:
        await asyncio.sleep(_HEALTH_LOOP_INTERVAL_S)
        try:
            await _ping_redis()
            # Ping succeeded
            if _redis_degraded:
                # fail→healthy transition
                _set_degraded(False)
                # MED-2: reset rate_limit's debounce so the next outage emits again.
                # mark_recovered() is the ONLY external writer of _degraded_emitted.
                try:
                    from gateway.middleware.rate_limit import mark_recovered

                    mark_recovered()
                except Exception:
                    pass
                # F-009: update health gauge (pure addition — R2).
                try:
                    from gateway.observability.metrics import set_redis_health

                    set_redis_health(True)
                except Exception:
                    pass
                log.info("redis_rate_limit_recovered")
                await _emit_rate_limit_event(
                    "rate_limit_recovered",
                    request_id=_SYSTEM_REQUEST_ID,
                    redis_error_class=None,
                )
        except (RedisConnectionError, RedisTimeoutError, Exception) as exc:
            error_class = type(exc).__name__
            if not _redis_degraded:
                # healthy→fail transition
                _set_degraded(True)
                # F-009: update health gauge (pure addition — R2).
                try:
                    from gateway.observability.metrics import set_redis_health

                    set_redis_health(False)
                except Exception:
                    pass
                log.warning(
                    "redis_rate_limit_degraded",
                    redis_error_class=error_class,
                )
                await _emit_rate_limit_event(
                    "rate_limit_degraded",
                    request_id=_SYSTEM_REQUEST_ID,
                    redis_error_class=error_class,
                    redis_error_module=type(exc).__module__[:128],
                )


async def _ping_redis() -> None:
    """Ping Redis with a socket timeout. Raises on failure."""
    if _pool is None:
        raise RedisConnectionError("pool not initialised")
    client = AsyncRedis(connection_pool=_pool)
    try:
        await asyncio.wait_for(client.ping(), timeout=_HEALTH_PING_TIMEOUT_S)
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Rate-limit event emit (mirrors emit_routing_decision pattern)
# ---------------------------------------------------------------------------


async def _emit_rate_limit_event(
    event_type: str,
    *,
    request_id: str,
    tenant_id: str | None = None,
    team_id: str | None = None,
    project_id: str | None = None,
    agent_id: str | None = None,
    redis_error_class: str | None = None,
    redis_error_module: str | None = None,
) -> None:
    """Emit a rate_limit_degraded / rate_limit_recovered / rate_limit_redis_error event.

    Best-effort: exceptions are caught and logged at ERROR level. If Redis is down
    this emit will also fail — the structlog line above is the durable fallback.

    IDs convention (ADR-0011 §7):
      - degraded/redis_error with in-request context: real four IDs.
      - degraded/recovered from health loop: WILDCARD_UUID + agent_id='rate-limiter'.

    redis_error_class: type(exc).__name__ (never str(exc) — may contain credentials).
    redis_error_module: type(exc).__module__ bounded [:128].
    """
    # Import lazily to avoid circular imports at module level.
    from gateway.middleware.audit import emit_rate_limit_event

    try:
        await emit_rate_limit_event(
            event_type,
            request_id=request_id,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            redis_error_class=redis_error_class,
            redis_error_module=redis_error_module,
        )
    except Exception:
        log.error(
            "rate_limit_event_emit_failed",
            event_type=event_type,
            request_id=request_id,
        )


# ---------------------------------------------------------------------------
# Lifecycle: init / shutdown
# ---------------------------------------------------------------------------


async def init(settings: GatewaySettings) -> None:
    """Initialise the Redis connection pool and start the health-loop task.

    Called from _lifespan startup. Idempotent: subsequent calls are no-ops if
    the pool is already initialised.

    Failure mode γ: if Redis is unreachable at startup we do NOT raise — the
    health loop will detect the outage and set _redis_degraded=True so the
    rate limiter falls back to in-process.
    """
    global _pool, _health_task

    if _pool is not None:
        return  # already initialised

    log.info("redis_pool_init", redis_url_scheme=settings.redis_url.split("://")[0])

    _pool = ConnectionPool.from_url(
        settings.redis_url,
        max_connections=settings.redis_pool_size,
        socket_connect_timeout=settings.redis_connection_timeout,
        socket_timeout=1.0,  # R10: 1 s socket read/write timeout
        decode_responses=True,
    )

    # Perform an initial connectivity check to set the degraded flag eagerly.
    try:
        client = AsyncRedis(connection_pool=_pool)
        await asyncio.wait_for(client.ping(), timeout=settings.redis_connection_timeout)
        await client.aclose()
        log.info("redis_pool_ready")
        # F-009: set health gauge to healthy on successful startup ping (R2).
        try:
            from gateway.observability.metrics import set_redis_health

            set_redis_health(True)
        except Exception:
            pass
    except Exception as exc:
        error_class = type(exc).__name__
        _set_degraded(True)
        # F-009: set health gauge to degraded on startup failure (R2).
        try:
            from gateway.observability.metrics import set_redis_health

            set_redis_health(False)
        except Exception:
            pass
        log.warning(
            "redis_unavailable_at_startup_using_fallback",
            redis_error_class=error_class,
        )

    # Start the background health loop regardless of initial connectivity.
    _health_task = asyncio.create_task(_health_loop(), name="redis_health_loop")
    log.info("redis_health_loop_started")


async def shutdown() -> None:
    """Cancel the health task and close the connection pool.

    Called from _lifespan teardown. Safe to call even if init() was never called.
    """
    global _pool, _health_task

    if _health_task is not None:
        _health_task.cancel()
        try:
            await _health_task
        except asyncio.CancelledError:
            pass
        _health_task = None

    if _pool is not None:
        await _pool.aclose()
        _pool = None

    log.info("redis_pool_closed")


def _reset_for_testing() -> None:
    """Reset all module-level state (test helper only). NOT for production use."""
    global _pool, _health_task, _redis_degraded
    _pool = None
    _health_task = None
    _redis_degraded = False
