"""In-process rate limiter (ADR-0006 pipeline step 6, Decision 5).

Phase 0: in-process sliding-window counter per (virtual_key_id, tenant_id).
Rate limit is keyed NEVER on IP/X-Forwarded-For (threat #5: IP spoofing is
immaterial — the limiter only sees the authenticated key and resolved tenant).

Two components:
  1. Request-rate limiter — sliding-window, dual-scope (per-key AND per-tenant).
     Both windows must permit the request; stricter of the two governs.
     Config: RATE_LIMIT_RPM (default 600/60s), RATE_LIMIT_BURST.
  2. Concurrent-stream counter — per-resolved-tenant_id integer of open SSE
     streams. Capped at MAX_CONCURRENT_STREAMS_PER_TENANT (default 20).
     Decremented on stream close/complete/error/disconnect (guaranteed via
     asynccontextmanager finally, not middleware dispatch path).

MED-1 (TOCTOU fix): check_rate_limit() now ATOMICALLY increments the per-tenant
stream counter at admission time when is_stream=True. Previously the function
only READ the counter (admitting the request) while stream_slot() incremented it
later, creating a TOCTOU window where concurrent requests could bypass the cap.
The fix: increment UNDER the lock at admission; stream_slot() no longer
increments (it only decrements on exit). If admission fails the counter is not
incremented and stream_slot() is not entered.

LOW-1: After evicting stale entries from a window, if the window becomes empty
the dict entry is pruned to prevent unbounded memory growth from distinct
key/tenant strings that are no longer active. Similarly, stream counter entries
at 0 are pruned after decrement.

Per-worker honest limitation (ADR-0006 Decision 5, Deferred):
  In-process state is per-worker. With N uvicorn workers/replicas the effective
  global limit is N × RATE_LIMIT_RPM and the concurrent-stream cap is
  per-worker, not truly per-tenant-global. Documented and accepted for Phase 0.
  Redis-backed distributed rate limiting deferred to F-010.

The X-RateLimit-* response headers REPORT this worker's view of the
limit/remaining/reset; they are reporting, not the control mechanism.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog

from gateway.config import get_settings
from gateway.exceptions import GatewayError

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Sliding-window state — module-level singletons (per-process)
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


def _evict_old_entries(window: deque[float], now: float, window_seconds: float = 60.0) -> None:
    """Remove entries older than window_seconds from the sliding window."""
    cutoff = now - window_seconds
    while window and window[0] < cutoff:
        window.popleft()


async def check_rate_limit(
    virtual_key_id: str,
    tenant_id: str,
    is_stream: bool = False,
) -> tuple[int, int, int]:
    """Check and record a request against the rate limits.

    Returns (limit, remaining, reset_epoch_seconds) for the governing window.
    Raises GatewayError("rate_limit_exceeded") with retry_after set if over limit.

    MED-1: When is_stream=True and the request would be admitted, this function
    ATOMICALLY increments the per-tenant stream counter under the lock so that
    concurrent callers cannot both pass the check before either has incremented.
    stream_slot() is responsible for decrementing on stream close.

    MUST be called AFTER auth has resolved virtual_key_id and tenant_id.
    NEVER keyed on IP address.
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


@asynccontextmanager
async def stream_slot(tenant_id: str) -> AsyncIterator[None]:
    """Context manager that holds a concurrent-stream slot for tenant_id.

    MED-1: The counter was already incremented atomically by check_rate_limit()
    at admission time. This context manager only DECREMENTS on exit — it does
    NOT increment on entry (that would double-count and undo the MED-1 fix).

    Decrement is guaranteed via finally (close / complete / error / disconnect
    all decrement, ADR-0006 Decision 5, threat #4).

    LOW-1: After decrement, if the counter reaches 0 the dict entry is pruned.
    """
    try:
        yield
    finally:
        async with _lock:
            count = _stream_counters.get(tenant_id, 1)
            new_count = max(0, count - 1)
            if new_count == 0:
                # LOW-1: prune zero-counter entries to prevent unbounded dict growth.
                _stream_counters.pop(tenant_id, None)
            else:
                _stream_counters[tenant_id] = new_count


def _prune_empty_windows() -> None:
    """Evict stale entries and prune empty sliding-window deques (LOW-1 helper).

    Called under _lock from check_rate_limit() after the current key/tenant
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
    _key_windows.clear()
    _tenant_windows.clear()
    _stream_counters.clear()
