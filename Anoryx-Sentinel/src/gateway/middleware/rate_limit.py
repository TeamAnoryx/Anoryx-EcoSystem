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
     contextlib.contextmanager finally, not middleware dispatch path).

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

        # --- Concurrent-stream cap (for stream: true) ---
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

        # Admit the request — record the timestamp in both windows.
        key_window.append(now)
        tenant_window.append(now)

        remaining = max(0, rpm - len(key_window))
        reset_epoch = epoch_now + int(window_seconds)
        return rpm, remaining, reset_epoch


@asynccontextmanager
async def stream_slot(tenant_id: str) -> AsyncIterator[None]:
    """Context manager that holds a concurrent-stream slot for tenant_id.

    Increments the counter on entry and decrements on exit — guaranteed via
    finally (close / complete / error / disconnect all decrement, ADR-0006
    Decision 5, threat #4).
    """
    async with _lock:
        _stream_counters[tenant_id] = _stream_counters.get(tenant_id, 0) + 1
    try:
        yield
    finally:
        async with _lock:
            count = _stream_counters.get(tenant_id, 1)
            _stream_counters[tenant_id] = max(0, count - 1)


def reset_state_for_testing() -> None:
    """Clear all in-process rate-limit state (test helper only)."""
    _key_windows.clear()
    _tenant_windows.clear()
    _stream_counters.clear()
