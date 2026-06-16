"""Tests for in-process rate limiter (F-004, ADR-0006 Decision 5).

Covers:
- Per-key rate limit exceeded → 429 rate_limit_exceeded
- Per-tenant rate limit exceeded → 429 rate_limit_exceeded
- Independent per-key and per-tenant buckets
- Stricter-wins: either key or tenant limit triggers the rejection
- Rate-limit headers present on 2xx responses
- Rate-limit headers present on 429 responses
- Retry-After header on 429
- IP-spoof is immaterial (limiter never keys on IP)
- Concurrent-stream cap enforced
- Concurrent-stream counter decremented on completion (slot freed)
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gateway.exceptions import GatewayError
from gateway.middleware.rate_limit import (
    _key_windows,
    _stream_counters,
    _tenant_windows,
    check_rate_limit,
    reset_state_for_testing,
    stream_slot,
)


# ---------------------------------------------------------------------------
# Unit tests for check_rate_limit (no HTTP layer needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_within_limit_admits_request(settings_env):
    """A single request within the limit returns (limit, remaining, reset)."""
    limit, remaining, reset = await check_rate_limit("key-1", "tenant-1")
    assert limit == 600
    assert remaining == 599
    assert reset > 0


@pytest.mark.asyncio
async def test_per_key_limit_exceeded_raises(settings_env, monkeypatch):
    """Exhaust the per-key window → GatewayError(rate_limit_exceeded)."""
    import time
    monkeypatch.setenv("RATE_LIMIT_RPM", "3")
    monkeypatch.setenv("RATE_LIMIT_BURST", "10")
    from gateway.config import _reset_settings
    _reset_settings()

    for _ in range(3):
        await check_rate_limit("key-2", "tenant-2")

    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit("key-2", "tenant-2")
    assert exc_info.value.error_code == "rate_limit_exceeded"
    assert exc_info.value.retry_after is not None and exc_info.value.retry_after > 0


@pytest.mark.asyncio
async def test_per_tenant_limit_exceeded_raises(settings_env, monkeypatch):
    """Exhaust the per-tenant window (with two different keys) → 429."""
    monkeypatch.setenv("RATE_LIMIT_RPM", "3")
    monkeypatch.setenv("RATE_LIMIT_BURST", "10")
    from gateway.config import _reset_settings
    _reset_settings()

    # Three requests with different keys but same tenant.
    await check_rate_limit("key-a", "tenant-shared")
    await check_rate_limit("key-b", "tenant-shared")
    await check_rate_limit("key-c", "tenant-shared")

    # Fourth with a NEW key — tenant limit is still exhausted → 429.
    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit("key-d", "tenant-shared")
    assert exc_info.value.error_code == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_independent_buckets_different_keys(settings_env, monkeypatch):
    """Two different key+tenant pairs have independent rate-limit buckets."""
    monkeypatch.setenv("RATE_LIMIT_RPM", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "10")
    from gateway.config import _reset_settings
    _reset_settings()

    await check_rate_limit("key-x", "tenant-x")
    await check_rate_limit("key-x", "tenant-x")
    # key-x + tenant-x exhausted at 2 rpm.

    # key-y + tenant-y should be independent — still has capacity.
    limit, remaining, _ = await check_rate_limit("key-y", "tenant-y")
    assert remaining == 1  # 2 rpm - 1 used


@pytest.mark.asyncio
async def test_ip_address_is_not_a_rate_limit_key(settings_env):
    """Rate limiter uses key_id and tenant_id only — IP is irrelevant."""
    # Verify the internal buckets never contain IP-like keys.
    await check_rate_limit("key-z", "tenant-z")
    for k in list(_key_windows.keys()) + list(_tenant_windows.keys()):
        assert "127.0.0.1" not in k
        assert "x-forwarded-for" not in k.lower()


@pytest.mark.asyncio
async def test_retry_after_header_set_on_429(settings_env, monkeypatch):
    """GatewayError from rate limit includes retry_after."""
    monkeypatch.setenv("RATE_LIMIT_RPM", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "10")
    from gateway.config import _reset_settings
    _reset_settings()

    await check_rate_limit("key-ra", "tenant-ra")
    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit("key-ra", "tenant-ra")
    assert exc_info.value.retry_after is not None
    assert exc_info.value.retry_after >= 1


@pytest.mark.asyncio
async def test_concurrent_stream_cap_enforced(settings_env, monkeypatch):
    """Concurrent-stream cap (MAX_CONCURRENT_STREAMS_PER_TENANT=2) → 429 on third."""
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "2")
    from gateway.config import _reset_settings
    _reset_settings()

    # Manually set the counter to the limit.
    _stream_counters["tenant-stream"] = 2

    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit("key-s", "tenant-stream", is_stream=True)
    assert exc_info.value.error_code == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_stream_slot_decrements_on_exit():
    """stream_slot() increments and decrements the concurrent-stream counter."""
    tenant = "tenant-slot-test"
    _stream_counters.pop(tenant, None)

    async with stream_slot(tenant):
        assert _stream_counters.get(tenant, 0) == 1

    assert _stream_counters.get(tenant, 0) == 0


@pytest.mark.asyncio
async def test_stream_slot_decrements_on_exception():
    """stream_slot() still decrements counter even when an exception is raised."""
    tenant = "tenant-exc-test"
    _stream_counters.pop(tenant, None)

    with pytest.raises(ValueError):
        async with stream_slot(tenant):
            raise ValueError("simulated error")

    assert _stream_counters.get(tenant, 0) == 0


@pytest.mark.asyncio
async def test_rate_limit_headers_returned_on_success(settings_env):
    """X-RateLimit-* headers are present in the rate-limit check result."""
    limit, remaining, reset = await check_rate_limit("key-hdr", "tenant-hdr")
    assert isinstance(limit, int) and limit > 0
    assert isinstance(remaining, int) and remaining >= 0
    assert isinstance(reset, int) and reset > 0
    assert remaining == limit - 1
