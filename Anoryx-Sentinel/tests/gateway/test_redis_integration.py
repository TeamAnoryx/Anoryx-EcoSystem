"""Real-Redis integration tests for check_rate_limit() (F-009, ADR-0011).

These tests connect to a live Redis instance at REDIS_URL (default
redis://localhost:6379/0). If Redis is unreachable the entire module
is skipped automatically so the suite stays green in environments
without Redis.

Run selectively:
    pytest tests/gateway/test_redis_integration.py -v -m redis_integration

Run as part of the full suite (skips cleanly if Redis absent):
    pytest

Prerequisites:
    docker compose up -d redis
    SENTINEL_PROVISION_APP_ROLE=1 PYTHONPATH=src pytest tests/gateway/test_redis_integration.py -q
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

# ---------------------------------------------------------------------------
# Module-level reachability check — skip the whole file if Redis is down
# ---------------------------------------------------------------------------

_REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

pytestmark = pytest.mark.redis_integration


def _redis_reachable() -> bool:
    """Synchronous connectivity probe used at collection time."""
    try:
        import redis as sync_redis

        client = sync_redis.from_url(_REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        client.close()
        return True
    except Exception:
        return False


_REDIS_AVAILABLE = _redis_reachable()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def redis_url() -> str:
    if not _REDIS_AVAILABLE:
        pytest.skip("Redis not reachable — skipping real-Redis integration tests")
    return _REDIS_URL


@pytest.fixture()
async def redis_client(redis_url: str):
    """Yield a connected redis.asyncio client; flush test keys after each test."""
    client = aioredis.from_url(
        redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )
    yield client
    await client.aclose()


@pytest.fixture()
def unique_key_id() -> str:
    """Globally unique virtual_key_id for test isolation (no cross-test pollution)."""
    return f"integration-vk-{uuid.uuid4().hex}"


@pytest.fixture()
def unique_tenant_id() -> str:
    """Globally unique tenant_id for test isolation."""
    return f"integration-tenant-{uuid.uuid4().hex}"


@pytest.fixture(autouse=True)
def _setup_gateway_env(monkeypatch, redis_url):
    """Ensure required gateway env vars are set for GatewaySettings validation."""
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://fake-upstream")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/db")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://fake/appdb")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-secret-for-hmac-integration")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("REDIS_URL", redis_url)
    # Low RPM so tests can trigger rejection quickly without 600 requests.
    monkeypatch.setenv("RATE_LIMIT_RPM", "5")
    monkeypatch.setenv("RATE_LIMIT_BURST", "10")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")

    from gateway.config import _reset_settings

    _reset_settings()
    yield
    _reset_settings()


@pytest.fixture(autouse=True)
def _reset_redis_module():
    """Reset redis_client module state before each test."""
    import gateway.redis_client as rc

    rc._reset_for_testing()
    yield
    # Best-effort teardown — pool may already be closed.
    try:
        asyncio.get_event_loop().run_until_complete(rc.shutdown())
    except Exception:
        pass
    rc._reset_for_testing()


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Clear in-process rate-limit state (legacy path) before each test."""
    from gateway.middleware.rate_limit import reset_state_for_testing

    reset_state_for_testing()
    yield
    reset_state_for_testing()


# ---------------------------------------------------------------------------
# Helper: initialise redis_client pool pointing at real Redis
# ---------------------------------------------------------------------------


async def _init_pool(redis_url: str) -> None:
    """Initialise the gateway redis_client pool against the live Redis."""
    from gateway.config import get_settings
    import gateway.redis_client as rc

    settings = get_settings()
    await rc.init(settings)
    # Verify the pool actually connected (not degraded).
    if rc.is_degraded():
        pytest.skip("Redis pool initialised but immediately degraded — Redis not ready")


# ---------------------------------------------------------------------------
# (a) Admission under limit
# ---------------------------------------------------------------------------


async def test_admission_under_limit(redis_url, unique_key_id, unique_tenant_id):
    """check_rate_limit() admits requests below the RPM ceiling."""
    await _init_pool(redis_url)

    from gateway.middleware.rate_limit import check_rate_limit

    limit, remaining, reset = await check_rate_limit(unique_key_id, unique_tenant_id)

    assert limit == 5, f"Expected limit=5 (RPM env), got {limit}"
    assert remaining == 4, f"Expected remaining=4 after 1 request, got {remaining}"
    assert reset > 0, "Expected a positive reset epoch"


# ---------------------------------------------------------------------------
# (b) Rejection over limit
# ---------------------------------------------------------------------------


async def test_rejection_over_limit(redis_url, unique_key_id, unique_tenant_id):
    """check_rate_limit() raises GatewayError(rate_limit_exceeded) when over RPM."""
    await _init_pool(redis_url)

    from gateway.exceptions import GatewayError
    from gateway.middleware.rate_limit import check_rate_limit

    # Exhaust the 5-RPM window.
    for _ in range(5):
        await check_rate_limit(unique_key_id, unique_tenant_id)

    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit(unique_key_id, unique_tenant_id)

    assert exc_info.value.error_code == "rate_limit_exceeded"
    assert exc_info.value.retry_after is not None
    assert exc_info.value.retry_after > 0


# ---------------------------------------------------------------------------
# (c) Sorted-set keys appear in Redis after admission
# ---------------------------------------------------------------------------


async def test_sorted_set_keys_exist_in_redis(redis_url, redis_client, unique_key_id, unique_tenant_id):
    """After admission, sentinel:rl:vk:* and sentinel:rl:tenant:* ZSETs exist in Redis."""
    await _init_pool(redis_url)

    from gateway.middleware.rate_limit import check_rate_limit

    await check_rate_limit(unique_key_id, unique_tenant_id)

    vk_key = f"sentinel:rl:vk:{unique_key_id}"
    tenant_key = f"sentinel:rl:tenant:{unique_tenant_id}"

    vk_count = await redis_client.zcard(vk_key)
    tenant_count = await redis_client.zcard(tenant_key)

    assert vk_count >= 1, f"Expected ZSET {vk_key} to exist with at least 1 member, got {vk_count}"
    assert tenant_count >= 1, (
        f"Expected ZSET {tenant_key} to exist with at least 1 member, got {tenant_count}"
    )

    # Members use the {timestamp_ms}:{uuid4hex} format (D1).
    members = await redis_client.zrange(vk_key, 0, -1)
    assert len(members) >= 1
    # Each member has the form "<int>:<hex>" per _redis_admit_tier.
    first_member = members[0]
    parts = first_member.split(":", 1)
    assert len(parts) == 2, f"Member format unexpected: {first_member!r}"
    assert parts[0].isdigit(), f"Expected timestamp-ms prefix to be digits, got {parts[0]!r}"

    # Cleanup test keys so they do not affect other test runs.
    await redis_client.delete(vk_key, tenant_key)


# ---------------------------------------------------------------------------
# (d) Recovery path: degrade then heal
# ---------------------------------------------------------------------------


async def test_degraded_then_recovered(redis_url, unique_key_id, unique_tenant_id, monkeypatch):
    """Setting _redis_degraded=True forces the legacy fallback path; clearing it
    returns to the Redis primary path.

    This validates the γ edge-detector contract (ADR-0011 D2) end-to-end:
    the degraded flag is the single switch between the two admission paths.
    """
    await _init_pool(redis_url)

    import gateway.redis_client as rc
    from gateway.middleware.rate_limit import check_rate_limit

    # --- Phase 1: simulate degraded (force legacy path) ---
    rc._set_degraded(True)
    assert rc.is_degraded(), "Expected degraded flag to be True"

    # Legacy path still admits requests (in-process sliding window).
    limit, remaining, reset = await check_rate_limit(unique_key_id, unique_tenant_id)
    assert limit == 5
    assert remaining == 4

    # Verify the Redis primary ZSETs were NOT written (legacy path bypasses Redis).
    async with aioredis.from_url(redis_url, decode_responses=True) as probe:
        vk_count = await probe.zcard(f"sentinel:rl:vk:{unique_key_id}")
        assert vk_count == 0, (
            f"Legacy path must not write to Redis; found {vk_count} entries in vk ZSET"
        )

    # --- Phase 2: heal (restore Redis primary path) ---
    rc._set_degraded(False)
    assert not rc.is_degraded(), "Expected degraded flag to be False after recovery"

    # Use a new unique key to avoid stale legacy-path window counts from phase 1.
    recovered_key = f"recovered-vk-{uuid.uuid4().hex}"
    recovered_tenant = f"recovered-tenant-{uuid.uuid4().hex}"

    limit2, remaining2, reset2 = await check_rate_limit(recovered_key, recovered_tenant)
    assert limit2 == 5
    assert remaining2 == 4

    # Redis primary ZSETs must now exist.
    async with aioredis.from_url(redis_url, decode_responses=True) as probe:
        vk_count2 = await probe.zcard(f"sentinel:rl:vk:{recovered_key}")
        assert vk_count2 >= 1, "After recovery Redis primary path must write to ZSET"
        # Cleanup.
        await probe.delete(
            f"sentinel:rl:vk:{recovered_key}",
            f"sentinel:rl:tenant:{recovered_tenant}",
        )
