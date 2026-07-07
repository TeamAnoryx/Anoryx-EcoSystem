"""Unit tests for the F-023 policy-eval cache (ADR-0029).

Fail-safe contract under test: any Redis unavailability (degraded flag,
connection error, timeout, decode error) must behave as a CACHE MISS — never
as a synthesized decision — and a write/invalidate failure must never raise.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from policy import eval_cache
from policy.enforcement import ModelAllow, ModelDeny, RequestScope

SCOPE = RequestScope(tenant_id="t1", team_id="team1", project_id="proj1", agent_id="agent1")


class _FakeRedis:
    """In-memory stand-in for the async Redis client (get/set/incr/aclose)."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def set(self, key: str, value: str, ex=None):
        self.store[key] = value

    async def incr(self, key: str) -> int:
        current = int(self.store.get(key, "0")) + 1
        self.store[key] = str(current)
        return current

    async def aclose(self):
        pass


def _not_degraded():
    return patch("policy.eval_cache.redis_client.is_degraded", return_value=False)


@pytest.mark.asyncio
async def test_cache_miss_when_empty():
    fake = _FakeRedis()
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        decision, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision is None
    assert version == 0


@pytest.mark.asyncio
async def test_write_then_read_hits_allow():
    fake = _FakeRedis()
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        _, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
        await eval_cache.set_cached_decision(
            SCOPE, "gpt-4", ModelAllow(policy_id="pol-1"), version, ttl_seconds=5.0
        )
        decision, _ = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision == ModelAllow(policy_id="pol-1")


@pytest.mark.asyncio
async def test_write_then_read_hits_deny():
    fake = _FakeRedis()
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        _, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
        deny = ModelDeny(policy_id="pol-2", reason="model_denied")
        await eval_cache.set_cached_decision(SCOPE, "gpt-4", deny, version, ttl_seconds=5.0)
        decision, _ = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision == deny


@pytest.mark.asyncio
async def test_invalidate_orphans_previous_version():
    fake = _FakeRedis()
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        _, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
        await eval_cache.set_cached_decision(
            SCOPE, "gpt-4", ModelAllow(policy_id="pol-1"), version, ttl_seconds=5.0
        )
        # A policy write bumps the tenant's version.
        await eval_cache.invalidate_tenant(SCOPE.tenant_id)
        decision, new_version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")

    assert decision is None  # old key is orphaned, not read under the new version
    assert new_version != version


@pytest.mark.asyncio
async def test_different_tenant_not_invalidated():
    fake = _FakeRedis()
    other_scope = RequestScope(
        tenant_id="t2", team_id="team1", project_id="proj1", agent_id="agent1"
    )
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        _, v1 = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
        await eval_cache.set_cached_decision(
            SCOPE, "gpt-4", ModelAllow(policy_id="pol-1"), v1, ttl_seconds=5.0
        )
        await eval_cache.invalidate_tenant(other_scope.tenant_id)
        decision, _ = await eval_cache.get_cached_decision(SCOPE, "gpt-4")

    assert decision == ModelAllow(policy_id="pol-1")


@pytest.mark.asyncio
async def test_degraded_short_circuits_to_miss_without_redis_call():
    get_client = AsyncMock()
    with (
        patch("policy.eval_cache.redis_client.is_degraded", return_value=True),
        patch("policy.eval_cache.redis_client.get_client", new=get_client),
    ):
        decision, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
        await eval_cache.set_cached_decision(SCOPE, "gpt-4", ModelAllow(), version, ttl_seconds=5.0)
        await eval_cache.invalidate_tenant(SCOPE.tenant_id)

    assert decision is None
    get_client.assert_not_called()


@pytest.mark.asyncio
async def test_connection_error_on_read_is_a_miss_not_a_raise():
    with (
        _not_degraded(),
        patch(
            "policy.eval_cache.redis_client.get_client",
            new=AsyncMock(side_effect=RedisConnectionError("down")),
        ),
    ):
        decision, version = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision is None
    assert version == 0


@pytest.mark.asyncio
async def test_write_error_is_swallowed_not_raised():
    class _FailingRedis(_FakeRedis):
        async def set(self, key, value, ex=None):
            raise RedisConnectionError("down")

    with (
        _not_degraded(),
        patch(
            "policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=_FailingRedis())
        ),
    ):
        # Must not raise.
        await eval_cache.set_cached_decision(SCOPE, "gpt-4", ModelAllow(), 0, ttl_seconds=5.0)


@pytest.mark.asyncio
async def test_invalidate_error_is_swallowed_not_raised():
    class _FailingRedis(_FakeRedis):
        async def incr(self, key):
            raise RedisConnectionError("down")

    with (
        _not_degraded(),
        patch(
            "policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=_FailingRedis())
        ),
    ):
        # Must not raise.
        await eval_cache.invalidate_tenant(SCOPE.tenant_id)


@pytest.mark.asyncio
async def test_decode_error_on_corrupt_payload_is_a_miss():
    fake = _FakeRedis()
    fake.store["sentinel:polcache:v:t1"] = "0"
    fake.store["sentinel:polcache:d:t1:0:team1:proj1:agent1:gpt-4"] = "not-json"
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        decision, _ = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision is None


@pytest.mark.asyncio
async def test_ttl_zero_disables_write():
    fake = _FakeRedis()
    with (
        _not_degraded(),
        patch("policy.eval_cache.redis_client.get_client", new=AsyncMock(return_value=fake)),
    ):
        await eval_cache.set_cached_decision(SCOPE, "gpt-4", ModelAllow(), 0, ttl_seconds=0)
        decision, _ = await eval_cache.get_cached_decision(SCOPE, "gpt-4")
    assert decision is None
    assert fake.store == {}
