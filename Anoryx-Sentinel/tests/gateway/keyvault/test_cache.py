"""Unit tests for CachedKeySource (F-027) — injected clock, no real sleep."""

from __future__ import annotations

import asyncio

import pytest

from gateway.keyvault.base import ProviderCredentials
from gateway.keyvault.cache import CachedKeySource
from gateway.keyvault.exceptions import KeyFetchError


class _CountingSource:
    def __init__(self):
        self.calls: list[str] = []

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        self.calls.append(provider)
        return ProviderCredentials(provider=provider, values={"api_key": f"key-{len(self.calls)}"})


class _ManualClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_second_fetch_within_ttl_is_cached():
    source = _CountingSource()
    clock = _ManualClock()
    cache = CachedKeySource(source, ttl_seconds=100.0, clock=clock)

    first = await cache.fetch_credentials("anthropic")
    clock.now += 10
    second = await cache.fetch_credentials("anthropic")

    assert first == second
    assert source.calls == ["anthropic"]  # only ONE real fetch


@pytest.mark.asyncio
async def test_fetch_after_ttl_expiry_refetches():
    source = _CountingSource()
    clock = _ManualClock()
    cache = CachedKeySource(source, ttl_seconds=10.0, clock=clock)

    await cache.fetch_credentials("anthropic")
    clock.now += 11  # past TTL
    await cache.fetch_credentials("anthropic")

    assert source.calls == ["anthropic", "anthropic"]


@pytest.mark.asyncio
async def test_invalidate_single_provider_forces_refetch():
    source = _CountingSource()
    clock = _ManualClock()
    cache = CachedKeySource(source, ttl_seconds=1000.0, clock=clock)

    await cache.fetch_credentials("anthropic")
    await cache.fetch_credentials("bedrock")
    cache.invalidate("anthropic")

    await cache.fetch_credentials("anthropic")
    await cache.fetch_credentials("bedrock")

    assert source.calls == ["anthropic", "bedrock", "anthropic"]


@pytest.mark.asyncio
async def test_invalidate_all_forces_refetch_of_every_provider():
    source = _CountingSource()
    clock = _ManualClock()
    cache = CachedKeySource(source, ttl_seconds=1000.0, clock=clock)

    await cache.fetch_credentials("anthropic")
    await cache.fetch_credentials("bedrock")
    cache.invalidate()

    await cache.fetch_credentials("anthropic")
    await cache.fetch_credentials("bedrock")

    assert source.calls == ["anthropic", "bedrock", "anthropic", "bedrock"]


@pytest.mark.asyncio
async def test_concurrent_fetches_on_cold_cache_do_not_thundering_herd():
    source = _CountingSource()
    clock = _ManualClock()
    cache = CachedKeySource(source, ttl_seconds=1000.0, clock=clock)

    results = await asyncio.gather(*(cache.fetch_credentials("anthropic") for _ in range(10)))

    assert len(source.calls) == 1  # lock prevented duplicate concurrent fetches
    assert all(r == results[0] for r in results)


@pytest.mark.asyncio
async def test_source_error_propagates_and_is_not_cached():
    class _FlakySource:
        def __init__(self):
            self.attempts = 0

        async def fetch_credentials(self, provider: str) -> ProviderCredentials:
            self.attempts += 1
            if self.attempts == 1:
                raise KeyFetchError("transient")
            return ProviderCredentials(provider=provider, values={"api_key": "ok"})

    source = _FlakySource()
    cache = CachedKeySource(source, ttl_seconds=1000.0)

    with pytest.raises(KeyFetchError):
        await cache.fetch_credentials("anthropic")

    creds = await cache.fetch_credentials("anthropic")
    assert creds.values == {"api_key": "ok"}
    assert source.attempts == 2
