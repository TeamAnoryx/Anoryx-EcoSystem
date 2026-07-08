"""TTL-cached ProviderKeySource wrapper — the "runtime fetch + rotation" seam.

Rotation here is BOUNDED-LAG, not push-based: `invalidate()` forces the next
fetch to bypass the cache, but nothing pushes a rotated key into a live
gateway process from outside it (that would need a new admin HTTP endpoint —
out of scope, see docs/adr/0033). The periodic background refresh in
gateway/main.py re-fetches every `ttl_seconds` regardless of invalidation, so
a credential rotated in Vault/KMS propagates within one TTL window even
without an operator calling `sentinel-keyvault rotate`.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict

from gateway.keyvault.base import ProviderCredentials, ProviderKeySource


class CachedKeySource:
    """Wraps a ProviderKeySource with a per-provider TTL cache."""

    def __init__(
        self,
        source: ProviderKeySource,
        *,
        ttl_seconds: float = 300.0,
        clock: "callable[[], float]" = time.monotonic,
    ) -> None:
        self._source = source
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: dict[str, tuple[float, ProviderCredentials]] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        cached = self._entries.get(provider)
        if cached is not None:
            fetched_at, creds = cached
            if self._clock() - fetched_at < self._ttl_seconds:
                return creds

        async with self._locks[provider]:
            # Re-check after acquiring the lock — another task may have
            # already refreshed this provider while we were waiting.
            cached = self._entries.get(provider)
            if cached is not None:
                fetched_at, creds = cached
                if self._clock() - fetched_at < self._ttl_seconds:
                    return creds

            creds = await self._source.fetch_credentials(provider)
            self._entries[provider] = (self._clock(), creds)
            return creds

    def invalidate(self, provider: str | None = None) -> None:
        """Force the next fetch(es) to bypass the cache (rotation trigger)."""
        if provider is None:
            self._entries.clear()
        else:
            self._entries.pop(provider, None)
