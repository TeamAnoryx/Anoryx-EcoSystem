"""Per-tenant pattern loader with hot-reload TTL cache (F-028, ADR-0034).

Loads a tenant's active custom patterns from tenant_custom_pii_patterns,
compiles them, and caches the compiled set per tenant for a short TTL. A
pattern change (add/revoke) lands in a live gateway within one TTL window —
bounded-lag hot-reload, same rationale as F-027's keyvault cache. The cache is
process-local; each gateway process reloads independently.

Fail-safe posture: a DB error while loading raises, which the CustomPiiHook
turns into a fail-safe BLOCK (CLAUDE.md #5) — a tenant who HAS custom PII
patterns must never have content pass uninspected because the pattern store
was briefly unreachable. A tenant with ZERO patterns caches an empty list and
does no masking (the common, cheap path).
"""

from __future__ import annotations

import time

import structlog

from data_protection.custom_pii.engine import CompiledPattern, compile_pattern
from persistence.database import get_tenant_session
from persistence.repositories.tenant_custom_pii_pattern_repository import (
    TenantCustomPiiPatternRepository,
)

log = structlog.get_logger(__name__)


class CustomPiiPatternLoader:
    """Loads + compiles + caches per-tenant custom patterns."""

    def __init__(
        self, *, ttl_seconds: float = 30.0, clock=time.monotonic, session_factory=None
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        # session_factory is a test seam: () -> async context manager yielding a
        # session. Defaults to get_tenant_session(tenant_id) at call time.
        self._session_factory = session_factory
        self._cache: dict[str, tuple[float, list[CompiledPattern]]] = {}

    async def load(self, tenant_id: str) -> list[CompiledPattern]:
        # NO per-tenant asyncio.Lock: this loader is a PROCESS-GLOBAL singleton
        # (hook.py) that must survive across many request event loops. A Lock
        # bound to the loop that first awaited it raises "attached to a different
        # loop" when reused under a later loop. The lock only guarded against a
        # cold-cache thundering herd; a duplicate concurrent fetch is merely a
        # wasted DB read (idempotent, self-healing once cached), so we drop the
        # lock entirely rather than carry cross-loop fragility.
        cached = self._cache.get(tenant_id)
        if cached is not None and self._clock() - cached[0] < self._ttl_seconds:
            return cached[1]

        rows = await self._fetch_rows(tenant_id)
        compiled: list[CompiledPattern] = []
        for row in rows:
            try:
                compiled.append(
                    compile_pattern(row.name, row.pattern, score=row.score, action=row.action)
                )
            except Exception:  # noqa: S112 — a stored pattern that won't compile
                # (shouldn't happen — validated at write) is skipped, not fatal;
                # it simply does not contribute matches. Logged below.
                log.warning("custom_pii.stored_pattern_compile_failed", pattern_name=row.name)
                continue
        self._cache[tenant_id] = (self._clock(), compiled)
        return compiled

    async def _fetch_rows(self, tenant_id: str):
        if self._session_factory is not None:
            async with self._session_factory(tenant_id) as session:
                return await TenantCustomPiiPatternRepository(session).list_for_tenant(
                    tenant_id, active_only=True, limit=1000
                )
        async with get_tenant_session(tenant_id) as session:
            return await TenantCustomPiiPatternRepository(session).list_for_tenant(
                tenant_id, active_only=True, limit=1000
            )

    def invalidate(self, tenant_id: str | None = None) -> None:
        if tenant_id is None:
            self._cache.clear()
        else:
            self._cache.pop(tenant_id, None)
