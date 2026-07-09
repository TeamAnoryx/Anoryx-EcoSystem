"""Unit tests for CustomPiiPatternLoader TTL cache + compile (F-028) — no DB.

Subclasses the loader to override _fetch_rows with canned rows + a call
counter, so the cache/hot-reload/compile logic is tested independently of
Postgres."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from data_protection.custom_pii.loader import CustomPiiPatternLoader


@dataclass
class _Row:
    name: str
    pattern: str
    score: float = 0.85
    action: str | None = None


class _ManualClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class _FakeLoader(CustomPiiPatternLoader):
    def __init__(self, rows, **kw):
        super().__init__(**kw)
        self._rows = rows
        self.fetch_calls = 0

    async def _fetch_rows(self, tenant_id: str):
        self.fetch_calls += 1
        return self._rows


@pytest.mark.asyncio
async def test_compiles_rows_into_patterns():
    loader = _FakeLoader([_Row("EMPLOYEE_ID", r"EMP-\d{6}")])
    patterns = await loader.load("t1")
    assert len(patterns) == 1
    assert patterns[0].name == "EMPLOYEE_ID"


@pytest.mark.asyncio
async def test_second_load_within_ttl_is_cached():
    clock = _ManualClock()
    loader = _FakeLoader([_Row("E", r"E-\d")], ttl_seconds=100.0, clock=clock)
    await loader.load("t1")
    clock.now += 10
    await loader.load("t1")
    assert loader.fetch_calls == 1


@pytest.mark.asyncio
async def test_load_after_ttl_refetches():
    clock = _ManualClock()
    loader = _FakeLoader([_Row("E", r"E-\d")], ttl_seconds=10.0, clock=clock)
    await loader.load("t1")
    clock.now += 11
    await loader.load("t1")
    assert loader.fetch_calls == 2


@pytest.mark.asyncio
async def test_invalidate_forces_refetch():
    loader = _FakeLoader([_Row("E", r"E-\d")], ttl_seconds=1000.0)
    await loader.load("t1")
    loader.invalidate("t1")
    await loader.load("t1")
    assert loader.fetch_calls == 2


@pytest.mark.asyncio
async def test_uncompilable_stored_row_is_skipped_not_fatal():
    loader = _FakeLoader([_Row("BAD", r"E-(\d"), _Row("GOOD", r"G-\d")])
    patterns = await loader.load("t1")
    assert [p.name for p in patterns] == ["GOOD"]


@pytest.mark.asyncio
async def test_per_tenant_isolation_in_cache():
    clock = _ManualClock()
    loader = _FakeLoader([_Row("E", r"E-\d")], ttl_seconds=1000.0, clock=clock)
    await loader.load("t1")
    await loader.load("t2")
    assert loader.fetch_calls == 2  # each tenant fetched independently
