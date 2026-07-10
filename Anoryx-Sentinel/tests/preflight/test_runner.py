"""Unit tests for the F-031 runner — DB checks SKIP cleanly offline."""

from __future__ import annotations

import pytest

from preflight.result import STATUS_SKIP
from preflight.runner import DB_CHECKS, run_all_checks, summarize


@pytest.mark.asyncio
async def test_offline_run_skips_db_checks(monkeypatch):
    # No DATABASE_URL -> the two DB checks report SKIP, not crash.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    results = await run_all_checks()
    by_name = {r.name: r for r in results}
    for db_check in DB_CHECKS:
        assert by_name[db_check].status == STATUS_SKIP


@pytest.mark.asyncio
async def test_skip_excludes_named_checks(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    results = await run_all_checks(skip=frozenset({"secrets-vaulted"}))
    assert "secrets-vaulted" not in {r.name for r in results}


@pytest.mark.asyncio
async def test_summarize_shape(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    results = await run_all_checks()
    summary = summarize(results)
    assert "gate_passed" in summary
    assert "worst_status" in summary
    assert isinstance(summary["checks"], list)
    assert all({"name", "status", "detail"} <= set(c) for c in summary["checks"])
