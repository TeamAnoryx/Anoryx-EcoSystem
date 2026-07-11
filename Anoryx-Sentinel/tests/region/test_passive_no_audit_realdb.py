"""F-022 H1 — real-DB proof that a passive region writes NO events_audit_log row.

DB-GATED (skips without DATABASE_URL). This is the acceptance-criteria test from
docs/followups/f-022-passive-readonly-enforcement.md: against a REAL Postgres, a
governed request to a `passive` region is refused 503 and the `events_audit_log`
row count is UNCHANGED — proving the hash chain cannot fork on a standby.

Lives outside tests/gateway/ deliberately: that package's autouse fixtures pin
DATABASE_URL to a fake host and mock the persistence engine, which would defeat a
real-DB assertion.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

pytestmark = pytest.mark.asyncio

_HEADERS = {
    "X-Anoryx-Tenant-Id": "11111111-1111-1111-1111-111111111111",
    "X-Anoryx-Team-Id": "22222222-2222-2222-2222-222222222222",
    "X-Anoryx-Project-Id": "33333333-3333-3333-3333-333333333333",
    "X-Anoryx-Agent-Id": "test-agent",
    "Content-Type": "application/json",
}
_BODY = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}


def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


async def _dispose_engines() -> None:
    """Null + dispose the persistence engine singletons (this package has no
    autouse reset fixture, so we clean up ourselves to avoid cross-test leaks)."""
    import persistence.database as _db

    for engine_attr, factory_attr in (
        ("_app_engine", "_app_session_factory"),
        ("_privileged_engine", "_privileged_session_factory"),
    ):
        engine = getattr(_db, engine_attr, None)
        if engine is not None:
            try:
                await engine.dispose()
            except Exception:
                pass
        setattr(_db, engine_attr, None)
        setattr(_db, factory_attr, None)


async def _count_audit_rows() -> int:
    from persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        result = await session.execute(text("SELECT count(*) FROM events_audit_log"))
        return int(result.scalar_one())


async def test_passive_region_writes_no_audit_row_realdb(monkeypatch):
    if not _db_available():
        pytest.skip("DATABASE_URL not set — skipping real-DB passive-region test")

    # Isolate provider config (CI may inject a half-set of AWS vars) and pin the
    # region to passive.
    for var in ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://fake-upstream")
    monkeypatch.setenv("SENTINEL_REGION_ROLE", "passive")

    from gateway.config import _reset_settings

    await _dispose_engines()
    _reset_settings()
    try:
        from gateway.main import create_app

        app = create_app()

        before = await _count_audit_rows()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post("/v1/chat/completions", headers=_HEADERS, json=_BODY)
        after = await _count_audit_rows()
    finally:
        await _dispose_engines()
        _reset_settings()

    assert resp.status_code == 503
    assert resp.json()["error_code"] == "region_passive_standby"
    # THE acceptance assertion: the passive region wrote NO audit row to the real
    # events_audit_log — so its per-DB sequence + hash chain are untouched and
    # cannot fork on failover.
    assert after == before
