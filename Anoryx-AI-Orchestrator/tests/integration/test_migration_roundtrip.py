"""Migration reversibility on a real Postgres (O-003, ADR-0003).

The Orchestrator's first migration must apply clean to head AND reverse cleanly. Proves a
non-stubbed round-trip: upgrade head → tables present → downgrade base → tables gone →
upgrade head → tables present again. Re-provisions the orchestrator_app password after the
final upgrade (downgrade base drops the passwordless role) so later tests still connect.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

_TABLES = ("ingest_events", "ingest_audit_log", "dead_letter_queue", "forward_outbox")


async def _table_exists(conn, name: str) -> bool:
    return await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{name}")


async def test_migration_round_trip(db_conn, run_alembic, reprovision_app_role):
    # Start at head (the session fixture already upgraded).
    for table in _TABLES:
        assert await _table_exists(db_conn, table), f"{table} missing at head"

    # downgrade base — everything reverses cleanly.
    down = run_alembic("downgrade", "base")
    assert down.returncode == 0, f"downgrade base failed:\n{down.stderr}"
    for table in _TABLES:
        assert not await _table_exists(db_conn, table), f"{table} still present after downgrade"

    # upgrade head again — rebuilds from drop.
    up = run_alembic("upgrade", "head")
    assert up.returncode == 0, f"upgrade head failed:\n{up.stderr}"
    for table in _TABLES:
        assert await _table_exists(db_conn, table), f"{table} missing after re-upgrade"

    # Restore the orchestrator_app password for subsequent tests (sync).
    reprovision_app_role()
