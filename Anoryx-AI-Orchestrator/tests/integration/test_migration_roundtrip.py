"""Migration reversibility on a real Postgres (0001 -> 0002 -> D-004 -> 0004 -> 0005 -> 0006 ->
0007 -> 0008 -> 0009 -> 0010 -> 0011 -> 0012).

The Orchestrator's migrations must apply clean to head AND reverse cleanly. Proves a
non-stubbed round-trip across ALL migrations (head = 0012_safety_events): upgrade
head -> tables present -> downgrade base -> tables gone -> upgrade head -> tables present again.
Re-provisions the orchestrator_app password after the final upgrade (downgrade base drops the
passwordless role) so later tests still connect. The O-005/O-009/O-010/O-011/O-012/O-013/O-014/
X-004 migrations touched no EXISTING audit-chain table (each adds its own new one), so all eleven
hash chains stay verifiable across the round-trip by construction.

STALE-CONNECTION-POOL TRAP: 0001's downgrade() drops the orchestrator_app role outright (it
owns no objects, only grants) and its upgrade() recreates it — a DIFFERENT role OID. The
module-global async app-engine pool (orchestrator/persistence/database.py) is session-scoped
(reset once at session start/end, per the harness's ADR-0026 discipline — NOT per test), so
any connection it already pooled BEFORE this round trip stays authenticated as the OLD
(now-nonexistent) role OID; Postgres's ACL checks then reject it against the NEW OID's grants,
surfacing as `InsufficientPrivilegeError` on a LATER test's first tenant-scoped query — not
here, since db_conn/run_alembic never touch the app engine. Disposing + nulling the app engine
here (mirroring reset_engines()'s own purpose) forces the next checkout to open a fresh
connection authenticated as the freshly-recreated role, so this test's DDL round trip cannot
leak a stale, permission-mismatched connection into any test that runs after it.
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import database as db

pytestmark = pytest.mark.integration

# 0001 (ingest baseline) + 0002 (policy distribution) + d004 (forward_outbox dispatch columns
# extend forward_outbox, no new table) + 0004 (O-005 sentinel registry) + 0005 (O-006 per-tenant
# query principal — query_service_tokens) + 0006 (O-009 relay_audit_log) + 0007 (O-010
# identity_events + identity_audit_log) + 0008 (O-011 automation_rules + automation_executions) +
# 0009 (O-012 agent_messages + agent_messaging_audit_log + agent_state + agent_state_audit_log) +
# 0010 (O-013 third_party_api_keys + external_gateway_audit_log +
# external_gateway_rate_limit_counters) + 0011 (O-014 distribution_rollbacks) + 0012 (X-004
# safety_events + safety_audit_log) tables.
_TABLES = (
    "ingest_events",
    "ingest_audit_log",
    "dead_letter_queue",
    "forward_outbox",
    "policy_distributions",
    "policy_distribution_targets",
    "distribution_audit_log",
    "sentinel_registry",
    "sentinel_registry_audit_log",
    "query_service_tokens",
    "relay_audit_log",
    "identity_events",
    "identity_audit_log",
    "automation_rules",
    "automation_executions",
    "agent_messages",
    "agent_messaging_audit_log",
    "agent_state",
    "agent_state_audit_log",
    "third_party_api_keys",
    "external_gateway_audit_log",
    "external_gateway_rate_limit_counters",
    "distribution_rollbacks",
    "safety_events",
    "safety_audit_log",
)


async def _table_exists(conn, name: str) -> bool:
    return await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{name}")


async def test_migration_round_trip(db_conn, run_alembic, reprovision_app_role):
    # Single head, and it is the X-004 revision (0012_safety_events).
    heads = run_alembic("heads")
    assert heads.returncode == 0, heads.stderr
    assert "0012_safety_events" in heads.stdout, heads.stdout

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

    # Dispose any app-engine connections pooled before this round trip — they are stale
    # (authenticated as the just-dropped-and-recreated role OID; see the module docstring)
    # and would surface as a false-positive InsufficientPrivilegeError on a LATER test's
    # first tenant-scoped query rather than here. The privileged engine (owner role,
    # never dropped by any migration) is untouched by the round trip and does not need
    # resetting.
    await db.reset_engines()
