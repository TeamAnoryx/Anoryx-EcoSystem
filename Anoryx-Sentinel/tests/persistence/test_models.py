"""Model integrity tests: verify tables exist and constraints are active (F-003).

Tests run against the live DB using the session fixture from conftest.py.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.base import Base


@pytest.mark.asyncio
async def test_all_tables_exist(session: AsyncSession) -> None:
    """All 10 expected tables must exist in the DB after migrations."""
    expected = {
        "tenants",
        "teams",
        "projects",
        "agents",
        "users",
        "role_assignments",
        "virtual_api_keys",
        "policies",
        "policy_versions",
        "events_audit_log",
    }
    result = await session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    actual = {row[0] for row in result}
    missing = expected - actual
    assert not missing, f"Missing tables: {missing}"


@pytest.mark.asyncio
async def test_orm_metadata_matches_db(session: AsyncSession) -> None:
    """ORM Base.metadata table names match DB tables (basic sanity)."""
    orm_tables = set(Base.metadata.tables.keys())
    result = await session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    db_tables = {row[0] for row in result}
    # All ORM tables must exist in DB.
    missing = orm_tables - db_tables
    assert not missing, f"ORM tables not in DB: {missing}"


@pytest.mark.asyncio
async def test_events_audit_log_check_constraints(session: AsyncSession) -> None:
    """Verify CHECK constraints exist on events_audit_log.

    These constraint names are the final contract names, born in migration 0005:
      ck_eal_severity     — PiiBlockedEvent.severity (matches events.schema.json)
      ck_eal_status       — ComplianceCheckedEvent.status (matches events.schema.json)
      ck_eal_action_taken — union of valid action_taken values across all event variants
    """
    result = await session.execute(text("""
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'events_audit_log'::regclass
            AND contype = 'c'
            """))
    constraints = {row[0] for row in result}
    expected_constraints = {
        "ck_eal_event_type",
        "ck_eal_tokens_in",
        "ck_eal_tokens_out",
        "ck_eal_latency_ms",
        "ck_eal_row_hash_len",
        "ck_eal_prev_hash_len",
        # Final contract names (migration 0005, born with these names):
        "ck_eal_severity",  # PiiBlockedEvent.severity
        "ck_eal_status",  # ComplianceCheckedEvent.status
        "ck_eal_action_taken",  # union of valid action_taken values
    }
    missing = expected_constraints - constraints
    assert not missing, f"Missing CHECK constraints: {missing}"
    # Confirm old names (from pre-consolidation) never appear in schema.
    assert (
        "ck_eal_pii_severity" not in constraints
    ), "ck_eal_pii_severity must not exist; the column is named 'severity' from creation"
    assert (
        "ck_eal_compliance_status" not in constraints
    ), "ck_eal_compliance_status must not exist; the column is named 'status' from creation"


@pytest.mark.asyncio
async def test_policies_check_constraints(session: AsyncSession) -> None:
    """Verify CHECK constraints exist on policies."""
    result = await session.execute(text("""
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'policies'::regclass
            AND contype = 'c'
            """))
    constraints = {row[0] for row in result}
    assert "ck_policies_policy_type" in constraints
    assert "ck_policies_version_positive" in constraints
    assert "ck_policies_signature_length" in constraints


@pytest.mark.asyncio
async def test_virtual_api_keys_fingerprint_constraint(session: AsyncSession) -> None:
    """Verify the key_fingerprint length CHECK constraint exists."""
    result = await session.execute(text("""
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'virtual_api_keys'::regclass
            AND contype = 'c'
            """))
    constraints = {row[0] for row in result}
    assert "ck_vak_fingerprint_len" in constraints


@pytest.mark.asyncio
async def test_rls_enabled_on_tenant_scoped_tables(session: AsyncSession) -> None:
    """RLS must be ENABLED on tenant-scoped tables."""
    rls_tables = ["teams", "projects", "users", "role_assignments", "events_audit_log"]
    for table in rls_tables:
        result = await session.execute(
            text(
                "SELECT rowsecurity FROM pg_tables "
                "WHERE tablename = :t AND schemaname = 'public'"
            ),
            {"t": table},
        )
        row = result.fetchone()
        assert row is not None, f"Table {table!r} not found"
        assert row[0] is True, f"RLS not enabled on {table!r}"


@pytest.mark.asyncio
async def test_append_only_triggers_exist(session: AsyncSession) -> None:
    """Verify BEFORE UPDATE and BEFORE DELETE triggers on events_audit_log."""
    result = await session.execute(text("""
            SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'events_audit_log'::regclass
            AND tgtype & 2 > 0  -- BEFORE triggers
            """))
    triggers = {row[0] for row in result}
    assert "trg_eal_deny_update" in triggers, "Missing deny_update trigger"
    assert "trg_eal_deny_delete" in triggers, "Missing deny_delete trigger"


@pytest.mark.asyncio
async def test_policy_monotonicity_trigger_exists(session: AsyncSession) -> None:
    """Verify the monotonicity trigger exists on policy_versions."""
    result = await session.execute(text("""
            SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'policy_versions'::regclass
            """))
    triggers = {row[0] for row in result}
    assert "trg_policy_versions_monotonicity" in triggers
