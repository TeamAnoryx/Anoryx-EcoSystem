"""D-009 non-stubbed hash-chain DB suite: real appends, real tamper detection, real
concurrency, real RLS isolation. Uses the tests/persistence/conftest.py harness
(tenant_db, privileged_session, app_engine) shared with the D-003 ledger suite.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import insert, text
from sqlalchemy.exc import DBAPIError

from delta.persistence.audit_log import (
    GENESIS_HASH,
    append_history,
    compute_row_hash,
    list_history,
    verify_chain,
)
from delta.persistence.models import change_history

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


async def test_first_append_prev_hash_is_genesis(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        row = await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id=str(uuid.uuid4()),
            action="requested",
            actor="operator-1",
            now=_NOW,
        )
        await s.commit()
    assert row.prev_hash == GENESIS_HASH
    assert row.row_hash == compute_row_hash(
        {
            "tenant_id": tenant_id,
            "entity_type": "allocation",
            "entity_id": row.entity_id,
            "action": "requested",
            "actor": "operator-1",
            "note": None,
            "created_at": _NOW.isoformat(),
            "prev_hash": GENESIS_HASH,
        }
    )


async def test_second_append_links_to_first(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        first = await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    async with tenant_db() as s:
        second = await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="approved",
            actor="op2",
            now=_NOW,
        )
        await s.commit()
    assert second.prev_hash == first.row_hash
    assert second.sequence_number > first.sequence_number


async def test_verify_chain_passes_on_untampered_chain(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        for i in range(4):
            await append_history(
                s,
                tenant_id=tenant_id,
                entity_type="allocation",
                entity_id=str(i),
                action="requested",
                actor="op",
                now=_NOW,
            )
        await s.commit()
    async with tenant_db() as s:
        result = await verify_chain(s, tenant_id=tenant_id)
    assert result.is_valid is True
    assert result.rows_checked == 4
    assert result.first_mismatch_sequence is None


async def test_verify_chain_detects_forged_row_hash(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        # A forged second row: correct prev_hash link, but a row_hash that does NOT
        # match compute_row_hash of its own content (simulates what a compromised
        # write path — bypassing append_history entirely — would produce; the
        # append-only trigger only prevents UPDATING an EXISTING row, so this proves
        # verify_chain's cryptographic check is the backstop for a forged INSERT).
        tip = await s.execute(
            text(
                "SELECT row_hash FROM delta.change_history WHERE tenant_id = :t "
                "ORDER BY sequence_number DESC LIMIT 1"
            ),
            {"t": tenant_id},
        )
        prev_hash = tip.scalar_one()
        # row_hash is globally unique (uq_history_row_hash) and change_history is
        # never truncated between tests — a hardcoded literal like "f" * 64 would
        # collide with a leftover row from an earlier run of THIS SAME test. Derive
        # a value that's still obviously wrong (won't match compute_row_hash's real
        # output) but unique per invocation.
        forged_row_hash = ("f" + uuid.uuid4().hex + uuid.uuid4().hex)[:64]
        await s.execute(
            insert(change_history).values(
                history_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                entity_type="allocation",
                entity_id="a",
                action="approved",
                actor="attacker",
                note=None,
                created_at=_NOW,
                prev_hash=prev_hash,
                row_hash=forged_row_hash,  # deliberately wrong, but unique
            )
        )
        await s.commit()
    async with tenant_db() as s:
        result = await verify_chain(s, tenant_id=tenant_id)
    assert result.is_valid is False
    # sequence_number is a single global BIGSERIAL shared across the whole test
    # session (change_history is never truncated between tests) — rows_checked
    # (a local count of THIS tenant's walk) is the stable thing to assert on.
    assert result.rows_checked == 2
    assert "row_hash mismatch" in result.error_detail


async def test_verify_chain_detects_broken_prev_hash_link(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        # A forged row claiming a fabricated prev_hash instead of the real tip.
        forged_prev = "0" * 64
        forged_data = {
            "tenant_id": tenant_id,
            "entity_type": "allocation",
            "entity_id": "a",
            "action": "approved",
            "actor": "attacker",
            "note": None,
            "created_at": _NOW.isoformat(),
            "prev_hash": forged_prev,
        }
        await s.execute(
            insert(change_history).values(
                history_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                entity_type="allocation",
                entity_id="a",
                action="approved",
                actor="attacker",
                note=None,
                created_at=_NOW,
                prev_hash=forged_prev,
                row_hash=compute_row_hash(forged_data),  # internally consistent, but...
            )
        )
        await s.commit()
    async with tenant_db() as s:
        result = await verify_chain(s, tenant_id=tenant_id)
    # ...the prev_hash doesn't match the REAL previous row's row_hash, so the link
    # check catches it even though the forged row's own hash is self-consistent.
    assert result.is_valid is False
    assert result.rows_checked == 2
    assert "prev_hash mismatch" in result.error_detail


async def test_deny_update_denied_by_grant_for_app_role(tenant_db, tenant_id: str) -> None:
    """delta_app has no UPDATE grant on change_history at all — Postgres denies this
    at the grant layer, before the append-only trigger ever gets a chance to fire.
    (See test_deny_update_trigger_blocks_modification for the trigger layer itself,
    exercised via the privileged/owner role, which DOES hold UPDATE rights.)"""
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    async with tenant_db() as s:
        with pytest.raises(DBAPIError, match="permission denied"):
            await s.execute(
                text("UPDATE delta.change_history SET action = 'tampered' " "WHERE tenant_id = :t"),
                {"t": tenant_id},
            )
            await s.commit()


async def test_deny_delete_denied_by_grant_for_app_role(tenant_db, tenant_id: str) -> None:
    """Same grant-layer denial as above, for DELETE."""
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    async with tenant_db() as s:
        with pytest.raises(DBAPIError, match="permission denied"):
            await s.execute(
                text("DELETE FROM delta.change_history WHERE tenant_id = :t"), {"t": tenant_id}
            )
            await s.commit()


async def test_deny_update_trigger_blocks_modification(
    tenant_db, privileged_session, tenant_id: str
) -> None:
    """The privileged/owner role DOES hold UPDATE rights (unlike delta_app), so this
    exercises the actual append-only trigger backstop rather than the grant layer."""
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        await privileged_session.execute(
            text("UPDATE delta.change_history SET action = 'tampered' WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        await privileged_session.commit()


async def test_deny_delete_trigger_blocks_deletion(
    tenant_db, privileged_session, tenant_id: str
) -> None:
    """Trigger-layer denial for DELETE, via the privileged/owner role (see above)."""
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        await privileged_session.execute(
            text("DELETE FROM delta.change_history WHERE tenant_id = :t"), {"t": tenant_id}
        )
        await privileged_session.commit()


async def test_concurrent_appends_produce_an_unbroken_chain(tenant_db_for, tenant_id: str) -> None:
    async def _append(i: int) -> None:
        async with tenant_db_for(tenant_id) as s:
            await append_history(
                s,
                tenant_id=tenant_id,
                entity_type="allocation",
                entity_id=str(i),
                action="requested",
                actor=f"op-{i}",
                now=_NOW,
            )
            await s.commit()

    await asyncio.gather(*(_append(i) for i in range(8)))

    async with tenant_db_for(tenant_id) as s:
        result = await verify_chain(s, tenant_id=tenant_id)
    # The advisory lock serializes the 8 concurrent tip-read+insert critical sections;
    # if it didn't, two racing appends could read the same tip and both link to it,
    # producing a fork verify_chain would catch as a prev_hash mismatch downstream.
    assert result.is_valid is True
    assert result.rows_checked == 8


async def test_list_history_filters_and_limits(tenant_db, tenant_id: str) -> None:
    async with tenant_db() as s:
        for _i in range(3):
            await append_history(
                s,
                tenant_id=tenant_id,
                entity_type="allocation",
                entity_id="a",
                action="requested",
                actor="op",
                now=_NOW,
            )
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="budget_enforcement",
            entity_id="b",
            action="enforce",
            actor="budget-engine",
            now=_NOW,
        )
        await s.commit()
    async with tenant_db() as s:
        allocation_rows = await list_history(s, entity_type="allocation")
        capped = await list_history(s, limit=2)
    assert len(allocation_rows) == 3
    assert all(r.entity_type == "allocation" for r in allocation_rows)
    assert len(capped) == 2


async def test_cross_tenant_chain_is_isolated(
    tenant_db, tenant_db_for, tenant_id: str, other_tenant_id: str
) -> None:
    async with tenant_db() as s:
        await append_history(
            s,
            tenant_id=tenant_id,
            entity_type="allocation",
            entity_id="a",
            action="requested",
            actor="op",
            now=_NOW,
        )
        await s.commit()
    async with tenant_db_for(other_tenant_id) as s:
        result = await verify_chain(s, tenant_id=other_tenant_id)
        rows = await list_history(s)
    assert result.rows_checked == 0  # RLS: tenant A's row is structurally invisible
    assert rows == []
