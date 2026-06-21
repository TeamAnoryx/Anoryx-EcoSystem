"""F-015 idempotency threat model — vector 9 (ADR-0018 §11).

DB-backed (skips cleanly when no Postgres). Proves a replayed idempotency key
returns the SAME batch and never creates a second one (no double-process/emit/bill).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from bulk.repositories.batch_repository import BatchRepository
from bulk.storage.keys import mint_object_key

pytestmark = pytest.mark.integration


async def test_idempotency_replay_dedupes(
    seed_tenants, tenant_session_factory, test_tenant_id, cleanup_bulk_after
):
    await seed_tenants(test_tenant_id)
    make = tenant_session_factory(test_tenant_id)
    group = str(uuid.uuid4())
    keys = [mint_object_key(test_tenant_id, group), mint_object_key(test_tenant_id, group)]

    # First submit creates the batch.
    async with make() as s:
        repo = BatchRepository(s)
        batch1, files = await repo.create_batch(
            tenant_id=test_tenant_id,
            team_id=str(uuid.uuid4()),
            project_id=str(uuid.uuid4()),
            agent_id="bulk-test",
            idempotency_key="idem-K",
            object_keys=keys,
        )
        bid1 = batch1.batch_id
        assert len(files) == 2

    # Replay: the existing batch is returned — same id, no new batch.
    async with make() as s:
        repo = BatchRepository(s)
        existing = await repo.get_by_idempotency_key(test_tenant_id, "idem-K")
        assert existing is not None
        assert existing.batch_id == bid1

    # A direct duplicate create violates UNIQUE (tenant_id, idempotency_key).
    with pytest.raises(IntegrityError):
        async with make() as s:
            repo = BatchRepository(s)
            await repo.create_batch(
                tenant_id=test_tenant_id,
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="bulk-test",
                idempotency_key="idem-K",
                object_keys=keys,
            )
