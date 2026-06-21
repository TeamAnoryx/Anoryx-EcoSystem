"""F-015 tenant-isolation threat model — vector 1 (ADR-0018 §11, PRIMARY).

DB-backed (skips cleanly when no Postgres). Commits real rows for two tenants over
real sentinel_app (NOBYPASSRLS) connections and proves tenant B cannot see tenant
A's batch / files — the RLS floor, not application code (Fork 1 (a)).

Vectors 2/7 (object-key namespacing + traversal) are proven as pure-unit tests in
test_bulk_storage_threat_model.py; vector 4 (no blanket BYPASSRLS) is proven in the
worker tests (STEP 4).
"""

from __future__ import annotations

import uuid

import pytest

from bulk.repositories.batch_repository import BatchRepository
from bulk.storage.keys import mint_object_key

pytestmark = pytest.mark.integration


async def test_batch_scoped_to_submitting_tenant(
    seed_tenants, tenant_session_factory, test_tenant_id, tenant_b_id, cleanup_bulk_after
):
    await seed_tenants(test_tenant_id, tenant_b_id)
    make_a = tenant_session_factory(test_tenant_id)
    make_b = tenant_session_factory(tenant_b_id)
    group = str(uuid.uuid4())

    # Tenant A submits a batch (committed under A's RLS scope).
    async with make_a() as s:
        repo = BatchRepository(s)
        batch, _ = await repo.create_batch(
            tenant_id=test_tenant_id,
            team_id=str(uuid.uuid4()),
            project_id=str(uuid.uuid4()),
            agent_id="bulk-test",
            idempotency_key="iso-K",
            object_keys=[mint_object_key(test_tenant_id, group)],
        )
        bid = batch.batch_id

    # Tenant B cannot see A's batch or its files — RLS denies at the DB floor.
    async with make_b() as s:
        repo = BatchRepository(s)
        assert await repo.get_batch(bid) is None
        assert await repo.list_files(bid) == []
        assert await repo.count_files_by_status(bid) == {}

    # Tenant A can see its own batch.
    async with make_a() as s:
        repo = BatchRepository(s)
        assert (await repo.get_batch(bid)) is not None
        assert len(await repo.list_files(bid)) == 1
