"""F-015 fairness threat model — vector 16 (ADR-0018 §11).

Redis-backed (skips without Redis). Proves per-tenant caps enforce backpressure so
one tenant cannot starve others, and that a released slot frees capacity.
"""

from __future__ import annotations

import uuid

import pytest

from bulk.exceptions import BatchLimitExceeded

pytestmark = pytest.mark.integration


async def test_per_tenant_batch_limit_enforced(redis_pool, monkeypatch):
    monkeypatch.setenv("BULK_MAX_CONCURRENT_BATCHES_PER_TENANT", "2")
    monkeypatch.setenv("BULK_MAX_INFLIGHT_FILES_PER_TENANT", "100")
    from bulk import limits
    from bulk.config import _reset_bulk_settings_for_testing

    _reset_bulk_settings_for_testing()
    tenant = str(uuid.uuid4())
    other = str(uuid.uuid4())

    # Two concurrent batches allowed.
    await limits.reserve_batch(tenant, 1)
    await limits.reserve_batch(tenant, 1)
    # The third is rejected — backpressure (no starvation of other tenants).
    with pytest.raises(BatchLimitExceeded):
        await limits.reserve_batch(tenant, 1)

    # A DIFFERENT tenant is unaffected (per-tenant isolation of the cap).
    await limits.reserve_batch(other, 1)

    # Releasing a slot frees capacity for the first tenant again.
    await limits.release_batch_slot(tenant)
    await limits.reserve_batch(tenant, 1)  # must not raise

    _reset_bulk_settings_for_testing()


async def test_per_tenant_file_cap_enforced(redis_pool, monkeypatch):
    monkeypatch.setenv("BULK_MAX_CONCURRENT_BATCHES_PER_TENANT", "100")
    monkeypatch.setenv("BULK_MAX_INFLIGHT_FILES_PER_TENANT", "5")
    from bulk import limits
    from bulk.config import _reset_bulk_settings_for_testing

    _reset_bulk_settings_for_testing()
    tenant = str(uuid.uuid4())

    await limits.reserve_batch(tenant, 5)  # exactly at cap
    with pytest.raises(BatchLimitExceeded):
        await limits.reserve_batch(tenant, 1)  # one more file exceeds the cap

    _reset_bulk_settings_for_testing()
