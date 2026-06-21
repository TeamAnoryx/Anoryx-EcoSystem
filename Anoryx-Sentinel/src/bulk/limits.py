"""Per-tenant batch limits + backpressure (F-015, ADR-0018 §7 D6, R8, vector 16).

Redis counters (reusing the F-009 pool) bound, per tenant:
  - concurrent active batches      (bulk_max_concurrent_batches_per_tenant)
  - total in-flight files          (bulk_max_inflight_files_per_tenant)

so one tenant's large batch cannot starve others of worker capacity (the F-009
fairness concern in batch form). `reserve_batch` is called at submit and raises
BatchLimitExceeded (→ 429) when a cap would be exceeded; the worker releases one
file slot per terminal file and one batch slot when the batch completes.

Counters carry a TTL so a crashed worker can never wedge a tenant permanently —
stuck counts self-heal. Floors clamp at 0 (a fairness counter must never go
negative). File-level idempotency (the worker skips already-terminal files)
guarantees release-once-per-file, so the counts track real in-flight work.
"""

from __future__ import annotations

import structlog

from bulk.config import get_bulk_settings
from bulk.exceptions import BatchLimitExceeded
from gateway.redis_client import get_client

log = structlog.get_logger(__name__)

# Safety TTL (seconds) so abandoned counters self-heal (24h).
_COUNTER_TTL = 86_400


def _batches_key(tenant_id: str) -> str:
    return f"sentinel:bulk:limits:batches:{tenant_id}"


def _files_key(tenant_id: str) -> str:
    return f"sentinel:bulk:limits:files:{tenant_id}"


async def reserve_batch(tenant_id: str, file_count: int) -> None:
    """Reserve one batch slot + `file_count` file slots, or raise BatchLimitExceeded.

    Rolls back its own partial reservation on rejection so a denied submit leaves
    the counters unchanged.
    """
    settings = get_bulk_settings()
    bkey, fkey = _batches_key(tenant_id), _files_key(tenant_id)
    async with await get_client() as client:
        new_batches = await client.incr(bkey)
        await client.expire(bkey, _COUNTER_TTL)
        if new_batches > settings.bulk_max_concurrent_batches_per_tenant:
            await client.decr(bkey)
            raise BatchLimitExceeded("per-tenant concurrent-batch cap exceeded")

        new_files = await client.incrby(fkey, file_count)
        await client.expire(fkey, _COUNTER_TTL)
        if new_files > settings.bulk_max_inflight_files_per_tenant:
            await client.decrby(fkey, file_count)
            await client.decr(bkey)
            raise BatchLimitExceeded("per-tenant in-flight-file cap exceeded")


async def release_reservation(tenant_id: str, file_count: int) -> None:
    """Give back a whole reservation (idempotent-replay / creation-race rollback)."""
    async with await get_client() as client:
        await _decr_floor(client, _files_key(tenant_id), file_count)
        await _decr_floor(client, _batches_key(tenant_id), 1)


async def release_file(tenant_id: str) -> None:
    """Release one in-flight file slot (called once per terminal file)."""
    async with await get_client() as client:
        await _decr_floor(client, _files_key(tenant_id), 1)


async def release_batch_slot(tenant_id: str) -> None:
    """Release one batch slot (called when the batch completes)."""
    async with await get_client() as client:
        await _decr_floor(client, _batches_key(tenant_id), 1)


# Atomic DECRBY-with-floor + TTL refresh (review MED + audit Low): the decr + clamp
# must be one operation (else concurrent releases/reserves race between DECRBY and a
# separate SET), and the TTL is refreshed so a long-running batch's counter cannot
# expire mid-flight and under-count in-flight work.
_DECR_FLOOR_LUA = (
    "local v = redis.call('decrby', KEYS[1], ARGV[1]); "
    "if v < 0 then redis.call('set', KEYS[1], 0); v = 0 end; "
    "redis.call('expire', KEYS[1], ARGV[2]); return v"
)


async def _decr_floor(client, key: str, amount: int) -> None:
    """Atomic DECRBY then clamp at 0 (never negative) + refresh the counter TTL."""
    await client.eval(_DECR_FLOOR_LUA, 1, key, amount, _COUNTER_TTL)
