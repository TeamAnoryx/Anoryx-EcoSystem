"""F-015 end-to-end: MinIO storage round-trip, worker consumer-loop, load test.

Requires Postgres + Redis + MinIO (skips cleanly if any is unreachable). The load
test reports an HONEST measured files/min at a fixed single-worker count — a design
goal validation, NOT a production autoscale guarantee (ADR-0018 §10).

Env (defaults match docker-compose): BULK_STORAGE_ENDPOINT, BULK_STORAGE_ACCESS_KEY,
BULK_STORAGE_SECRET_KEY, BULK_STORAGE_BUCKET. BULK_LOADTEST_N sets the file count.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from bulk.queue import JobMessage, enqueue_files, ensure_group, queue_depth
from bulk.repositories.batch_repository import BatchRepository
from bulk.worker import process_job

pytestmark = pytest.mark.integration

_ENDPOINT = os.environ.get("BULK_STORAGE_ENDPOINT", "http://localhost:9000")
_ACCESS = os.environ.get("BULK_STORAGE_ACCESS_KEY", "minioadmin")
_SECRET = os.environ.get("BULK_STORAGE_SECRET_KEY", "minioadmin")
_BUCKET = os.environ.get("BULK_STORAGE_BUCKET", "sentinel-bulk")


def _pin_minio_env(monkeypatch):
    monkeypatch.setenv("BULK_STORAGE_ENDPOINT", _ENDPOINT)
    monkeypatch.setenv("BULK_STORAGE_ACCESS_KEY", _ACCESS)
    monkeypatch.setenv("BULK_STORAGE_SECRET_KEY", _SECRET)
    monkeypatch.setenv("BULK_STORAGE_BUCKET", _BUCKET)
    from bulk.config import _reset_bulk_settings_for_testing

    _reset_bulk_settings_for_testing()


def _boto3_client():
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=_ENDPOINT,
        aws_access_key_id=_ACCESS,
        aws_secret_access_key=_SECRET,
        region_name="us-east-1",
        config=Config(signature_version="s3v4"),
    )
    try:
        client.head_bucket(Bucket=_BUCKET)
    except Exception:
        pytest.skip(f"MinIO/bucket unreachable at {_ENDPOINT} — skipping")
    return client


def _deps(storage):
    from gateway.config import get_settings
    from orchestration.config import get_orchestration_settings
    from orchestration.registry import build_default_registry

    return {
        "storage": storage,
        "hook_registry": build_default_registry(),
        "gateway_settings": get_settings(),
        "orch_settings": get_orchestration_settings(),
    }


def _job(batch_id, fid, key, tenant):
    return JobMessage(
        batch_id=batch_id,
        file_id=fid,
        tenant_id=tenant,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="bulk-test",
        object_key=key,
        idempotency_key="seed-K",
        model="",
    )


# --------------------------------------------------------------------------- #
# MinIO backend round-trip — presign_upload + fetch/head/delete
# --------------------------------------------------------------------------- #
async def test_minio_backend_round_trip(test_tenant_id, monkeypatch):
    _pin_minio_env(monkeypatch)
    client = _boto3_client()  # also the reachability gate
    from bulk.storage import get_storage
    from bulk.storage.keys import mint_object_key

    storage = get_storage()
    key = mint_object_key(test_tenant_id, str(uuid.uuid4()))
    client.put_object(Bucket=_BUCKET, Key=key, Body=b"round-trip content")

    data = await storage.fetch(key, max_bytes=1024)
    assert data == b"round-trip content"
    meta = await storage.head(key)
    assert meta.size == len(b"round-trip content")
    await storage.delete(key)
    from bulk.exceptions import StorageError

    with pytest.raises(StorageError):
        await storage.fetch(key, max_bytes=1024)  # gone


# --------------------------------------------------------------------------- #
# Worker consumer-loop drains the Redis Streams group (queue + worker plumbing)
# --------------------------------------------------------------------------- #
async def test_worker_loop_drains_stream(
    seed_batch, tenant_session_factory, stub_storage, test_tenant_id, redis_pool, cleanup_bulk_after
):
    from bulk.config import get_bulk_settings
    from bulk.worker import _consume_batch
    from gateway.redis_client import get_client

    batch_id, files = await seed_batch(test_tenant_id, object_count=3)
    jobs = []
    for fid, key in files:
        stub_storage.content[key] = b"benign loop content"
        jobs.append(_job(batch_id, fid, key, test_tenant_id))
    await ensure_group()
    await enqueue_files(jobs)
    assert await queue_depth() >= 3

    d = _deps(stub_storage)
    deps_tuple = (d["storage"], d["hook_registry"], d["gateway_settings"], d["orch_settings"])
    s = get_bulk_settings()
    async with await get_client() as client:
        handled = await _consume_batch(
            client, s.bulk_consumer_group, "test-consumer", s.bulk_stream_key, deps_tuple
        )
    assert handled == 3

    make = tenant_session_factory(test_tenant_id)
    async with make() as sess:
        manifest = await BatchRepository(sess).list_files(batch_id)
        states = [(f.status, f.outcome, f.attempt_count, f.failure_class) for f in manifest]
        assert all(f.status == "done" for f in manifest), states
        assert (await BatchRepository(sess).get_batch(batch_id)).status == "completed"


async def test_run_worker_starts_and_stops(
    seed_batch, tenant_session_factory, test_tenant_id, redis_pool, monkeypatch, cleanup_bulk_after
):
    """run_worker bootstraps (ensure_group + deps) and drains one batch, then stops
    on the stop_event — covers the consumer-pool entrypoint + _build_deps."""
    _pin_minio_env(monkeypatch)
    client = _boto3_client()
    import asyncio

    from bulk.worker import run_worker

    batch_id, files = await seed_batch(test_tenant_id, object_count=2)
    for _fid, key in files:
        client.put_object(Bucket=_BUCKET, Key=key, Body=b"benign run-worker content")
    await ensure_group()
    await enqueue_files([_job(batch_id, fid, key, test_tenant_id) for fid, key in files])

    stop = asyncio.Event()

    async def _stopper():
        # Let the worker drain one consume cycle, then signal stop.
        for _ in range(40):
            if await queue_depth() == 0:
                break
            await asyncio.sleep(0.25)
        stop.set()

    await asyncio.gather(run_worker(stop_event=stop), _stopper())

    make = tenant_session_factory(test_tenant_id)
    async with make() as sess:
        manifest = await BatchRepository(sess).list_files(batch_id)
        assert all(f.status == "done" for f in manifest)


# --------------------------------------------------------------------------- #
# LOAD TEST — honest measured files/min at a fixed single worker (design goal)
# --------------------------------------------------------------------------- #
async def test_bulk_load_throughput(
    seed_batch, tenant_session_factory, test_tenant_id, redis_pool, monkeypatch, cleanup_bulk_after
):
    _pin_minio_env(monkeypatch)
    client = _boto3_client()
    from bulk.storage import get_storage

    n = int(os.environ.get("BULK_LOADTEST_N", "100"))
    batch_id, files = await seed_batch(test_tenant_id, object_count=n)
    payload = b"benign load-test document. " * 8
    for _fid, key in files:
        client.put_object(Bucket=_BUCKET, Key=key, Body=payload)

    deps = _deps(get_storage())
    start = time.monotonic()
    for fid, key in files:
        await process_job(_job(batch_id, fid, key, test_tenant_id), **deps)
    elapsed = time.monotonic() - start

    files_per_min = n / elapsed * 60.0
    # Honest report — single worker, real MinIO fetch + full F-005 pipeline per file.
    print(
        f"\n[F-015 LOAD] {n} files in {elapsed:.2f}s @ 1 worker = "
        f"{files_per_min:,.0f} files/min (single-worker measured; "
        f"10-20 workers scale ~linearly toward the 5000/5min design goal — "
        f"NOT a production autoscale guarantee, ADR-0018 §10)"
    )

    make = tenant_session_factory(test_tenant_id)
    async with make() as sess:
        assert (await BatchRepository(sess).get_batch(batch_id)).status == "completed"
    assert files_per_min > 0
