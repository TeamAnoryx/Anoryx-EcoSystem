"""F-015 data-plane route tests (app + virtual-key auth + RLS).

App-backed (skips without Postgres) + Redis-backed (skips without Redis). Storage
is stubbed (the presign call) so the route layer is tested without MinIO. Covers
auth integration, the four-ID header gate, idempotency (202 new / 200 replay),
cross-tenant 404, foreign-key rejection, and count bounds.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from bulk.storage.base import PresignedUpload
from bulk.storage.keys import mint_object_key

pytestmark = pytest.mark.integration


class _StubStorage:
    def presign_upload(self, key, *, max_bytes, ttl):
        return PresignedUpload(
            url="http://stub-minio/upload",
            fields={"key": key},
            key=key,
            max_bytes=max_bytes,
            expires_in=ttl,
        )


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _mint(client, headers, count):
    return await client.post("/v1/batches/uploads", json={"count": count}, headers=headers)


async def test_mint_uploads_returns_tenant_prefixed_grants(
    bulk_app, seeded_key, redis_pool, monkeypatch, cleanup_bulk_after
):
    monkeypatch.setattr("bulk.api.routes.get_storage", lambda: _StubStorage())
    async with _client(bulk_app) as client:
        r = await _mint(client, seeded_key["headers"], 3)
    assert r.status_code == 200
    uploads = r.json()["uploads"]
    assert len(uploads) == 3
    for u in uploads:
        assert u["object_key"].startswith(seeded_key["tenant_id"] + "/")


async def test_mint_uploads_rejects_excess_count(
    bulk_app, seeded_key, redis_pool, monkeypatch, cleanup_bulk_after
):
    monkeypatch.setattr("bulk.api.routes.get_storage", lambda: _StubStorage())
    async with _client(bulk_app) as client:
        r = await _mint(client, seeded_key["headers"], 1001)  # > default cap 1000
    assert r.status_code == 400


async def test_missing_id_headers_rejected(bulk_app, seeded_key, cleanup_bulk_after):
    async with _client(bulk_app) as client:
        # Only the bearer, no X-Anoryx-* headers → header-format gate 400.
        r = await client.post(
            "/v1/batches/uploads",
            json={"count": 1},
            headers={"Authorization": f"Bearer {seeded_key['plaintext']}"},
        )
    assert r.status_code == 400


async def test_submit_status_manifest_flow(
    bulk_app, seeded_key, redis_pool, monkeypatch, cleanup_bulk_after
):
    monkeypatch.setattr("bulk.api.routes.get_storage", lambda: _StubStorage())
    headers = seeded_key["headers"]
    async with _client(bulk_app) as client:
        grants = (await _mint(client, headers, 2)).json()["uploads"]
        keys = [g["object_key"] for g in grants]

        submit = await client.post(
            "/v1/batches",
            json={"idempotency_key": "route-K1", "object_keys": keys},
            headers=headers,
        )
        assert submit.status_code == 202
        batch_id = submit.json()["batch_id"]
        assert submit.json()["total_files"] == 2

        status = await client.get(f"/v1/batches/{batch_id}", headers=headers)
        assert status.status_code == 200
        assert status.json()["status"] in ("queued", "running", "completed")

        manifest = await client.get(f"/v1/batches/{batch_id}/files", headers=headers)
        assert manifest.status_code == 200
        assert len(manifest.json()["files"]) == 2


async def test_submit_idempotent_replay_returns_same_batch(
    bulk_app, seeded_key, redis_pool, monkeypatch, cleanup_bulk_after
):
    monkeypatch.setattr("bulk.api.routes.get_storage", lambda: _StubStorage())
    headers = seeded_key["headers"]
    async with _client(bulk_app) as client:
        keys = [g["object_key"] for g in (await _mint(client, headers, 1)).json()["uploads"]]
        first = await client.post(
            "/v1/batches",
            json={"idempotency_key": "route-K2", "object_keys": keys},
            headers=headers,
        )
        second = await client.post(
            "/v1/batches",
            json={"idempotency_key": "route-K2", "object_keys": keys},
            headers=headers,
        )
    assert first.status_code == 202
    assert second.status_code == 200  # idempotent replay
    assert first.json()["batch_id"] == second.json()["batch_id"]


async def test_submit_rejects_foreign_namespace_key(
    bulk_app, seeded_key, redis_pool, monkeypatch, cleanup_bulk_after
):
    monkeypatch.setattr("bulk.api.routes.get_storage", lambda: _StubStorage())
    headers = seeded_key["headers"]
    foreign = mint_object_key(str(uuid.uuid4()), str(uuid.uuid4()))  # different tenant prefix
    async with _client(bulk_app) as client:
        r = await client.post(
            "/v1/batches",
            json={"idempotency_key": "route-K3", "object_keys": [foreign]},
            headers=headers,
        )
    assert r.status_code == 400  # key not in caller's namespace (vector 2/7)


async def test_status_unknown_batch_is_404(bulk_app, seeded_key, cleanup_bulk_after):
    async with _client(bulk_app) as client:
        r = await client.get(f"/v1/batches/{uuid.uuid4()}", headers=seeded_key["headers"])
    assert r.status_code == 404
    assert r.json()["error_code"] == "not_found"
