"""F-024 S3/MinIO sink round-trip (ADR-0030). Requires a live MinIO/S3 (skips
cleanly if unreachable — mirrors tests/bulk/test_bulk_e2e_minio.py exactly,
including env var defaults matching docker-compose).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from dr.backends.s3 import S3Sink
from dr.exceptions import BackupNotFound
from dr.key_format import make_key

pytestmark = pytest.mark.integration

_ENDPOINT = os.environ.get("DR_S3_ENDPOINT", "http://localhost:9000")
_ACCESS = os.environ.get("DR_S3_ACCESS_KEY", "minioadmin")
_SECRET = os.environ.get("DR_S3_SECRET_KEY", "minioadmin")
_BUCKET = os.environ.get("DR_S3_BUCKET", "sentinel-dr-backups")


def _sink() -> S3Sink:
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
        try:
            client.create_bucket(Bucket=_BUCKET)
        except Exception:
            pytest.skip(f"MinIO/bucket unreachable at {_ENDPOINT} — skipping")
    return S3Sink(
        bucket=_BUCKET,
        endpoint=_ENDPOINT,
        region="us-east-1",
        access_key=_ACCESS,
        secret_key=_SECRET,
    )


@pytest.mark.asyncio
async def test_s3_store_fetch_list_delete_round_trip(tmp_path):
    sink = _sink()
    key = make_key(datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC))
    src = tmp_path / "dump.bin"
    src.write_bytes(b"s3 dump bytes")

    await sink.store(src, key)
    try:
        dest = tmp_path / "restored.bin"
        await sink.fetch(key, dest)
        assert dest.read_bytes() == b"s3 dump bytes"

        objects = await sink.list_objects()
        assert any(o.key == key and o.size_bytes == len(b"s3 dump bytes") for o in objects)
    finally:
        await sink.delete(key)

    with pytest.raises(BackupNotFound):
        await sink.fetch(key, tmp_path / "gone.bin")
