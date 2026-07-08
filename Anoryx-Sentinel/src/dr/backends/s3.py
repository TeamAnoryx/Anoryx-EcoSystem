"""S3/MinIO-compatible backup sink (F-024, ADR-0030).

The off-cluster-durability sink. Same lib family as F-015 bulk / F-006 bedrock
(boto3); lazy-imported behind the [dr-s3] extra so a slim deploy that never
enables S3-backed backup does not need boto3 installed (mirrors bulk's
storage/minio_backend.py discipline exactly).

boto3 is SYNC — every network call runs in asyncio.to_thread so the caller's
event loop is never blocked. Credentials are SECRETS — never logged; error
messages carry only the exception CLASS, never the endpoint/bucket/credentials.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from dr.backends.base import BackupObject, BackupSink
from dr.exceptions import BackupNotFound, StorageDependencyMissing
from dr.key_format import parse_created_at

log = structlog.get_logger(__name__)


def _load_boto3():
    """Lazy-import boto3, with a clear install hint when [dr-s3] is absent."""
    try:
        import boto3  # noqa: PLC0415 — intentional lazy import (slim-image discipline)
        from botocore.config import Config

        return boto3, Config
    except ImportError as exc:  # pragma: no cover - import-guard
        raise StorageDependencyMissing(
            "the S3 backup sink requires the optional extra: pip install anoryx-sentinel[dr-s3]"
        ) from exc


class S3Sink(BackupSink):
    """Backs up dumps to an S3-compatible bucket. Key == object key."""

    def __init__(
        self,
        *,
        bucket: str,
        endpoint: str | None,
        region: str,
        access_key: str | None,
        secret_key: str | None,
    ) -> None:
        self._bucket = bucket
        boto3, Config = _load_boto3()
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,  # None => AWS S3
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4"),
        )

    async def store(self, local_path: Path, key: str) -> None:
        await asyncio.to_thread(self._client.upload_file, str(local_path), self._bucket, key)

    async def fetch(self, key: str, dest_path: Path) -> None:
        try:
            await asyncio.to_thread(self._client.download_file, self._bucket, key, str(dest_path))
        except Exception as exc:
            error_class = type(exc).__name__
            if error_class in ("ClientError", "NoSuchKey", "404"):
                raise BackupNotFound(f"no such backup: {key!r}") from exc
            raise

    async def list_objects(self) -> list[BackupObject]:
        def _list() -> list[BackupObject]:
            out = []
            paginator = self._client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket):
                for obj in page.get("Contents", []):
                    created_at = parse_created_at(obj["Key"])
                    if created_at is None:
                        continue
                    out.append(
                        BackupObject(key=obj["Key"], size_bytes=obj["Size"], created_at=created_at)
                    )
            return out

        return await asyncio.to_thread(_list)

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._client.delete_object, Bucket=self._bucket, Key=key)
