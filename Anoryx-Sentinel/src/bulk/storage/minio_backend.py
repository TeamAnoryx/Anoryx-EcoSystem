"""MinIO / S3-compatible storage backend (F-015, ADR-0018 §6, Fork 3).

ONE boto3 S3 client bound to a SINGLE configured endpoint at construction. There
is no per-call host/URL parameter anywhere — the worker addresses objects by
validated key only, so the SSRF class (internal/metadata fetch) is structurally
removed (R4 / vector 8). The same class serves MinIO (endpoint set) and AWS S3
(endpoint None) — S3 lives behind this interface (Fork 3).

boto3 is SYNC. Presign generation is pure (signing, no network) and called
directly; network ops (fetch/head/delete) run in asyncio.to_thread so the worker
event loop is never blocked.

The boto3 client + credentials are SECRETS-adjacent — never logged. Exception
messages carry only the error CLASS, never object bytes / keys / credentials.
"""

from __future__ import annotations

import asyncio

import structlog

from bulk.config import get_bulk_settings
from bulk.exceptions import (
    ObjectTooLarge,
    StorageDependencyMissing,
    StorageError,
)
from bulk.storage.base import ObjectMeta, PresignedUpload, Storage
from bulk.storage.keys import validate_object_key

log = structlog.get_logger(__name__)


def _load_boto3():
    """Lazy-import boto3, with a clear install hint when the [bulk] extra is absent."""
    try:
        import boto3  # noqa: PLC0415 — intentional lazy import (slim-image discipline)
        from botocore.config import Config

        return boto3, Config
    except ImportError as exc:  # pragma: no cover - import-guard
        raise StorageDependencyMissing(
            "bulk storage backend requires the optional extra: " "pip install anoryx-sentinel[bulk]"
        ) from exc


class MinioStorage(Storage):
    """S3-compatible backend (MinIO wired v1; AWS S3 selectable by endpoint=None)."""

    def __init__(self) -> None:
        settings = get_bulk_settings()
        self._bucket = settings.bulk_storage_bucket
        boto3, Config = _load_boto3()
        # signature_version s3v4 is required for presigned POST + MinIO.
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.bulk_storage_endpoint,  # None => AWS S3
            region_name=settings.bulk_storage_region,
            aws_access_key_id=settings.bulk_storage_access_key,
            aws_secret_access_key=settings.bulk_storage_secret_key,
            config=Config(signature_version="s3v4"),
        )

    # ----------------------------------------------------------------- presign
    def presign_upload(self, key: str, *, max_bytes: int, ttl: int) -> PresignedUpload:
        """Presigned POST policy: pinned key + content-length-range + expiry."""
        validate_object_key(key)
        try:
            presigned = self._client.generate_presigned_post(
                Bucket=self._bucket,
                Key=key,
                # Pin the exact key; cap size at [1, max_bytes] (server-enforced).
                Conditions=[
                    {"key": key},
                    ["content-length-range", 1, max_bytes],
                ],
                ExpiresIn=ttl,
            )
        except Exception as exc:
            raise StorageError(f"presign_upload failed: {type(exc).__name__}") from exc
        return PresignedUpload(
            url=presigned["url"],
            fields=presigned["fields"],
            key=key,
            max_bytes=max_bytes,
            expires_in=ttl,
        )

    def presign_download(self, key: str, *, ttl: int) -> str:
        validate_object_key(key)
        try:
            return self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self._bucket, "Key": key},
                ExpiresIn=ttl,
            )
        except Exception as exc:
            raise StorageError(f"presign_download failed: {type(exc).__name__}") from exc

    # ------------------------------------------------------------------- io
    async def fetch(self, key: str, *, max_bytes: int) -> bytes:
        """Download object bytes by key; reject oversize at read time (backstop)."""
        validate_object_key(key)
        return await asyncio.to_thread(self._fetch_blocking, key, max_bytes)

    def _fetch_blocking(self, key: str, max_bytes: int) -> bytes:
        try:
            obj = self._client.get_object(Bucket=self._bucket, Key=key)
            body = obj["Body"]
            try:
                # Read one byte past the cap to detect oversize without buffering all.
                data = body.read(max_bytes + 1)
            finally:
                body.close()
        except Exception as exc:
            raise StorageError(f"fetch failed: {type(exc).__name__}") from exc
        if len(data) > max_bytes:
            raise ObjectTooLarge("object exceeds per-file size cap")
        return data

    async def head(self, key: str) -> ObjectMeta:
        validate_object_key(key)
        return await asyncio.to_thread(self._head_blocking, key)

    def _head_blocking(self, key: str) -> ObjectMeta:
        try:
            meta = self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            raise StorageError(f"head failed: {type(exc).__name__}") from exc
        return ObjectMeta(
            key=key,
            size=int(meta.get("ContentLength", 0)),
            declared_content_type=meta.get("ContentType"),
        )

    async def delete(self, key: str) -> None:
        validate_object_key(key)
        await asyncio.to_thread(self._delete_blocking, key)

    def _delete_blocking(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            raise StorageError(f"delete failed: {type(exc).__name__}") from exc
