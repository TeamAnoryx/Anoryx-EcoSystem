"""Storage abstraction for the bulk pipeline (F-015, ADR-0018 §6).

One `Storage` interface; the MinIO/S3-compatible backend is wired v1 (Fork 3).
Object keys are server-minted, tenant-namespaced, and unguessable; presigned
grants are single-object + short-TTL + size-capped. The pipeline NEVER fetches
an arbitrary URL — only a validated key against the single configured endpoint
(R4: SSRF surface structurally removed).
"""

from __future__ import annotations

from bulk.storage.base import ObjectMeta, PresignedUpload, Storage
from bulk.storage.keys import (
    key_belongs_to_tenant,
    mint_object_key,
    validate_object_key,
)

__all__ = [
    "Storage",
    "ObjectMeta",
    "PresignedUpload",
    "mint_object_key",
    "validate_object_key",
    "key_belongs_to_tenant",
    "get_storage",
]


def get_storage() -> Storage:
    """Return the configured Storage backend (Fork 3: MinIO/S3 via one client).

    Lazy-imports the backend so the slim image / a non-bulk deploy imports
    `bulk` without the [bulk] storage client installed.
    """
    from bulk.storage.minio_backend import MinioStorage

    return MinioStorage()
