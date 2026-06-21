"""Storage interface + value types (F-015, ADR-0018 §6).

The interface is deliberately narrow: mint a presigned single-object upload,
mint a presigned single-object download, fetch object bytes by key (server-side),
head, delete. Presign methods are pure (signing only, no network) and synchronous;
fetch/head/delete touch the network and are async (the worker awaits them).

A backend implementation MUST:
  - bind to ONE configured endpoint (no per-call host/URL — R4 SSRF defense),
  - validate the key on every operation (tenant-namespaced, no traversal — R3),
  - enforce the size cap on the presigned upload (content-length-range) AND
    re-check it on fetch (backstop — vector 5).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PresignedUpload:
    """A presigned single-object upload grant (S3 POST policy form).

    `url` + `fields` are POSTed by the client with the object as the file part.
    The signed policy pins the exact `key`, a `content-length-range` (size cap),
    and an expiry — so the grant cannot be reused for another object/tenant and
    expires (R3 / vectors 3, 5).
    """

    url: str
    fields: dict[str, str]
    key: str
    max_bytes: int
    expires_in: int


@dataclass(frozen=True, slots=True)
class ObjectMeta:
    """Minimal object metadata from a head() call."""

    key: str
    size: int
    # The storage-reported content-type. NEVER trusted for processing decisions
    # (R4 / vector 6); recorded for observability only.
    declared_content_type: str | None


class Storage(ABC):
    """Object-storage interface. One bound endpoint; key-only addressing."""

    @abstractmethod
    def presign_upload(self, key: str, *, max_bytes: int, ttl: int) -> PresignedUpload:
        """Mint a presigned single-object upload grant (size-capped, short-TTL)."""

    @abstractmethod
    def presign_download(self, key: str, *, ttl: int) -> str:
        """Mint a presigned single-object GET URL (short-TTL)."""

    @abstractmethod
    async def fetch(self, key: str, *, max_bytes: int) -> bytes:
        """Download object bytes by key. Rejects oversize at read time (backstop)."""

    @abstractmethod
    async def head(self, key: str) -> ObjectMeta:
        """Return object metadata, or raise StorageError if absent."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete an object by key (best-effort cleanup)."""
