"""Backup sink interface (F-024, ADR-0030).

Deliberately narrow: store a local dump file under a key, fetch a key back to
a local path, list keys (newest-first is NOT guaranteed by the interface —
callers sort by the returned BackupObject.created_at), delete a key. A sink
implementation MUST namespace keys so backups from different environments
sharing one bucket/directory cannot collide (the key format embeds a UTC
timestamp — see backup.py).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BackupObject:
    """Minimal metadata about a stored backup."""

    key: str
    size_bytes: int
    created_at: str  # RFC3339 UTC, parsed from the key's timestamp prefix


class BackupSink(ABC):
    """Where backup dumps live. One bound target (dir or bucket) per instance."""

    @abstractmethod
    async def store(self, local_path: Path, key: str) -> None:
        """Upload/copy the dump at local_path under key."""

    @abstractmethod
    async def fetch(self, key: str, dest_path: Path) -> None:
        """Download/copy key to dest_path. Raises BackupNotFound if absent."""

    @abstractmethod
    async def list_objects(self) -> list[BackupObject]:
        """Return all stored backups (any order — callers sort)."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a backup by key (best-effort — used by retention cleanup)."""
