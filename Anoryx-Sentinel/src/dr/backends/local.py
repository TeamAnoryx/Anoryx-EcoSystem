"""Local-directory backup sink (F-024, ADR-0030).

The default sink — zero extra dependencies, always available. Intended for a
PVC-mounted directory in-cluster. HONEST LIMITATION (see config.py / ADR-0030 /
deploy/DISASTER-RECOVERY.md): this does NOT provide off-cluster durability — a
lost/corrupted volume takes the backups with it. Configure the S3 sink
(src/dr/backends/s3.py) for genuine disaster-recovery posture.

Async methods run blocking filesystem I/O in asyncio.to_thread so this sink is
a drop-in for the same interface the S3 sink implements (which does real
network I/O off the event loop).
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import structlog

from dr.backends.base import BackupObject, BackupSink
from dr.exceptions import BackupNotFound
from dr.key_format import parse_created_at

log = structlog.get_logger(__name__)


class LocalDirSink(BackupSink):
    """Stores dumps as files under a single directory. Key == filename."""

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)

    def _path(self, key: str) -> Path:
        # Keys are minted by backup.py (timestamp + fixed suffix, no separators
        # that could traverse) — reject anything else defensively.
        if "/" in key or "\\" in key or key in (".", ".."):
            raise ValueError(f"invalid backup key: {key!r}")
        return self._dir / key

    async def store(self, local_path: Path, key: str) -> None:
        def _copy() -> None:
            self._dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path, self._path(key))

        await asyncio.to_thread(_copy)

    async def fetch(self, key: str, dest_path: Path) -> None:
        src = self._path(key)

        def _copy() -> None:
            if not src.is_file():
                raise BackupNotFound(f"no such backup: {key!r}")
            shutil.copy2(src, dest_path)

        await asyncio.to_thread(_copy)

    async def list_objects(self) -> list[BackupObject]:
        def _list() -> list[BackupObject]:
            if not self._dir.is_dir():
                return []
            out = []
            for p in self._dir.iterdir():
                if not p.is_file():
                    continue
                created_at = parse_created_at(p.name)
                if created_at is None:
                    continue  # not one of our keys — ignore foreign files
                out.append(
                    BackupObject(key=p.name, size_bytes=p.stat().st_size, created_at=created_at)
                )
            return out

        return await asyncio.to_thread(_list)

    async def delete(self, key: str) -> None:
        def _delete() -> None:
            self._path(key).unlink(missing_ok=True)

        await asyncio.to_thread(_delete)
