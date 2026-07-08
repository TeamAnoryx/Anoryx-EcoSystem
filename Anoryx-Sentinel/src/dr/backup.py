"""Backup: pg_dump the source database, store the dump via the configured
sink, apply retention cleanup (F-024, ADR-0030).

Always dumps via the PRIVILEGED connection (DATABASE_URL) — RLS would
otherwise silently scope pg_dump's own queries to whatever role it connects
as, and the privileged/BYPASSRLS role is the only one that sees every
tenant's rows (mirrors how Alembic migrations and hash-chain ops already run
privileged, persistence/database.py's documented split).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from dr.backends.base import BackupSink
from dr.exceptions import BackupFailed
from dr.key_format import make_key
from dr.pg_url import parse_pg_url

log = structlog.get_logger(__name__)

_STDERR_LOG_CAP = 2000


@dataclass(frozen=True, slots=True)
class BackupResult:
    key: str
    size_bytes: int
    duration_s: float
    deleted_for_retention: list[str]


def _decode_stderr(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")[:_STDERR_LOG_CAP]


async def _apply_retention(sink: BackupSink, retention_days: int, *, now: datetime) -> list[str]:
    cutoff = now - timedelta(days=retention_days)
    deleted: list[str] = []
    for obj in await sink.list_objects():
        created = datetime.fromisoformat(obj.created_at.replace("Z", "+00:00"))
        if created < cutoff:
            await sink.delete(obj.key)
            deleted.append(obj.key)
    return deleted


async def run_backup(
    sink: BackupSink,
    *,
    source_database_url: str,
    retention_days: int,
    pg_dump_bin: str = "pg_dump",
    now: datetime | None = None,
) -> BackupResult:
    """pg_dump (custom format, -Fc) source_database_url, store under a
    timestamp-derived key, then delete backups older than retention_days.

    Raises BackupFailed if pg_dump exits non-zero. Never logs the connection
    URL (carries a password) or dump bytes.
    """
    start = time.monotonic()
    conn = parse_pg_url(source_database_url)
    now = now or datetime.now(UTC)
    key = make_key(now)

    with tempfile.TemporaryDirectory(prefix="sentinel-dr-backup-") as tmp:
        dump_path = Path(tmp) / "dump.pgdump"
        cmd = [pg_dump_bin, *conn.cli_args(), "-Fc", "--no-owner", "-f", str(dump_path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=conn.env(dict(os.environ)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            log.error("dr_backup_pg_dump_failed", returncode=proc.returncode)
            raise BackupFailed(f"pg_dump exited {proc.returncode}: {_decode_stderr(stderr)}")

        size_bytes = dump_path.stat().st_size
        await sink.store(dump_path, key)

    deleted = await _apply_retention(sink, retention_days, now=now)
    duration_s = time.monotonic() - start
    log.info(
        "dr_backup_completed",
        key=key,
        size_bytes=size_bytes,
        duration_s=round(duration_s, 3),
        deleted_for_retention=len(deleted),
    )
    return BackupResult(
        key=key, size_bytes=size_bytes, duration_s=duration_s, deleted_for_retention=deleted
    )
