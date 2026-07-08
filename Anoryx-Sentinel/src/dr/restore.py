"""Restore: fetch a dump from the configured sink, pg_restore it into an
EXPLICIT target database, then verify the append-only hash chain is intact
(F-024, ADR-0030).

Fail-safe (CLAUDE.md #5): a restore whose post-restore chain validation fails
is NOT treated as successful — run_restore() raises ChainValidationFailed
rather than returning a "partially OK" result, so callers (the CLI, any
future automation) cannot silently promote a restored database whose audit
trail cannot be trusted.

target_database_url is ALWAYS an explicit, operator-supplied argument — never
defaulted to the running gateway's own DATABASE_URL. A restore is destructive
to whatever it targets; there is no automated/scheduled restore path (only
backup is CronJob-driven — see deploy/DISASTER-RECOVERY.md).
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from dr.backends.base import BackupSink
from dr.exceptions import ChainValidationFailed, RestoreFailed
from dr.pg_url import parse_pg_url

log = structlog.get_logger(__name__)

_STDERR_LOG_CAP = 2000


@dataclass(frozen=True, slots=True)
class RestoreResult:
    key: str
    duration_s: float
    rows_checked: int


def _decode_stderr(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")[:_STDERR_LOG_CAP]


def _asyncpg_url(raw: str) -> str:
    """postgresql[+driver]:// -> postgresql+asyncpg:// (mirrors
    persistence/database.py's normalizer; kept local — same precedent as
    tests/policy/conftest.py's own _async_url — rather than importing a
    private helper across module boundaries)."""
    url = re.sub(r"^postgresql\+\w+://", "postgresql://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


async def _validate_chain_on(database_url: str):
    from persistence.repositories.audit_log_repository import AuditLogRepository

    engine = create_async_engine(
        _asyncpg_url(database_url),
        pool_pre_ping=True,
        echo=False,
        # Marks the connection privileged (mirrors _get_privileged_engine) so
        # AuditLogRepository._assert_privileged_session() accepts it — the
        # PRIMARY check is still the Postgres role itself (current_user), which
        # this connection has because it authenticates as the same role the
        # target_database_url carries (must be the privileged role, not
        # sentinel_app, or validate_chain() correctly refuses — fail-closed).
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )
    try:
        async with factory() as session, session.begin():
            return await AuditLogRepository(session).validate_chain()
    finally:
        await engine.dispose()


async def run_restore(
    sink: BackupSink,
    key: str,
    *,
    target_database_url: str,
    pg_restore_bin: str = "pg_restore",
) -> RestoreResult:
    """Fetch key, pg_restore --clean --if-exists into target_database_url,
    then validate the restored hash chain. Raises RestoreFailed on a
    pg_restore error, ChainValidationFailed if the chain does not verify."""
    start = time.monotonic()
    conn = parse_pg_url(target_database_url)

    with tempfile.TemporaryDirectory(prefix="sentinel-dr-restore-") as tmp:
        dump_path = Path(tmp) / "dump.pgdump"
        await sink.fetch(key, dump_path)

        cmd = [
            pg_restore_bin,
            *conn.cli_args(),
            "--clean",
            "--if-exists",
            "--no-owner",
            str(dump_path),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=conn.env(dict(os.environ)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            log.error("dr_restore_pg_restore_failed", returncode=proc.returncode)
            raise RestoreFailed(f"pg_restore exited {proc.returncode}: {_decode_stderr(stderr)}")

    chain_result = await _validate_chain_on(target_database_url)
    if not chain_result.is_valid:
        log.error(
            "dr_restore_chain_invalid",
            first_mismatch_sequence=chain_result.first_mismatch_sequence,
        )
        raise ChainValidationFailed(
            f"restored hash chain failed validation at "
            f"sequence={chain_result.first_mismatch_sequence}: {chain_result.error_detail}"
        )

    duration_s = time.monotonic() - start
    log.info(
        "dr_restore_completed",
        key=key,
        duration_s=round(duration_s, 3),
        rows_checked=chain_result.rows_checked,
    )
    return RestoreResult(key=key, duration_s=duration_s, rows_checked=chain_result.rows_checked)
