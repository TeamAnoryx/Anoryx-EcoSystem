"""Unit-level proof that run_restore() blocks on a failed chain validation
(F-024, CLAUDE.md #5 fail-safe) — no live Postgres / pg_restore binary
required. The real drill (tests/dr/test_backup_restore_drill.py) proves the
happy path against a live DB; this proves the wiring refuses a bad one.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dr.backends.local import LocalDirSink
from dr.exceptions import ChainValidationFailed, RestoreFailed
from dr.restore import run_restore
from persistence.repositories.audit_log_repository import ChainValidationResult


class _FakeProc:
    def __init__(self, returncode: int, stderr: bytes = b""):
        self.returncode = returncode
        self._stderr = stderr

    async def communicate(self):
        return b"", self._stderr


@pytest.mark.asyncio
async def test_run_restore_raises_on_invalid_chain(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    (tmp_path / "backups").mkdir(parents=True)
    (tmp_path / "backups" / "sentinel-backup-20260707T030000Z.dump").write_bytes(b"fake dump")

    invalid = ChainValidationResult(
        is_valid=False, rows_checked=5, first_mismatch_sequence=3, error_detail="row_hash mismatch"
    )

    with (
        patch(
            "dr.restore.asyncio.create_subprocess_exec", new=AsyncMock(return_value=_FakeProc(0))
        ),
        patch("dr.restore._validate_chain_on", new=AsyncMock(return_value=invalid)),
    ):
        with pytest.raises(ChainValidationFailed, match="sequence=3"):
            await run_restore(
                sink,
                "sentinel-backup-20260707T030000Z.dump",
                target_database_url="postgresql://sentinel:pw@localhost:5432/throwaway",
            )


@pytest.mark.asyncio
async def test_run_restore_succeeds_when_chain_valid(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    (tmp_path / "backups").mkdir(parents=True)
    (tmp_path / "backups" / "sentinel-backup-20260707T030000Z.dump").write_bytes(b"fake dump")

    valid = ChainValidationResult(
        is_valid=True, rows_checked=5, first_mismatch_sequence=None, error_detail=None
    )

    with (
        patch(
            "dr.restore.asyncio.create_subprocess_exec", new=AsyncMock(return_value=_FakeProc(0))
        ),
        patch("dr.restore._validate_chain_on", new=AsyncMock(return_value=valid)),
    ):
        result = await run_restore(
            sink,
            "sentinel-backup-20260707T030000Z.dump",
            target_database_url="postgresql://sentinel:pw@localhost:5432/throwaway",
        )
    assert result.rows_checked == 5


@pytest.mark.asyncio
async def test_run_restore_raises_on_pg_restore_nonzero_exit(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    (tmp_path / "backups").mkdir(parents=True)
    (tmp_path / "backups" / "sentinel-backup-20260707T030000Z.dump").write_bytes(b"fake dump")

    with patch(
        "dr.restore.asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=_FakeProc(1, stderr=b"pg_restore: error: could not connect")),
    ):
        with pytest.raises(RestoreFailed, match="pg_restore exited 1"):
            await run_restore(
                sink,
                "sentinel-backup-20260707T030000Z.dump",
                target_database_url="postgresql://sentinel:pw@localhost:5432/throwaway",
            )
