from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from dr.backends.local import LocalDirSink
from dr.exceptions import BackupNotFound
from dr.key_format import make_key


@pytest.mark.asyncio
async def test_store_then_fetch_round_trip(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    src = tmp_path / "dump.bin"
    src.write_bytes(b"hello dump")
    key = make_key(datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC))

    await sink.store(src, key)

    dest = tmp_path / "restored.bin"
    await sink.fetch(key, dest)
    assert dest.read_bytes() == b"hello dump"


@pytest.mark.asyncio
async def test_fetch_missing_key_raises(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    with pytest.raises(BackupNotFound):
        await sink.fetch("sentinel-backup-20260707T030000Z.dump", tmp_path / "out.bin")


@pytest.mark.asyncio
async def test_list_objects_ignores_foreign_files(tmp_path):
    backup_dir = tmp_path / "backups"
    sink = LocalDirSink(str(backup_dir))
    src = tmp_path / "dump.bin"
    src.write_bytes(b"data")
    key = make_key(datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC))
    await sink.store(src, key)
    backup_dir.mkdir(parents=True, exist_ok=True)
    (backup_dir / "README.txt").write_text("not a backup")

    objects = await sink.list_objects()
    assert [o.key for o in objects] == [key]
    assert objects[0].size_bytes == 4
    assert objects[0].created_at == "2026-07-07T03:00:00Z"


@pytest.mark.asyncio
async def test_list_objects_empty_dir_returns_empty(tmp_path):
    sink = LocalDirSink(str(tmp_path / "does-not-exist-yet"))
    assert await sink.list_objects() == []


@pytest.mark.asyncio
async def test_delete_removes_object(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    src = tmp_path / "dump.bin"
    src.write_bytes(b"data")
    key = make_key(datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC))
    await sink.store(src, key)
    assert len(await sink.list_objects()) == 1

    await sink.delete(key)
    assert await sink.list_objects() == []


@pytest.mark.asyncio
async def test_delete_missing_key_is_noop(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    await sink.delete("sentinel-backup-20260707T030000Z.dump")  # must not raise


@pytest.mark.asyncio
async def test_path_traversal_key_rejected(tmp_path):
    sink = LocalDirSink(str(tmp_path / "backups"))
    with pytest.raises(ValueError):
        await sink.store(Path("dummy"), "../escape.dump")
