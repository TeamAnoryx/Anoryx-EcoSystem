from __future__ import annotations

from datetime import UTC, datetime

from dr.key_format import make_key, parse_created_at


def test_make_key_shape():
    now = datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC)
    key = make_key(now)
    assert key == "sentinel-backup-20260707T030000Z.dump"


def test_make_key_normalizes_to_utc():
    from datetime import timedelta, timezone

    tz = timezone(timedelta(hours=-5))
    now = datetime(2026, 7, 7, 3, 0, 0, tzinfo=tz)  # 08:00 UTC
    key = make_key(now)
    assert key == "sentinel-backup-20260707T080000Z.dump"


def test_parse_created_at_round_trip():
    now = datetime(2026, 7, 7, 3, 0, 0, tzinfo=UTC)
    key = make_key(now)
    created_at = parse_created_at(key)
    assert created_at == "2026-07-07T03:00:00Z"


def test_parse_created_at_rejects_foreign_filename():
    assert parse_created_at("not-a-backup.txt") is None
    assert parse_created_at("sentinel-backup-bad.dump") is None
    assert parse_created_at("") is None
