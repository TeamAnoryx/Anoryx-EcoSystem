from __future__ import annotations

import pytest

from dr.backends.factory import build_sink
from dr.backends.local import LocalDirSink
from dr.config import DrSettings, _reset_dr_settings_for_testing, get_dr_settings


@pytest.fixture(autouse=True)
def _reset():
    _reset_dr_settings_for_testing()
    yield
    _reset_dr_settings_for_testing()


def test_defaults_are_local_sink_disabled():
    settings = DrSettings()
    assert settings.dr_backup_enabled is False
    assert settings.dr_backup_sink == "local"
    assert settings.dr_retention_days == 14


def test_invalid_sink_rejected():
    with pytest.raises(ValueError):
        DrSettings(dr_backup_sink="ftp")


def test_non_positive_retention_rejected():
    with pytest.raises(ValueError):
        DrSettings(dr_retention_days=0)


def test_get_dr_settings_is_cached():
    a = get_dr_settings()
    b = get_dr_settings()
    assert a is b


def test_build_sink_local_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("DR_LOCAL_BACKUP_DIR", str(tmp_path))
    settings = DrSettings()
    sink = build_sink(settings)
    assert isinstance(sink, LocalDirSink)


def test_build_sink_s3_requires_boto3_or_raises_import_hint(monkeypatch):
    settings = DrSettings(dr_backup_sink="s3")
    try:
        sink = build_sink(settings)
    except Exception as exc:
        assert "dr-s3" in str(exc)
        return
    from dr.backends.s3 import S3Sink

    assert isinstance(sink, S3Sink)
