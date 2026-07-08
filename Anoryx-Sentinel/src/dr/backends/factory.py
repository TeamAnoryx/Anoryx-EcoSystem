"""Build the configured BackupSink from DrSettings (F-024)."""

from __future__ import annotations

from dr.backends.base import BackupSink
from dr.backends.local import LocalDirSink
from dr.config import DrSettings


def build_sink(settings: DrSettings) -> BackupSink:
    if settings.dr_backup_sink == "s3":
        from dr.backends.s3 import S3Sink  # lazy: keeps boto3 optional

        return S3Sink(
            bucket=settings.dr_s3_bucket,
            endpoint=settings.dr_s3_endpoint,
            region=settings.dr_s3_region,
            access_key=settings.dr_s3_access_key,
            secret_key=settings.dr_s3_secret_key,
        )
    return LocalDirSink(settings.dr_local_backup_dir)
