"""Bulk-pipeline configuration (F-015, ADR-0018).

Reads env via pydantic-settings, matching the GatewaySettings convention (no env
prefix: a field `bulk_storage_endpoint` reads `BULK_STORAGE_ENDPOINT`). Storage
credentials are SECRETS — env-only, never in code/config/logs (CLAUDE.md #4).
The gateway's `redis_url` / `database_url` / `app_database_url` are reused from
GatewaySettings; this file holds only bulk-specific knobs.

NEVER log: bulk_storage_access_key, bulk_storage_secret_key.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Defaults chosen LEAN (ADR-0018 §10): caps that bound resource use without
# pretending to autoscale. Tune via env in deploy.
_DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB per file
_DEFAULT_MAX_FILES_PER_BATCH = 1000
_DEFAULT_PRESIGN_TTL = 900  # 15 min — short-lived single-object grant (R3)
_DEFAULT_RETRY_MAX = 3  # bounded retry before DLQ (R7)


class BulkSettings(BaseSettings):
    """F-015 bulk runtime configuration. Storage creds fail-loud only at use."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Storage (Fork 3: MinIO wired; S3 = same client, endpoint None) ---
    # endpoint None => AWS S3; set to e.g. http://minio:9000 for MinIO/self-host.
    bulk_storage_endpoint: str | None = None
    bulk_storage_bucket: str = "sentinel-bulk"
    bulk_storage_region: str = "us-east-1"
    bulk_storage_access_key: str | None = None  # secret
    bulk_storage_secret_key: str | None = None  # secret

    # --- Upload caps (R3) ---
    bulk_max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES
    bulk_max_files_per_batch: int = _DEFAULT_MAX_FILES_PER_BATCH
    bulk_presign_ttl_seconds: int = _DEFAULT_PRESIGN_TTL

    # --- Queue / worker (Redis Streams; reuses the F-009 redis_url) ---
    bulk_stream_key: str = "sentinel:bulk:jobs"
    bulk_dlq_stream_key: str = "sentinel:bulk:dlq"
    bulk_consumer_group: str = "bulk-workers"
    bulk_retry_max: int = _DEFAULT_RETRY_MAX

    # --- Per-tenant fairness caps (R8 / vector 16) ---
    bulk_max_concurrent_batches_per_tenant: int = 5
    bulk_max_inflight_files_per_tenant: int = 5000

    @field_validator(
        "bulk_max_file_bytes",
        "bulk_max_files_per_batch",
        "bulk_presign_ttl_seconds",
        "bulk_retry_max",
        "bulk_max_concurrent_batches_per_tenant",
        "bulk_max_inflight_files_per_tenant",
    )
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("bulk numeric settings must be > 0")
        return v


@lru_cache(maxsize=1)
def get_bulk_settings() -> BulkSettings:
    """Cached BulkSettings accessor (one instance per process)."""
    return BulkSettings()


def _reset_bulk_settings_for_testing() -> None:
    """Clear the cached settings (test helper only)."""
    get_bulk_settings.cache_clear()
