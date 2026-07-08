"""F-024 disaster-recovery configuration (ADR-0030).

Reads env via pydantic-settings, matching the GatewaySettings / BulkSettings
convention (no env prefix beyond the field name: `dr_backup_sink` reads
`DR_BACKUP_SINK`). Storage credentials are SECRETS — env-only, never in
code/config/logs (CLAUDE.md #4).

Two sinks (src/dr/backends/):
  local — a directory (PVC mount in-cluster). Zero extra dependencies, always
          available, the default. HONEST LIMITATION: local-only backup does
          NOT survive loss of the volume/cluster it's stored on — it protects
          against logical corruption / accidental deletion / a bad migration,
          not a full cluster/PV loss. See deploy/DISASTER-RECOVERY.md.
  s3    — S3/MinIO-compatible object storage (off-cluster durability). Same
          lib family as F-015 bulk / F-006 bedrock; lazy-imported behind the
          [dr-s3] extra.

NEVER log: dr_s3_access_key, dr_s3_secret_key, or any constructed DATABASE_URL
(carries a password).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_RETENTION_DAYS = 14


class DrSettings(BaseSettings):
    """F-024 disaster-recovery runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Backup schedule gate (Helm CronJob honors this too; default OFF) ---
    dr_backup_enabled: bool = False

    # --- Sink selection ---
    dr_backup_sink: str = "local"  # "local" | "s3"

    # --- Local sink (PVC-mounted directory) ---
    dr_local_backup_dir: str = "/var/lib/sentinel/backups"

    # --- S3 sink (endpoint None => AWS S3; set for MinIO/self-host) ---
    dr_s3_endpoint: str | None = None
    dr_s3_bucket: str = "sentinel-dr-backups"
    dr_s3_region: str = "us-east-1"
    dr_s3_access_key: str | None = None  # secret
    dr_s3_secret_key: str | None = None  # secret

    # --- Retention (applied after every successful backup) ---
    dr_retention_days: int = _DEFAULT_RETENTION_DAYS

    @field_validator("dr_backup_sink")
    @classmethod
    def _valid_sink(cls, v: str) -> str:
        if v not in ("local", "s3"):
            raise ValueError(f"dr_backup_sink must be 'local' or 's3', got {v!r}")
        return v

    @field_validator("dr_retention_days")
    @classmethod
    def _positive_retention(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("dr_retention_days must be > 0")
        return v


@lru_cache(maxsize=1)
def get_dr_settings() -> DrSettings:
    """Cached DrSettings accessor (one instance per process)."""
    return DrSettings()


def _reset_dr_settings_for_testing() -> None:
    """Clear the cached settings (test helper only)."""
    get_dr_settings.cache_clear()
