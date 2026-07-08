"""KeyVaultSettings (F-027) — which backend, and its connection config.

Separate from GatewaySettings.keyvault_backend (the single field registry.py
needs for the configured_providers() fail-closed check) — this settings
object carries the backend-specific connection details (Vault addr/token,
KMS region, cache TTL) so gateway/config.py doesn't grow Vault/KMS-specific
fields it has no other reason to know about.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class KeyVaultSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    keyvault_backend: str = "env"  # "env" | "vault" | "kms"
    keyvault_cache_ttl_seconds: float = 300.0

    # Vault backend
    vault_addr: str | None = None
    vault_token: str | None = None  # secret
    vault_mount: str = "secret"
    vault_path_prefix: str = "sentinel/providers"

    # KMS backend
    kms_region: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "KeyVaultSettings":
        if self.keyvault_backend not in ("env", "vault", "kms"):
            raise ValueError(
                f"keyvault_backend must be one of env/vault/kms, got {self.keyvault_backend!r}"
            )
        if self.keyvault_cache_ttl_seconds <= 0:
            raise ValueError("keyvault_cache_ttl_seconds must be > 0")
        if self.keyvault_backend == "vault" and not (self.vault_addr and self.vault_token):
            raise ValueError("keyvault_backend=vault requires VAULT_ADDR and VAULT_TOKEN")
        return self


@lru_cache
def get_keyvault_settings() -> KeyVaultSettings:
    return KeyVaultSettings()


def _reset_keyvault_settings_for_testing() -> None:
    get_keyvault_settings.cache_clear()
