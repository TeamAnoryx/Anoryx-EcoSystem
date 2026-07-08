"""Build a (cached) ProviderKeySource from settings (F-027)."""

from __future__ import annotations

from typing import Any

from gateway.config import GatewaySettings
from gateway.keyvault.base import ProviderKeySource
from gateway.keyvault.cache import CachedKeySource
from gateway.keyvault.env_source import EnvProviderKeySource
from gateway.keyvault.kms_source import KmsProviderKeySource
from gateway.keyvault.settings import KeyVaultSettings
from gateway.keyvault.vault_source import VaultProviderKeySource


def build_key_source(
    gateway_settings: GatewaySettings,
    keyvault_settings: KeyVaultSettings,
    *,
    vault_client: Any = None,
    kms_client: Any = None,
) -> ProviderKeySource:
    """Return the configured backend, wrapped in a TTL cache."""
    backend = keyvault_settings.keyvault_backend

    source: ProviderKeySource
    if backend == "env":
        source = EnvProviderKeySource(gateway_settings)
    elif backend == "vault":
        source = VaultProviderKeySource(
            vault_addr=keyvault_settings.vault_addr,
            vault_token=keyvault_settings.vault_token,
            mount_point=keyvault_settings.vault_mount,
            path_prefix=keyvault_settings.vault_path_prefix,
            client=vault_client,
        )
    elif backend == "kms":
        source = KmsProviderKeySource(
            region=keyvault_settings.kms_region or gateway_settings.aws_region,
            client=kms_client,
        )
    else:  # pragma: no cover — KeyVaultSettings validates this already
        raise ValueError(f"unknown keyvault_backend: {backend!r}")

    return CachedKeySource(source, ttl_seconds=keyvault_settings.keyvault_cache_ttl_seconds)
