"""Unit tests for KeyVaultSettings validation (F-027)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gateway.keyvault.settings import KeyVaultSettings


def test_env_backend_is_default():
    settings = KeyVaultSettings()
    assert settings.keyvault_backend == "env"


def test_unknown_backend_rejected():
    with pytest.raises(ValidationError):
        KeyVaultSettings(keyvault_backend="s3")


def test_non_positive_ttl_rejected():
    with pytest.raises(ValidationError):
        KeyVaultSettings(keyvault_cache_ttl_seconds=0)


def test_vault_backend_requires_addr_and_token():
    with pytest.raises(ValidationError):
        KeyVaultSettings(keyvault_backend="vault")


def test_vault_backend_accepted_with_addr_and_token():
    settings = KeyVaultSettings(
        keyvault_backend="vault", vault_addr="https://vault.internal", vault_token="root"
    )
    assert settings.keyvault_backend == "vault"


def test_kms_backend_has_no_required_extra_fields():
    settings = KeyVaultSettings(keyvault_backend="kms")
    assert settings.keyvault_backend == "kms"
