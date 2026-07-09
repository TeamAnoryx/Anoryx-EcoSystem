"""Unit tests for build_key_source (F-027)."""

from __future__ import annotations

import pytest

from gateway.keyvault.cache import CachedKeySource
from gateway.keyvault.env_source import EnvProviderKeySource
from gateway.keyvault.factory import build_key_source
from gateway.keyvault.kms_source import KmsProviderKeySource
from gateway.keyvault.settings import KeyVaultSettings
from gateway.keyvault.vault_source import VaultProviderKeySource


@pytest.mark.asyncio
async def test_env_backend_wraps_env_source(make_gateway_settings):
    settings = make_gateway_settings(anthropic_api_key="sk-ant-fake")
    kv_settings = KeyVaultSettings(keyvault_backend="env")

    key_source = build_key_source(settings, kv_settings)

    assert isinstance(key_source, CachedKeySource)
    assert isinstance(key_source._source, EnvProviderKeySource)
    creds = await key_source.fetch_credentials("anthropic")
    assert creds.values == {"api_key": "sk-ant-fake"}


def test_vault_backend_wraps_vault_source(make_gateway_settings):
    settings = make_gateway_settings()
    kv_settings = KeyVaultSettings(
        keyvault_backend="vault", vault_addr="https://vault.internal", vault_token="root"
    )

    key_source = build_key_source(settings, kv_settings, vault_client=object())

    assert isinstance(key_source, CachedKeySource)
    assert isinstance(key_source._source, VaultProviderKeySource)


def test_kms_backend_wraps_kms_source_and_falls_back_to_gateway_aws_region(make_gateway_settings):
    settings = make_gateway_settings(
        aws_region="us-east-1", aws_access_key_id="AKIAFAKE", aws_secret_access_key="shh"
    )
    kv_settings = KeyVaultSettings(keyvault_backend="kms")

    key_source = build_key_source(settings, kv_settings, kms_client=object())

    assert isinstance(key_source, CachedKeySource)
    assert isinstance(key_source._source, KmsProviderKeySource)
    assert key_source._source._region == "us-east-1"


def test_kms_backend_prefers_explicit_kms_region(make_gateway_settings):
    # aws_region intentionally left unset — GatewaySettings rejects a
    # half-configured Bedrock (ADR-0008 §10), and this test only needs to
    # prove kms_region wins over whatever gateway_settings.aws_region is.
    settings = make_gateway_settings()
    kv_settings = KeyVaultSettings(keyvault_backend="kms", kms_region="eu-west-1")

    key_source = build_key_source(settings, kv_settings, kms_client=object())

    assert key_source._source._region == "eu-west-1"


def test_cache_ttl_propagated_from_settings(make_gateway_settings):
    settings = make_gateway_settings()
    kv_settings = KeyVaultSettings(keyvault_backend="env", keyvault_cache_ttl_seconds=42.0)

    key_source = build_key_source(settings, kv_settings)

    assert key_source._ttl_seconds == 42.0
