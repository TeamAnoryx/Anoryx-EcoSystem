"""Unit tests for EnvProviderKeySource (F-027) — no DB/network needed."""

from __future__ import annotations

import pytest

from gateway.keyvault.env_source import EnvProviderKeySource
from gateway.keyvault.exceptions import KeyNotConfigured


@pytest.mark.asyncio
async def test_anthropic_key_fetched_when_set(make_gateway_settings):
    settings = make_gateway_settings(anthropic_api_key="sk-ant-fake")
    source = EnvProviderKeySource(settings)
    creds = await source.fetch_credentials("anthropic")
    assert creds.provider == "anthropic"
    assert creds.values == {"api_key": "sk-ant-fake"}


@pytest.mark.asyncio
async def test_anthropic_key_not_configured_when_unset(make_gateway_settings):
    settings = make_gateway_settings()
    source = EnvProviderKeySource(settings)
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_bedrock_credentials_fetched_when_all_three_set(make_gateway_settings):
    settings = make_gateway_settings(
        aws_region="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="fake-secret",
    )
    source = EnvProviderKeySource(settings)
    creds = await source.fetch_credentials("bedrock")
    assert creds.values == {
        "region": "us-east-1",
        "access_key_id": "AKIAFAKE",
        "secret_access_key": "fake-secret",
    }


@pytest.mark.asyncio
async def test_bedrock_not_configured_when_no_aws_fields_set(make_gateway_settings):
    # GatewaySettings itself rejects a HALF-configured Bedrock at construction
    # (model_validator, ADR-0008 §10) — the only reachable "not configured"
    # state here is all-three-unset.
    settings = make_gateway_settings()
    source = EnvProviderKeySource(settings)
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("bedrock")


@pytest.mark.asyncio
async def test_unknown_provider_not_configured(make_gateway_settings):
    settings = make_gateway_settings()
    source = EnvProviderKeySource(settings)
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("openai")
