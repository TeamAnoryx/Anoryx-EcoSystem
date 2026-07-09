"""ProviderRegistry.refresh_credentials() tests (F-027, ADR-0033).

Proves: (1) a successful fetch swaps the live adapter's credential in place
(no adapter/client recreation — reads AnthropicAdapter._api_key /
BedrockAdapter._access_key_id directly to prove the swap took effect),
(2) strict=True removes a provider on fetch failure (fail-closed, matches
init()'s posture), (3) strict=False keeps the last-known-good credential on
fetch failure (bounded-lag rotation, not an instant kill switch)."""

from __future__ import annotations

import pytest

from gateway.config import GatewaySettings
from gateway.keyvault.base import ProviderCredentials
from gateway.keyvault.exceptions import KeyFetchError
from gateway.router.registry import ProviderRegistry

_BASE_KWARGS = {
    "upstream_base_url": "http://fake-upstream",
    "database_url": "postgresql+asyncpg://fake/db",
    "app_database_url": "postgresql+asyncpg://fake/appdb",
    "sentinel_key_secret": "test-secret",
}


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    for var in (
        "ANTHROPIC_API_KEY",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "ROUTER_DEFAULT_PROVIDERS",
    ):
        monkeypatch.delenv(var, raising=False)


def _settings(**extra) -> GatewaySettings:
    return GatewaySettings(**{**_BASE_KWARGS, **extra})


class _StaticKeySource:
    """Returns a fixed credential set, or raises for providers in `failing`."""

    def __init__(self, values: dict[str, ProviderCredentials], failing: set[str] = frozenset()):
        self._values = values
        self._failing = failing

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        if provider in self._failing:
            raise KeyFetchError(f"{provider}: simulated failure")
        return self._values[provider]


@pytest.mark.asyncio
async def test_refresh_swaps_anthropic_key_in_place():
    reg = ProviderRegistry()
    reg.init(_settings(anthropic_api_key="original-key"))
    adapter = reg.get("anthropic")
    assert adapter._api_key == "original-key"

    source = _StaticKeySource(
        {"anthropic": ProviderCredentials(provider="anthropic", values={"api_key": "rotated-key"})}
    )
    await reg.refresh_credentials(source)

    assert reg.get("anthropic") is adapter  # same instance — no recreation
    assert adapter._api_key == "rotated-key"


@pytest.mark.asyncio
async def test_refresh_swaps_bedrock_credentials_in_place():
    reg = ProviderRegistry()
    reg.init(
        _settings(
            aws_region="us-east-1",
            aws_access_key_id="orig-id",
            aws_secret_access_key="orig-secret",
        )
    )
    adapter = reg.get("bedrock")

    source = _StaticKeySource(
        {
            "bedrock": ProviderCredentials(
                provider="bedrock",
                values={
                    "region": "us-west-2",
                    "access_key_id": "rotated-id",
                    "secret_access_key": "rotated-secret",
                },
            )
        }
    )
    await reg.refresh_credentials(source)

    assert adapter._region == "us-west-2"
    assert adapter._access_key_id == "rotated-id"
    assert adapter._secret_access_key == "rotated-secret"


@pytest.mark.asyncio
async def test_strict_refresh_failure_removes_provider():
    reg = ProviderRegistry()
    reg.init(_settings(anthropic_api_key="original-key"))
    assert "anthropic" in reg.available_providers()

    source = _StaticKeySource({}, failing={"anthropic"})
    await reg.refresh_credentials(source, strict=True)

    assert "anthropic" not in reg.available_providers()
    assert reg.get("anthropic") is None


@pytest.mark.asyncio
async def test_non_strict_refresh_failure_keeps_last_known_good():
    reg = ProviderRegistry()
    reg.init(_settings(anthropic_api_key="original-key"))
    adapter = reg.get("anthropic")

    source = _StaticKeySource({}, failing={"anthropic"})
    await reg.refresh_credentials(source, strict=False)

    assert "anthropic" in reg.available_providers()
    assert reg.get("anthropic") is adapter
    assert adapter._api_key == "original-key"  # unchanged


@pytest.mark.asyncio
async def test_refresh_is_a_noop_for_providers_without_an_adapter():
    reg = ProviderRegistry()
    reg.init(_settings())  # no anthropic/bedrock configured
    source = _StaticKeySource(
        {"anthropic": ProviderCredentials(provider="anthropic", values={"api_key": "unused"})}
    )
    await reg.refresh_credentials(source)  # must not raise
    assert reg.available_providers() == {"openai"}
