"""ProviderRegistry init/teardown tests (F-006, ADR-0008 §3 / §10).

Proves fail-closed availability: a provider with no configured credential is NOT
initialised. Teardown closes the dedicated Anthropic httpx client. No network.
"""

from __future__ import annotations

import pytest

from gateway.config import GatewaySettings, _reset_settings
from gateway.router.registry import ProviderRegistry

_BASE_KWARGS = {
    "upstream_base_url": "http://fake-upstream",
    "database_url": "postgresql+asyncpg://fake/db",
    "app_database_url": "postgresql+asyncpg://fake/appdb",
    "sentinel_key_secret": "test-secret",
}


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """Test-hygiene (STEP-6 carry-over): GatewaySettings reads os.environ for any
    field not passed as a kwarg, so a CI shell that exports provider credentials
    would defeat the fail-closed / fail-loud assertions below (a provider would
    look 'configured' when the test intends it absent). Clear the provider vars
    for every test in this module so availability is determined solely by the
    explicit kwargs each test passes.
    """
    for var in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "ROUTER_DEFAULT_PROVIDERS",
        "ROUTER_MAX_FALLBACKS",
    ):
        monkeypatch.delenv(var, raising=False)


def _settings(**extra) -> GatewaySettings:
    # Construct directly (kwargs). cors_allowed_origins uses its [] default.
    kwargs = {**_BASE_KWARGS, **{k.lower(): v for k, v in extra.items()}}
    return GatewaySettings(**kwargs)


def test_openai_always_available_others_fail_closed():
    reg = ProviderRegistry()
    reg.init(_settings())  # no anthropic/aws creds
    assert reg.available_providers() == {"openai"}
    assert reg.get("anthropic") is None
    assert reg.get("bedrock") is None


def test_anthropic_initialised_when_key_present():
    reg = ProviderRegistry()
    reg.init(_settings(ANTHROPIC_API_KEY="REPLACE_ME-key"))
    assert "anthropic" in reg.available_providers()
    assert reg.get("anthropic") is not None


def test_bedrock_initialised_when_all_aws_present():
    reg = ProviderRegistry()
    reg.init(
        _settings(
            AWS_REGION="us-east-1",
            AWS_ACCESS_KEY_ID="REPLACE_ME-id",
            AWS_SECRET_ACCESS_KEY="REPLACE_ME-secret",  # noqa: S106 — placeholder
        )
    )
    assert "bedrock" in reg.available_providers()


def test_half_configured_bedrock_is_fail_loud():
    # Only region set -> the model_validator must reject it at construction.
    with pytest.raises(ValueError, match="half-configured"):
        _settings(AWS_REGION="us-east-1")


@pytest.mark.asyncio
async def test_teardown_closes_anthropic_client():
    reg = ProviderRegistry()
    reg.init(_settings(ANTHROPIC_API_KEY="REPLACE_ME-key"))
    client = reg._anthropic_client
    assert client is not None and not client.is_closed
    await reg.teardown()
    assert client.is_closed
    assert reg.available_providers() == set()


def test_init_is_idempotent():
    reg = ProviderRegistry()
    reg.init(_settings(ANTHROPIC_API_KEY="REPLACE_ME-key"))
    first = reg.get("anthropic")
    reg.init(_settings())  # second call is a no-op; must not reset adapters
    assert reg.get("anthropic") is first


def teardown_module(module):  # noqa: D401 - pytest hook
    _reset_settings()
