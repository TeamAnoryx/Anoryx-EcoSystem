"""Shared fixtures for F-027 provider-key-vaulting tests."""

from __future__ import annotations

import pytest

from gateway.config import GatewaySettings


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """GatewaySettings/KeyVaultSettings read os.environ for any field not
    passed as a kwarg — a CI shell that happens to export one of these would
    defeat this module's explicit-kwargs assertions. Mirrors
    tests/gateway/router/test_registry.py's identical fixture."""
    for var in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "ROUTER_DEFAULT_PROVIDERS",
        "ROUTER_MAX_FALLBACKS",
        "KEYVAULT_BACKEND",
        "KEYVAULT_CACHE_TTL_SECONDS",
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "VAULT_MOUNT",
        "VAULT_PATH_PREFIX",
        "KMS_REGION",
        "SENTINEL_KMS_CIPHERTEXT_ANTHROPIC",
        "SENTINEL_KMS_CIPHERTEXT_BEDROCK",
    ):
        monkeypatch.delenv(var, raising=False)


_BASE_KWARGS = {
    "upstream_base_url": "http://fake-upstream",
    "database_url": "postgresql+asyncpg://fake/db",
    "app_database_url": "postgresql+asyncpg://fake/appdb",
    "sentinel_key_secret": "test-secret",
}


@pytest.fixture
def make_gateway_settings():
    """Factory fixture: make_gateway_settings(**overrides) -> GatewaySettings."""

    def _make(**overrides: object) -> GatewaySettings:
        return GatewaySettings(**{**_BASE_KWARGS, **overrides})

    return _make
