"""Unit tests for GatewaySettings.configured_providers() with F-027's
keyvault_backend field — the env backend must be byte-identical to
pre-F-027 behavior (default, zero-regression requirement)."""

from __future__ import annotations


def test_env_backend_unchanged_behavior_no_secrets(make_gateway_settings):
    settings = make_gateway_settings(keyvault_backend="env")
    assert settings.configured_providers() == {"openai"}


def test_env_backend_unchanged_behavior_with_secrets(make_gateway_settings):
    settings = make_gateway_settings(
        keyvault_backend="env",
        anthropic_api_key="sk-ant-fake",
        aws_region="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="shh",
    )
    assert settings.configured_providers() == {"openai", "anthropic", "bedrock"}


def test_vault_backend_uses_router_default_providers_not_raw_secrets(make_gateway_settings):
    # No raw env secrets set at all — vault/kms deployments intentionally omit them.
    settings = make_gateway_settings(
        keyvault_backend="vault", router_default_providers=["openai", "anthropic"]
    )
    assert settings.configured_providers() == {"openai", "anthropic"}


def test_kms_backend_declares_bedrock_via_router_default_providers(make_gateway_settings):
    settings = make_gateway_settings(
        keyvault_backend="kms", router_default_providers=["openai", "anthropic", "bedrock"]
    )
    assert settings.configured_providers() == {"openai", "anthropic", "bedrock"}


def test_vault_backend_with_only_openai_declared(make_gateway_settings):
    settings = make_gateway_settings(keyvault_backend="vault", router_default_providers=["openai"])
    assert settings.configured_providers() == {"openai"}
