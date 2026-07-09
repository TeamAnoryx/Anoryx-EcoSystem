"""Env-var ProviderKeySource — today's exact behavior (F-027 default backend).

Wraps the SAME GatewaySettings fields registry.py already reads directly.
This is the default (keyvault_backend="env") so a deployment that never
touches F-027 config sees byte-identical behavior to before this feature.
"""

from __future__ import annotations

from gateway.config import GatewaySettings
from gateway.keyvault.base import ProviderCredentials
from gateway.keyvault.exceptions import KeyNotConfigured


class EnvProviderKeySource:
    """Reads provider credentials from GatewaySettings env fields."""

    def __init__(self, settings: GatewaySettings) -> None:
        self._settings = settings

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        if provider == "anthropic":
            if not self._settings.anthropic_api_key:
                raise KeyNotConfigured("anthropic: ANTHROPIC_API_KEY not set")
            return ProviderCredentials(
                provider="anthropic", values={"api_key": self._settings.anthropic_api_key}
            )
        if provider == "bedrock":
            region = self._settings.aws_region
            access_key_id = self._settings.aws_access_key_id
            secret_access_key = self._settings.aws_secret_access_key
            if not (region and access_key_id and secret_access_key):
                raise KeyNotConfigured(
                    "bedrock: AWS_REGION/AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set"
                )
            return ProviderCredentials(
                provider="bedrock",
                values={
                    "region": region,
                    "access_key_id": access_key_id,
                    "secret_access_key": secret_access_key,
                },
            )
        raise KeyNotConfigured(f"{provider}: no env-backed credentials for this provider")
