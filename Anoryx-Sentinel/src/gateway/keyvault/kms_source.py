"""AWS KMS envelope-decryption ProviderKeySource (F-027, ADR-0033).

Each provider's credential material is stored as a base64 KMS ciphertext blob
in an env var (e.g. SENTINEL_KMS_CIPHERTEXT_ANTHROPIC) — the plaintext the
operator encrypted with `aws kms encrypt` is either a bare API key string
(Anthropic) or a small JSON object (Bedrock: region/access_key_id/
secret_access_key). Decryption happens at FETCH time, not at startup or in
any persisted store — nothing decrypted ever touches disk or the DB.

boto3 is LAZY-imported (HARD CONSTRAINT — same discipline as bedrock_provider
/ dr/backends/s3.py); `client` is an injection seam for network-free tests.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from gateway.keyvault.base import ProviderCredentials
from gateway.keyvault.exceptions import KeyFetchError, KeyNotConfigured

_CIPHERTEXT_ENV_PREFIX = "SENTINEL_KMS_CIPHERTEXT_"


class KmsProviderKeySource:
    """Fetches provider credentials via AWS KMS envelope decryption."""

    def __init__(
        self,
        *,
        region: str | None = None,
        ciphertext_env: dict[str, str] | None = None,
        client: Any = None,
    ) -> None:
        self._region = region
        # ciphertext_env is an injection seam for tests; defaults to os.environ
        # read lazily (not at import time) so module import stays side-effect-free.
        self._ciphertext_env = ciphertext_env
        self._client = client

    def _get_env(self) -> dict[str, str]:
        if self._ciphertext_env is not None:
            return self._ciphertext_env
        import os  # noqa: PLC0415

        return dict(os.environ)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # noqa: PLC0415 — lazy (HARD CONSTRAINT)
        except ImportError as exc:
            raise KeyFetchError(
                "KMS key source requires the 'kms' optional dependency. "
                "Install it with: pip install 'anoryx-sentinel[kms]'"
            ) from exc
        return boto3.client("kms", region_name=self._region)

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        env_key = f"{_CIPHERTEXT_ENV_PREFIX}{provider.upper()}"
        ciphertext_b64 = self._get_env().get(env_key)
        if not ciphertext_b64:
            raise KeyNotConfigured(f"{provider}: {env_key} not set")

        try:
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception as exc:
            raise KeyFetchError(f"{provider}: {env_key} is not valid base64") from exc

        client = self._get_client()
        try:
            resp = client.decrypt(CiphertextBlob=ciphertext)
        except Exception as exc:
            raise KeyFetchError(f"{provider}: KMS decrypt failed: {exc}") from exc

        plaintext = resp.get("Plaintext")
        if not plaintext:
            raise KeyFetchError(f"{provider}: KMS decrypt returned empty plaintext")
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")

        # Bedrock needs multiple fields -> JSON object; Anthropic is a bare key.
        stripped = plaintext.strip()
        if stripped.startswith("{"):
            try:
                values = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise KeyFetchError(f"{provider}: decrypted JSON payload is malformed") from exc
            if not isinstance(values, dict) or not values:
                raise KeyFetchError(
                    f"{provider}: decrypted JSON payload must be a non-empty object"
                )
        else:
            values = {"api_key": stripped}

        return ProviderCredentials(provider=provider, values={k: str(v) for k, v in values.items()})
