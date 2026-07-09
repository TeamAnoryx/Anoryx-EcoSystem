"""HashiCorp Vault KV-v2 ProviderKeySource (F-027, ADR-0033).

Reads secret/data/{path_prefix}/{provider} from Vault's KV-v2 engine. `hvac`
is LAZY-imported (HARD CONSTRAINT — module import must not require it; ships
in the optional [vault] extra, same discipline as [bedrock]/[dr-s3]/[saml]).
`client` is a dependency-injection seam — tests pass a fake object exposing
`.secrets.kv.v2.read_secret_version(path=..., mount_point=...)` so unit tests
never touch a live Vault server (mirrors mcp_gateway/url_guard.py's injected
`resolver` and dr/backends' injected client conventions).
"""

from __future__ import annotations

from typing import Any

from gateway.keyvault.base import ProviderCredentials
from gateway.keyvault.exceptions import KeyFetchError, KeyNotConfigured


class VaultProviderKeySource:
    """Fetches provider credentials from a Vault KV-v2 secrets engine."""

    def __init__(
        self,
        *,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        mount_point: str = "secret",
        path_prefix: str = "sentinel/providers",
        client: Any = None,
    ) -> None:
        self._vault_addr = vault_addr
        self._vault_token = vault_token
        self._mount_point = mount_point
        self._path_prefix = path_prefix
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._vault_addr or not self._vault_token:
            raise KeyFetchError("vault backend selected but VAULT_ADDR/VAULT_TOKEN not set")
        try:
            import hvac  # noqa: PLC0415 — lazy (HARD CONSTRAINT)
        except ImportError as exc:
            raise KeyFetchError(
                "Vault key source requires the 'vault' optional dependency. "
                "Install it with: pip install 'anoryx-sentinel[vault]'"
            ) from exc
        return hvac.Client(url=self._vault_addr, token=self._vault_token)

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        client = self._get_client()
        path = f"{self._path_prefix}/{provider}"
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount_point
            )
        except Exception as exc:
            # Fail-closed: distinguish "not found" from any other error only
            # by message inspection where the client library doesn't expose a
            # typed exception (hvac raises InvalidPath for 404s).
            if type(exc).__name__ == "InvalidPath":
                raise KeyNotConfigured(f"{provider}: no secret at vault path {path!r}") from exc
            raise KeyFetchError(f"{provider}: vault fetch failed: {exc}") from exc

        try:
            data = resp["data"]["data"]
        except (KeyError, TypeError) as exc:
            raise KeyFetchError(f"{provider}: malformed vault response at {path!r}") from exc
        if not data:
            raise KeyNotConfigured(f"{provider}: empty secret at vault path {path!r}")
        return ProviderCredentials(provider=provider, values=dict(data))
