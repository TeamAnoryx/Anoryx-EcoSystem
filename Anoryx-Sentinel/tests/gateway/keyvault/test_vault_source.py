"""Unit tests for VaultProviderKeySource (F-027) — injected fake client, no
live Vault server, no hvac install required (mirrors mcp_gateway/url_guard.py's
injected-resolver discipline)."""

from __future__ import annotations

import pytest

from gateway.keyvault.exceptions import KeyFetchError, KeyNotConfigured
from gateway.keyvault.vault_source import VaultProviderKeySource


class InvalidPath(Exception):
    """Stand-in for hvac.exceptions.InvalidPath — the real code matches by
    class NAME only (`type(exc).__name__ == "InvalidPath"`) to avoid a hard
    hvac import, so this fake must be named exactly `InvalidPath` too."""


class _FakeKvV2:
    def __init__(self, data_by_path: dict[str, dict]):
        self._data_by_path = data_by_path

    def read_secret_version(self, *, path: str, mount_point: str) -> dict:
        if path not in self._data_by_path:
            raise InvalidPath(f"no secret at {path}")
        return {"data": {"data": self._data_by_path[path]}}


class _FakeSecrets:
    def __init__(self, data_by_path: dict[str, dict]):
        self.kv = type("_Kv", (), {"v2": _FakeKvV2(data_by_path)})()


class _FakeVaultClient:
    def __init__(self, data_by_path: dict[str, dict]):
        self.secrets = _FakeSecrets(data_by_path)


@pytest.mark.asyncio
async def test_fetch_returns_stored_secret_data():
    client = _FakeVaultClient({"sentinel/providers/anthropic": {"api_key": "sk-ant-vaulted"}})
    source = VaultProviderKeySource(client=client)
    creds = await source.fetch_credentials("anthropic")
    assert creds.values == {"api_key": "sk-ant-vaulted"}


@pytest.mark.asyncio
async def test_fetch_bedrock_multi_field_secret():
    client = _FakeVaultClient(
        {
            "sentinel/providers/bedrock": {
                "region": "us-west-2",
                "access_key_id": "AKIAVAULT",
                "secret_access_key": "vaulted-secret",
            }
        }
    )
    source = VaultProviderKeySource(client=client)
    creds = await source.fetch_credentials("bedrock")
    assert creds.values["region"] == "us-west-2"


@pytest.mark.asyncio
async def test_missing_path_raises_not_configured():
    client = _FakeVaultClient({})
    source = VaultProviderKeySource(client=client)
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_empty_secret_raises_not_configured():
    client = _FakeVaultClient({"sentinel/providers/anthropic": {}})
    source = VaultProviderKeySource(client=client)
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_other_backend_error_raises_key_fetch_error():
    class _BoomKvV2:
        def read_secret_version(self, *, path: str, mount_point: str) -> dict:
            raise RuntimeError("connection refused")

    class _BoomClient:
        secrets = type("_S", (), {"kv": type("_Kv", (), {"v2": _BoomKvV2()})()})()

    source = VaultProviderKeySource(client=_BoomClient())
    with pytest.raises(KeyFetchError):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_no_client_and_no_addr_token_raises_key_fetch_error():
    source = VaultProviderKeySource()  # no client, no vault_addr/token
    with pytest.raises(KeyFetchError):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_custom_path_prefix_and_mount_used():
    client = _FakeVaultClient({"custom/prefix/anthropic": {"api_key": "sk-custom"}})
    source = VaultProviderKeySource(
        client=client, mount_point="custom-mount", path_prefix="custom/prefix"
    )
    creds = await source.fetch_credentials("anthropic")
    assert creds.values == {"api_key": "sk-custom"}
