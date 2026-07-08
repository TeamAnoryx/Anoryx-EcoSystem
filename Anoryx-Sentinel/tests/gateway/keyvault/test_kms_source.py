"""Unit tests for KmsProviderKeySource (F-027) — injected fake boto3 client,
no live AWS, no boto3 install required."""

from __future__ import annotations

import base64
import json

import pytest

from gateway.keyvault.exceptions import KeyFetchError, KeyNotConfigured
from gateway.keyvault.kms_source import KmsProviderKeySource


class _FakeKmsClient:
    def __init__(self, plaintext_by_ciphertext: dict[bytes, bytes]):
        self._map = plaintext_by_ciphertext

    def decrypt(self, *, CiphertextBlob: bytes) -> dict:
        if CiphertextBlob not in self._map:
            raise RuntimeError("InvalidCiphertextException")
        return {"Plaintext": self._map[CiphertextBlob]}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.asyncio
async def test_bare_key_plaintext_becomes_api_key_field():
    ciphertext = b"fake-ciphertext-1"
    client = _FakeKmsClient({ciphertext: b"sk-ant-decrypted"})
    source = KmsProviderKeySource(
        client=client, ciphertext_env={"SENTINEL_KMS_CIPHERTEXT_ANTHROPIC": _b64(ciphertext)}
    )
    creds = await source.fetch_credentials("anthropic")
    assert creds.values == {"api_key": "sk-ant-decrypted"}


@pytest.mark.asyncio
async def test_json_plaintext_becomes_multi_field_bedrock():
    payload = {"region": "us-east-1", "access_key_id": "AKIAFAKE", "secret_access_key": "shh"}
    ciphertext = b"fake-ciphertext-2"
    client = _FakeKmsClient({ciphertext: json.dumps(payload).encode("utf-8")})
    source = KmsProviderKeySource(
        client=client, ciphertext_env={"SENTINEL_KMS_CIPHERTEXT_BEDROCK": _b64(ciphertext)}
    )
    creds = await source.fetch_credentials("bedrock")
    assert creds.values == payload


@pytest.mark.asyncio
async def test_missing_env_var_raises_not_configured():
    source = KmsProviderKeySource(client=_FakeKmsClient({}), ciphertext_env={})
    with pytest.raises(KeyNotConfigured):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_invalid_base64_raises_key_fetch_error():
    source = KmsProviderKeySource(
        client=_FakeKmsClient({}),
        ciphertext_env={"SENTINEL_KMS_CIPHERTEXT_ANTHROPIC": "not-valid-base64!!!"},
    )
    with pytest.raises(KeyFetchError):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_decrypt_failure_raises_key_fetch_error():
    ciphertext = b"unregistered-ciphertext"
    source = KmsProviderKeySource(
        client=_FakeKmsClient({}),  # empty map -> decrypt() raises for any input
        ciphertext_env={"SENTINEL_KMS_CIPHERTEXT_ANTHROPIC": _b64(ciphertext)},
    )
    with pytest.raises(KeyFetchError):
        await source.fetch_credentials("anthropic")


@pytest.mark.asyncio
async def test_malformed_json_payload_raises_key_fetch_error():
    ciphertext = b"fake-ciphertext-3"
    client = _FakeKmsClient({ciphertext: b"{not valid json"})
    source = KmsProviderKeySource(
        client=client, ciphertext_env={"SENTINEL_KMS_CIPHERTEXT_ANTHROPIC": _b64(ciphertext)}
    )
    with pytest.raises(KeyFetchError):
        await source.fetch_credentials("anthropic")
