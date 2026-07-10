"""ZkClient — high-level client API for the F-032 ZK storage SDK (ADR-0038).

Holds the client's derived keys and provides the operations a client performs
LOCALLY before/after talking to a ciphertext-only server:
  - encrypt a record (+ compute blind-index tags for chosen searchable fields);
  - decrypt a record fetched back from the server;
  - compute a query tag to ask the server for equality matches.

The server never receives keys — only EncryptedRecord.to_server_dict() output.
"""

from __future__ import annotations

import json
from typing import Any

from zk_sdk.blind_index import blind_index_tag
from zk_sdk.envelope import EncryptedRecord, decrypt_record, encrypt_record
from zk_sdk.keys import DerivedKeys, derive_keys


class ZkClient:
    """Client-side ZK storage operations. Constructed from a 32-byte master key."""

    def __init__(self, master_key: bytes) -> None:
        self._keys: DerivedKeys = derive_keys(master_key)

    # -- record encryption --------------------------------------------------

    def encrypt(
        self,
        payload: dict[str, Any],
        *,
        record_id: str | None = None,
        index_fields: list[str] | None = None,
    ) -> EncryptedRecord:
        """Encrypt a JSON-serialisable payload into a server-storable record.

        index_fields names the payload keys to make equality-searchable via a
        blind-index tag (accepting the equality/frequency leakage — see
        blind_index.py). record_id, if given, is bound as AAD so the server
        cannot swap a ciphertext onto a different id undetected.
        """
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        aad = record_id.encode("utf-8") if record_id is not None else None

        tags: dict[str, str] = {}
        for field_name in index_fields or []:
            if field_name not in payload:
                continue
            value = payload[field_name]
            # Only string/number/bool values are index-able as an exact token.
            tags[field_name] = blind_index_tag(self._keys.index_key, field_name, _as_token(value))

        return encrypt_record(self._keys.data_key, plaintext, aad=aad, index_tags=tags)

    def decrypt(self, record: EncryptedRecord, *, record_id: str | None = None) -> dict[str, Any]:
        """Decrypt a record back into its payload dict (fail-closed on tamper)."""
        aad = record_id.encode("utf-8") if record_id is not None else None
        plaintext = decrypt_record(self._keys.data_key, record, aad=aad)
        return json.loads(plaintext.decode("utf-8"))

    # -- equality search ----------------------------------------------------

    def query_tag(self, field_name: str, value: Any) -> str:
        """Return the blind-index tag the server matches for `field == value`."""
        return blind_index_tag(self._keys.index_key, field_name, _as_token(value))


def _as_token(value: Any) -> str:
    """Canonical string token for a value used in a blind index.

    Bools/ints/floats become their canonical text so `5` and `"5"` index the
    same only if the caller passes the same Python type consistently. Complex
    values are rejected (an index over a dict/list has no well-defined equality
    token here).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    raise TypeError(f"cannot blind-index a value of type {type(value).__name__}")
