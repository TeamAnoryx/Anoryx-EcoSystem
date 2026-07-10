"""Deterministic blind-index tags for equality search over ciphertext (F-032).

A blind-index tag lets a ciphertext-only server answer "which records have
field X == value V?" WITHOUT ever seeing V or the plaintext — the client sends
the tag `HMAC(index_key, field_name ‖ value)` and the server matches it against
stored tags.

HONEST, LOAD-BEARING LIMITATION (ADR-0038): this is DETERMINISTIC, so it LEAKS
EQUALITY and FREQUENCY. Two records with the same value for the same field
produce the SAME tag — an attacker holding the ciphertext DB can see which
records share a value and run frequency analysis (e.g. infer the most common
value). This is the well-known, unavoidable tradeoff of equality-searchable
encryption; it is NOT full ZK and NOT ORAM. Only index fields whose
equality/frequency leakage you can accept. Field name is folded into the HMAC
so the same value under two different fields yields different tags (no
cross-field correlation).
"""

from __future__ import annotations

import hashlib
import hmac

# Tag length (bytes) — 16 bytes (128 bits) of HMAC-SHA256 output. Truncation to
# 128 bits keeps collision probability negligible at practical dataset sizes
# while halving storage vs the full 32-byte digest.
_TAG_BYTES = 16


def _normalize(value: str) -> bytes:
    # Normalize to NFC-ish stable bytes. We do NOT lowercase or trim — equality
    # is exact by design; the caller normalizes if case-insensitive match is wanted.
    return value.encode("utf-8")


def blind_index_tag(index_key: bytes, field_name: str, value: str) -> str:
    """Return a deterministic hex blind-index tag for (field_name, value).

    The SAME (index_key, field_name, value) always yields the SAME tag (that is
    what makes server-side equality matching possible) — with the leakage that
    property implies (see module docstring).
    """
    msg = field_name.encode("utf-8") + b"\x00" + _normalize(value)
    digest = hmac.new(index_key, msg, hashlib.sha256).digest()
    return digest[:_TAG_BYTES].hex()
