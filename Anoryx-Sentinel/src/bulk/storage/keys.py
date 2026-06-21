"""Object-key minting + validation (F-015, ADR-0018 §6, R3).

Key shape (canonical, the ONLY accepted form):

    {tenant_id}/{batch_id}/{object}

  - tenant_id, batch_id : lowercase UUID (server-resolved / server-generated)
  - object              : 32 lowercase hex chars (uuid4().hex) — unguessable

Keys are SERVER-MINTED. The submission API never accepts a client-supplied key
for a new object; it mints one and returns the presigned grant. Every use is
re-validated against this strict shape, so:
  - tenant A cannot read tenant B's object by key guessing (the tenant prefix is
    pinned and the object component is a 128-bit random — vector 2),
  - no path traversal / absolute path / encoded escape survives validation
    (vector 7).
"""

from __future__ import annotations

import re
import uuid

from bulk.exceptions import InvalidObjectKey

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_OBJECT = r"[0-9a-f]{32}"
# Anchored, single-line: exactly three slash-separated segments, nothing else.
# Disallows '..', leading/trailing '/', backslashes, '%', whitespace, control
# chars — any of those simply fail to match the anchored pattern.
_KEY_RE = re.compile(rf"^{_UUID}/{_UUID}/{_OBJECT}$")


def mint_object_key(tenant_id: str, batch_id: str) -> str:
    """Mint a fresh, unguessable, tenant-namespaced object key.

    tenant_id / batch_id are validated to be lowercase UUIDs so a malformed
    caller value can never produce a non-conforming key.
    """
    t = tenant_id.strip().lower()
    b = batch_id.strip().lower()
    if not re.fullmatch(_UUID, t) or not re.fullmatch(_UUID, b):
        raise InvalidObjectKey("tenant_id/batch_id must be lowercase UUIDs")
    return f"{t}/{b}/{uuid.uuid4().hex}"


def validate_object_key(key: str) -> None:
    """Raise InvalidObjectKey unless `key` is exactly the canonical 3-segment shape."""
    if not isinstance(key, str) or not _KEY_RE.match(key):
        # Do NOT echo the raw key (could be attacker-controlled noise in logs).
        raise InvalidObjectKey("object key failed strict validation")


def key_belongs_to_tenant(key: str, tenant_id: str) -> bool:
    """True iff `key` is valid AND its tenant prefix equals `tenant_id`.

    Used as a defense-in-depth check at the submission boundary on top of RLS:
    the server only accepts keys whose prefix is the authenticated tenant.
    """
    try:
        validate_object_key(key)
    except InvalidObjectKey:
        return False
    return key.split("/", 1)[0] == tenant_id.strip().lower()
