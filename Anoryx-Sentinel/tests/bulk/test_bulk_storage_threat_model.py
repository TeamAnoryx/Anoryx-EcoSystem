"""F-015 storage-surface threat model — vectors 2, 3, 5, 6, 7 (ADR-0018 §11).

Pure unit tests (no network / no DB) for the security-critical key + content
validation. The presigned-policy assertions (vectors 3, 5) are guarded on boto3
being installed (the optional [bulk] extra) and skip cleanly otherwise.
"""

from __future__ import annotations

import uuid

import pytest

from bulk.content import decode_text
from bulk.exceptions import (
    InvalidObjectKey,
    ObjectTooLarge,
    UnsupportedContent,
)
from bulk.storage.keys import (
    key_belongs_to_tenant,
    mint_object_key,
    validate_object_key,
)


def _ids() -> tuple[str, str]:
    return str(uuid.uuid4()), str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Vector 2 — object keys are tenant-namespaced + unguessable
# --------------------------------------------------------------------------- #
def test_minted_key_is_tenant_prefixed_and_unguessable():
    tenant, batch = _ids()
    key = mint_object_key(tenant, batch)
    assert key.startswith(f"{tenant}/{batch}/")
    # The object component is a 32-hex random (128 bits) — not guessable.
    obj = key.rsplit("/", 1)[1]
    assert len(obj) == 32
    # Two mints never collide.
    assert mint_object_key(tenant, batch) != key


def test_key_does_not_belong_to_other_tenant():
    tenant_a, batch = _ids()
    tenant_b = str(uuid.uuid4())
    key = mint_object_key(tenant_a, batch)
    assert key_belongs_to_tenant(key, tenant_a) is True
    # Tenant B cannot claim tenant A's key by guessing the prefix (vector 2).
    assert key_belongs_to_tenant(key, tenant_b) is False


def test_cross_tenant_guessed_key_rejected():
    # An attacker swaps in their own tenant prefix but keeps A's object id —
    # the key is structurally valid but does not belong to the attacker tenant.
    tenant_a, batch = _ids()
    victim = mint_object_key(tenant_a, batch)
    obj = victim.rsplit("/", 1)[1]
    attacker = str(uuid.uuid4())
    forged = f"{attacker}/{batch}/{obj}"
    assert key_belongs_to_tenant(forged, tenant_a) is False


# --------------------------------------------------------------------------- #
# Vector 7 — path traversal / malformed keys are rejected
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_key",
    [
        "../etc/passwd",
        "/abs/path",
        "a/b",  # too few segments
        "a/b/c/d",  # too many segments
        "",  # empty
        "  ",  # whitespace
        "00000000-0000-0000-0000-000000000000/..%2f/deadbeef",  # encoded traversal
        "00000000-0000-0000-0000-000000000000\\x/y",  # backslash
        "00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000/NOTHEX",
        "00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000/"
        + "a" * 31,  # object too short
        "tenant/batch/" + "a" * 32,  # non-UUID prefixes
    ],
)
def test_validate_object_key_rejects_malformed(bad_key):
    with pytest.raises(InvalidObjectKey):
        validate_object_key(bad_key)


def test_validate_object_key_accepts_canonical():
    tenant, batch = _ids()
    validate_object_key(mint_object_key(tenant, batch))  # must not raise


# --------------------------------------------------------------------------- #
# Vector 8 — no SSRF: a URL/host can never become a fetch target
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://evil.example/x",
        "file:///etc/passwd",
        "169.254.169.254/x/y",
    ],
)
def test_no_ssrf_via_storage_fetch_url_key_rejected(bad):
    # The worker addresses objects ONLY by validated key against the single
    # configured endpoint — there is no arbitrary-URL fetch path. A URL-shaped
    # "key" fails validation outright, so internal/metadata endpoints are
    # unreachable (vector 8).
    with pytest.raises(InvalidObjectKey):
        validate_object_key(bad)


def test_mint_rejects_non_uuid_inputs():
    with pytest.raises(InvalidObjectKey):
        mint_object_key("not-a-uuid", str(uuid.uuid4()))


# --------------------------------------------------------------------------- #
# Vector 5 — oversize content rejected (fetch-time backstop)
# --------------------------------------------------------------------------- #
def test_decode_text_rejects_oversize():
    with pytest.raises(ObjectTooLarge):
        decode_text(b"x" * 11, max_bytes=10)


# --------------------------------------------------------------------------- #
# Vector 6 — declared content-type is never trusted; bytes are validated
# --------------------------------------------------------------------------- #
def test_decode_text_rejects_binary_nul():
    # A real binary blob (ZIP local-file header) carries NUL bytes — a strong
    # binary signal that is never valid UTF-8 text.
    with pytest.raises(UnsupportedContent):
        decode_text(b"PK\x03\x04\x00\x08\x00\x00binary\x00data", max_bytes=1024)


def test_decode_text_rejects_invalid_utf8():
    with pytest.raises(UnsupportedContent):
        decode_text(b"\xff\xfe\xfa", max_bytes=1024)


def test_decode_text_accepts_real_text():
    assert decode_text("hello world".encode("utf-8"), max_bytes=1024) == "hello world"


# --------------------------------------------------------------------------- #
# Vector 3 / 5 (backend) — presigned POST pins key + size cap + expiry
# --------------------------------------------------------------------------- #
def test_presigned_upload_pins_key_size_and_ttl(monkeypatch):
    pytest.importorskip("boto3")
    monkeypatch.setenv("BULK_STORAGE_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("BULK_STORAGE_ACCESS_KEY", "test-access")
    monkeypatch.setenv("BULK_STORAGE_SECRET_KEY", "test-secret")  # noqa: S105 - test fixture
    from bulk.config import _reset_bulk_settings_for_testing
    from bulk.storage.minio_backend import MinioStorage

    _reset_bulk_settings_for_testing()
    storage = MinioStorage()
    tenant, batch = _ids()
    key = mint_object_key(tenant, batch)

    grant = storage.presign_upload(key, max_bytes=10, ttl=60)

    assert grant.key == key
    assert grant.max_bytes == 10
    assert grant.expires_in == 60
    # The signed POST policy pins the exact key (single-object — vector 3).
    assert grant.fields.get("key") == key
    _reset_bulk_settings_for_testing()
