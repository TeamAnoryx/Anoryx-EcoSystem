"""Offline install-bundle integrity (F-036, ADR-0041)."""

from __future__ import annotations

import pytest

from airgap.bundle import build_manifest, sign_manifest, verify_bundle
from airgap.exceptions import BundleError
from policy.crypto import generate_keypair


def _make_bundle(tmp_path):
    (tmp_path / "a.whl").write_bytes(b"wheel-a-contents")
    (tmp_path / "b.whl").write_bytes(b"wheel-b-contents")
    return ["a.whl", "b.whl"]


def test_build_and_verify_roundtrip(tmp_path):
    files = _make_bundle(tmp_path)
    manifest = build_manifest(str(tmp_path), files, bundle_id="2026.07")
    verified = verify_bundle(manifest, str(tmp_path))
    assert sorted(verified) == ["a.whl", "b.whl"]


def test_tampered_artifact_detected(tmp_path):
    files = _make_bundle(tmp_path)
    manifest = build_manifest(str(tmp_path), files, bundle_id="2026.07")
    # Tamper a file after the manifest was built.
    (tmp_path / "a.whl").write_bytes(b"malicious-swap")
    with pytest.raises(BundleError, match="digest mismatch"):
        verify_bundle(manifest, str(tmp_path))


def test_missing_artifact_detected(tmp_path):
    files = _make_bundle(tmp_path)
    manifest = build_manifest(str(tmp_path), files, bundle_id="2026.07")
    (tmp_path / "a.whl").unlink()
    with pytest.raises(BundleError, match="missing"):
        verify_bundle(manifest, str(tmp_path))


def test_signed_manifest_roundtrip(tmp_path):
    files = _make_bundle(tmp_path)
    priv, pub = generate_keypair()
    manifest = sign_manifest(build_manifest(str(tmp_path), files, bundle_id="2026.07"), priv)
    verified = verify_bundle(manifest, str(tmp_path), public_key=pub)
    assert len(verified) == 2


def test_signature_over_wrong_key_rejected(tmp_path):
    files = _make_bundle(tmp_path)
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    manifest = sign_manifest(build_manifest(str(tmp_path), files, bundle_id="2026.07"), priv)
    with pytest.raises(BundleError, match="signature"):
        verify_bundle(manifest, str(tmp_path), public_key=other_pub)


def test_tampered_manifest_body_breaks_signature(tmp_path):
    files = _make_bundle(tmp_path)
    priv, pub = generate_keypair()
    manifest = sign_manifest(build_manifest(str(tmp_path), files, bundle_id="2026.07"), priv)
    # Swap in a different (but real) digest for a.whl -> signature no longer matches.
    manifest["artifacts"]["a.whl"] = "0" * 64
    with pytest.raises(BundleError):
        verify_bundle(manifest, str(tmp_path), public_key=pub)


def test_unsigned_manifest_with_key_rejected(tmp_path):
    files = _make_bundle(tmp_path)
    _, pub = generate_keypair()
    manifest = build_manifest(str(tmp_path), files, bundle_id="2026.07")
    with pytest.raises(BundleError, match="unsigned"):
        verify_bundle(manifest, str(tmp_path), public_key=pub)


def test_empty_file_list_rejected(tmp_path):
    with pytest.raises(BundleError):
        build_manifest(str(tmp_path), [], bundle_id="2026.07")


def test_unknown_schema_rejected(tmp_path):
    files = _make_bundle(tmp_path)
    manifest = build_manifest(str(tmp_path), files, bundle_id="2026.07")
    manifest["schema"] = "bogus/v9"
    with pytest.raises(BundleError, match="schema"):
        verify_bundle(manifest, str(tmp_path))
