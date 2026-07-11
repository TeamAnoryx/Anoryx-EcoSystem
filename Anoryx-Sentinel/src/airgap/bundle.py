"""Offline install-bundle integrity (F-036, ADR-0041).

An air-gapped install starts by transferring a BUNDLE (wheels, container image
tarballs/digests, migration files, config) across the air gap on physical media.
Before installing it, the operator must be sure the bundle is complete and
untampered. This module builds and verifies a signed manifest:

- `build_manifest(root, files)` — walk the listed files under `root`, record a
  SHA-256 for each, and return a manifest dict (schema-versioned, sorted).
- `sign_manifest` / manifest signature — the manifest is signed with the SAME
  ES256 compact-JWS scheme as licenses (over a SHA-256 of the canonical manifest),
  so the operator verifies one signature to trust every digest.
- `verify_bundle(manifest, root, public_key=None)` — recompute every file's
  SHA-256 and confirm it matches the manifest; if a public key is given the
  signature is verified first. A manifest is self-attesting, so digest-only
  checking proves nothing about authenticity — `verify_bundle` therefore
  REFUSES (raises) when a manifest carries a signature but no key is supplied,
  never silently skipping it. Fail-closed on ANY mismatch, missing file, or bad
  signature. (The CLI further requires the operator to pass the key or an
  explicit --insecure-skip-signature opt-out for an unsigned manifest.)

Digest-then-sign (not sign-each-file) keeps the trust root a single signature
while still binding every artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from airgap.exceptions import BundleError
from policy.crypto import CompactJWSError, sign_claims, verify_compact_jws

MANIFEST_SCHEMA = "anoryx.airgap.bundle/v1"
_CHUNK = 1024 * 1024


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: str, files: list[str], *, bundle_id: str) -> dict[str, Any]:
    """Build an integrity manifest for `files` (paths relative to `root`)."""
    if not files:
        raise BundleError("cannot build a manifest for an empty file list")
    entries: dict[str, str] = {}
    for rel in sorted(set(files)):
        abs_path = os.path.join(root, rel)
        if not os.path.isfile(abs_path):
            raise BundleError(f"bundle file not found: {rel}")
        entries[rel] = _sha256_file(abs_path)
    return {
        "schema": MANIFEST_SCHEMA,
        "bundle_id": bundle_id,
        "artifacts": entries,
    }


def _canonical_digest(manifest: dict[str, Any]) -> str:
    """SHA-256 hex of the canonical manifest body (everything except `signature`)."""
    body = {k: v for k, v in manifest.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_manifest(manifest: dict[str, Any], private_key: EllipticCurvePrivateKey) -> dict[str, Any]:
    """Return a copy of the manifest with an ES256 signature over its canonical digest."""
    signed = dict(manifest)
    signed["signature"] = sign_claims({"manifest_sha256": _canonical_digest(manifest)}, private_key)
    return signed


def verify_bundle(
    manifest: dict[str, Any],
    root: str,
    *,
    public_key: EllipticCurvePublicKey | None = None,
) -> list[str]:
    """Verify every artifact digest (and the signature if a key is given).

    Returns the list of verified relative paths. Raises BundleError on any
    problem (fail-closed).
    """
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise BundleError(f"unknown manifest schema: {manifest.get('schema')!r}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise BundleError("manifest has no artifacts")

    # A manifest is self-attesting: without a signature check, digest matching only
    # proves the files match the (attacker-replaceable) manifest, not that the
    # bundle is authentic. So NEVER silently skip a present signature, and refuse
    # to "verify" an unsigned manifest unless the caller explicitly opts out.
    token = manifest.get("signature")
    if token and public_key is None:
        raise BundleError(
            "manifest is signed but no verifying key was supplied — pass the public key "
            "(refusing to skip signature verification)"
        )
    if public_key is not None:
        if not token:
            raise BundleError("manifest is unsigned but a verifying key was supplied")
        try:
            claims = verify_compact_jws(token, public_key)
        except (CompactJWSError, InvalidSignature) as exc:
            raise BundleError(f"manifest signature verification failed: {exc}") from exc
        if claims.get("manifest_sha256") != _canonical_digest(manifest):
            raise BundleError("manifest signature does not match manifest contents (tampered)")

    verified: list[str] = []
    for rel, expected in sorted(artifacts.items()):
        abs_path = os.path.join(root, rel)
        if not os.path.isfile(abs_path):
            raise BundleError(f"bundle artifact missing: {rel}")
        actual = _sha256_file(abs_path)
        if actual != expected:
            raise BundleError(f"digest mismatch for {rel}: expected {expected}, got {actual}")
        verified.append(rel)
    return verified
