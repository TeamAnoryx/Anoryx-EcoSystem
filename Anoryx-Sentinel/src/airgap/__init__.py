"""Self-hosted / air-gapped enterprise deployment support (F-036).

Some enterprises run Sentinel with NO outbound internet: no PyPI, no container
registry, no license phone-home. This package provides the three primitives that
kind of deployment needs, all OFFLINE and fail-closed:

- `license`  — OFFLINE license validation. A license is a signed claim set
               (ES256 compact-JWS, the SAME vetted scheme F-008 uses for policy
               signing — no hand-rolled crypto). The deployed Sentinel ships only
               the PUBLIC key and validates the license locally: signature +
               validity window + edition/feature/tenant limits. No network call,
               ever. Fail-closed: bad signature / expired / unreadable key → deny.
- `bundle`   — OFFLINE install-bundle integrity. Build a manifest of every
               artifact in a transfer bundle (wheels, image digests, migration
               files) with a SHA-256 per file, sign the manifest (ES256), and let
               the air-gapped operator VERIFY the bundle (recompute digests +
               check the signature) before installing. Fail-closed on any
               digest mismatch, missing file, or bad signature.
- `mirror`   — OFFLINE mirror configuration validation. Confirm a deployment's
               pip / container-registry config points ONLY at internal mirrors,
               never a public internet host (pypi.org, ghcr.io, docker.io, ...),
               so an air-gapped install cannot silently reach out.

Honest scope (ADR-0041): this is the validation/integrity TOOLKIT + the
`sentinel-airgap` CLI. It does NOT build the actual wheelhouse/registry mirror or
ship a specific customer license — those are release-engineering + commercial
concerns. See docs/followups/f-036-release-bundle-build.md.
"""

from __future__ import annotations

from airgap.license import ValidatedLicense, verify_license
from airgap.mirror import MirrorConfigError, validate_mirror_config

__all__ = ["ValidatedLicense", "verify_license", "validate_mirror_config", "MirrorConfigError"]
