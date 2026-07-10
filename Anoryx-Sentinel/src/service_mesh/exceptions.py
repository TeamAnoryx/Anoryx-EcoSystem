"""Service-mesh mTLS exceptions (F-034, ADR-0040).

All are fail-closed signals: any identity/verification/authorization failure
raises rather than returning a permissive default (CLAUDE.md #5).
"""

from __future__ import annotations


class MeshError(Exception):
    """Base class for all service-mesh errors."""


class InvalidIdentityError(MeshError):
    """A mesh identity string is malformed or outside the trust domain."""


class CaError(MeshError):
    """CA generation, loading, or issuance failed (fail-closed)."""


class PeerVerificationError(MeshError):
    """A peer certificate did not verify against the mesh (chain, validity, SAN)."""


class MeshAuthorizationError(MeshError):
    """A verified peer identity is not permitted to reach the requested callee."""
