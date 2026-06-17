"""Typed intake results (ADR-0009 §3).

intake_policy() returns exactly one of these. They carry only non-sensitive
metadata for internal callers (the CLI, F-009 later); user-facing layers decide
what, if anything, to surface. Raw disputed body IDs are NEVER placed here — they
go only to structured logs keyed by request_id (Decision B).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Accepted:
    """Policy verified, scope-resolved, version-fresh, persisted, and audited."""

    policy_id: str
    policy_version: int
    policy_type: str


@dataclass(frozen=True, slots=True)
class RejectedSchema:
    """Record failed Draft 2020-12 validation (or was unparseable / oversized)."""

    detail: str = "schema validation failed"


@dataclass(frozen=True, slots=True)
class RejectedSignature:
    """Compact-JWS signature absent, malformed, wrong-alg, or did not verify."""

    detail: str = "signature verification failed"


@dataclass(frozen=True, slots=True)
class RejectedScopeMismatch:
    """Verified signature scope disagrees with the body, or claims a forbidden wildcard tenant."""

    dimension: (
        str  # which dimension disagreed: tenant|team|project|agent|policy_id|...|wildcard_tenant
    )
    detail: str = "signature-resolved scope does not match record body"


@dataclass(frozen=True, slots=True)
class RejectedReplay:
    """policy_version is not strictly greater than the stored max for this policy_id."""

    policy_id: str
    attempted_version: int
    current_max_version: int
    detail: str = "policy_version not strictly greater than stored max (replay/rollback)"


IntakeResult = (
    Accepted | RejectedSchema | RejectedSignature | RejectedScopeMismatch | RejectedReplay
)
