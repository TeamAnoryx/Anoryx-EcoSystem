"""Compliance Evidence Engine — exception hierarchy (F-011).

Fail-closed semantics: any mapping or evidence error raises rather than
silently continuing.  Callers must handle explicitly.
"""

from __future__ import annotations


class ComplianceError(Exception):
    """Base exception for all compliance engine errors.

    Raised (not swallowed) so callers can make an explicit decision; the
    compliance engine NEVER silently skips a malformed artifact.
    """


class MappingValidationError(ComplianceError):
    """Raised when a framework YAML mapping fails structural or semantic validation.

    Causes: unknown keys, missing required fields, duplicate control_id,
    evidence_event_types referencing unknown event types, schema violations.
    """


class MappingNotFoundError(ComplianceError):
    """Raised when a requested framework mapping file does not exist or cannot be located."""


class EvidenceWindowError(ComplianceError):
    """Raised when evidence window parameters are invalid.

    Causes: t0 >= t1 (empty or reversed window), empty tenant_id.
    Fail-closed: generation is refused rather than silently producing
    an evidence projection over a nonsensical window.
    """


class GapAnalysisError(ComplianceError):
    """Raised when gap analysis inputs are inconsistent.

    Causes: framework mismatch or framework_version mismatch between
    FrameworkMap and EvidenceProjection.  Fail-closed: silently mixing
    two incompatible datasets would violate R8 (no fabricated coverage).
    """


class PackSigningKeyError(ComplianceError):
    """Raised when a compliance pack signing key is misconfigured or unreadable.

    Causes: COMPLIANCE_PACK_SIGNING_KEY_PATH or COMPLIANCE_PACK_PUBKEY_PATH is
    set but the file is unreadable, unparseable, or not a P-256 (secp256r1) key.
    Fail-closed: a misconfigured pack key is a deployment error; the engine
    refuses to export an unsigned pack rather than silently skipping tamper-evidence.
    """
