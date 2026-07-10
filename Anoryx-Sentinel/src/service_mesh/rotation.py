"""Leaf rotation logic (F-034, ADR-0040).

Mesh leaves are short-lived (see ca.DEFAULT_LEAF_TTL_HOURS) and rotated well
before expiry. This module answers a single question about a leaf: given its
validity window and a renewal threshold, is it FRESH, DUE for renewal, or
already EXPIRED?

By default we renew once a leaf has consumed `DEFAULT_RENEW_AT_FRACTION` (2/3) of
its lifetime — the standard "renew at 2/3 of TTL" heuristic that keeps a valid
overlap between the old and new cert while the new one propagates.

The SCHEDULER that periodically calls this and re-issues via `MeshCa.issue` is a
deploy concern — in Kubernetes that is cert-manager renewing a `Certificate`
before `renewBefore`. See docs/followups/f-034-cert-manager-wiring.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cryptography import x509

# Renew once 2/3 of the leaf's lifetime has elapsed.
DEFAULT_RENEW_AT_FRACTION = 2.0 / 3.0


class RotationState(str, Enum):
    FRESH = "fresh"  # inside the first part of its life; nothing to do
    DUE = "due"  # past the renewal threshold; re-issue now
    EXPIRED = "expired"  # already past not_valid_after; re-issue urgently


@dataclass(frozen=True)
class RotationStatus:
    state: RotationState
    not_valid_before: datetime
    not_valid_after: datetime
    renew_at: datetime
    seconds_until_expiry: float

    @property
    def needs_renewal(self) -> bool:
        return self.state in (RotationState.DUE, RotationState.EXPIRED)


def evaluate(
    leaf: x509.Certificate,
    *,
    now: datetime | None = None,
    renew_at_fraction: float = DEFAULT_RENEW_AT_FRACTION,
) -> RotationStatus:
    """Classify a leaf's rotation state from its validity window."""
    if not 0.0 < renew_at_fraction < 1.0:
        raise ValueError("renew_at_fraction must be in (0, 1)")
    now = now or datetime.now(timezone.utc)
    nvb = leaf.not_valid_before_utc
    nva = leaf.not_valid_after_utc
    lifetime = (nva - nvb).total_seconds()
    renew_at = nvb + (nva - nvb) * renew_at_fraction if lifetime > 0 else nva
    seconds_until_expiry = (nva - now).total_seconds()

    if now >= nva:
        state = RotationState.EXPIRED
    elif now >= renew_at:
        state = RotationState.DUE
    else:
        state = RotationState.FRESH
    return RotationStatus(
        state=state,
        not_valid_before=nvb,
        not_valid_after=nva,
        renew_at=renew_at,
        seconds_until_expiry=seconds_until_expiry,
    )
