"""F-018 shadow-AI classifier — pure, bounded, explainable heuristics (ADR-0021 §5).

Input: a tenant's recent `shadow_ai_detected_outbound` audit rows (each one
disallowed known-provider egress; `traffic_volume` is always 1 per emit). Output:
review CANDIDATES grouped by (team, project, endpoint, provider) with a confidence
band and the exact list of fired signals (explainability).

This module is PURE: no DB, no clock, no I/O. The analysis window bucket (used in
the dedup key) is passed in by the service so the function stays deterministic and
unit-testable. It reads only metadata — identity, endpoint, provider, counts,
timestamps — never any request/response body (R7).
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from shadow_ai import constants as C
from shadow_ai.attribution import AttributionKey, attribution_key
from shadow_ai.models import Candidate


def _parse_ts(value: str | None) -> float | None:
    """Parse an RFC3339 'Z' timestamp to epoch seconds, or None if unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _frequency_fires(epochs: list[float]) -> bool:
    """True if any FREQUENCY_WINDOW_SECONDS window holds >= FREQUENCY_MIN_EVENTS.

    Two-pointer over sorted epoch seconds — O(n). Rows with unparseable
    timestamps are excluded by the caller, so a malformed timestamp degrades the
    frequency signal (fewer points) rather than crashing the analysis.
    """
    if len(epochs) < C.FREQUENCY_MIN_EVENTS:
        return False
    ordered = sorted(epochs)
    left = 0
    for right in range(len(ordered)):
        while ordered[right] - ordered[left] > C.FREQUENCY_WINDOW_SECONDS:
            left += 1
        if right - left + 1 >= C.FREQUENCY_MIN_EVENTS:
            return True
    return False


def _band_for(fired: set[str]) -> str:
    """Map fired signals to a confidence band (ADR-0021 §5).

    Low: only `disallowed_provider`. Medium: + volume OR frequency.
    High: volume AND frequency.
    """
    has_volume = C.SIGNAL_VOLUME in fired
    has_frequency = C.SIGNAL_FREQUENCY in fired
    if has_volume and has_frequency:
        return C.BAND_HIGH
    if has_volume or has_frequency:
        return C.BAND_MEDIUM
    return C.BAND_LOW


def _candidate_key(tenant_id: str, key: AttributionKey, window_bucket: str) -> str:
    """Stable digest for dedup: one candidate per group per window bucket.

    Embedding `window_bucket` (a UTC date from the service) means the same group
    re-surfaces as a new candidate in a later bucket (intended), but is emitted
    at most once per bucket (deduped against existing candidate rows).
    """
    team_id, project_id, endpoint, provider = key
    raw = f"{tenant_id}|{team_id}|{project_id}|{endpoint}|{provider}|{window_bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64]


def classify(rows: list[Any], tenant_id: str, *, window_bucket: str) -> list[Candidate]:
    """Group raw egress rows into review candidates with confidence bands.

    `rows` are `EventsAuditLog` rows of type `shadow_ai_detected_outbound` (or any
    object exposing the same attributes — kept duck-typed for unit testing).
    """
    groups: dict[AttributionKey, list[Any]] = {}
    for row in rows:
        groups.setdefault(attribution_key(row), []).append(row)

    candidates: list[Candidate] = []
    for key, members in groups.items():
        team_id, project_id, endpoint, provider = key
        call_count = len(members)

        # 'disallowed_provider' is inherent — the group exists only because a known
        # provider was off the tenant allow-list.
        fired: set[str] = {C.SIGNAL_DISALLOWED}
        if call_count >= C.VOLUME_THRESHOLD:
            fired.add(C.SIGNAL_VOLUME)

        seen = [s for s in (getattr(r, "first_seen_at", None) for r in members) if s]
        # Parse once; reuse for the frequency signal AND first/last ordering so the
        # window bounds are correct regardless of timestamp offset format (ordering
        # by epoch, not lexicographically on the string).
        epoch_by_ts: dict[str, float | None] = {s: _parse_ts(s) for s in seen}
        epochs = [e for e in epoch_by_ts.values() if e is not None]
        if _frequency_fires(epochs):
            fired.add(C.SIGNAL_FREQUENCY)

        parseable = [s for s in seen if epoch_by_ts[s] is not None]
        if parseable:
            first_seen = min(parseable, key=lambda s: epoch_by_ts[s])
            last_seen = max(parseable, key=lambda s: epoch_by_ts[s])
        elif seen:
            first_seen, last_seen = min(seen), max(seen)
        else:
            first_seen = last_seen = ""

        candidates.append(
            Candidate(
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                endpoint=endpoint,
                provider=provider,
                call_count=call_count,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence_band=_band_for(fired),
                fired_signals=tuple(sorted(fired)),
                candidate_key=_candidate_key(tenant_id, key, window_bucket),
            )
        )
    # Stable order: highest call_count first, then endpoint (deterministic output).
    candidates.sort(key=lambda c: (-c.call_count, c.endpoint, c.team_id))
    return candidates
