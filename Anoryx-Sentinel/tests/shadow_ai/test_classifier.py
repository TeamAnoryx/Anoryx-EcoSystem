"""Classifier unit tests (F-018, ADR-0021 §5).

Pure tests — no DB, no I/O. Duck-typed row objects exercise the classifier
and attribution logic.

Vectors covered:
  3  test_detection_surfaced_as_candidate — label=="candidate", never verdict
  4  test_false_attribution_guard         — zero raw rows -> zero candidates
  5  test_disallowed_endpoint_flagged     — rows present -> candidate produced
  6  test_allowlisted_endpoint_not_flagged — no rows -> no candidate
  11 test_detection_observes_metadata_not_payload — body fields not read/stored
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from shadow_ai import constants as C
from shadow_ai.classifier import _band_for, _frequency_fires, classify

# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _ts(offset_seconds: float = 0.0) -> str:
    """RFC3339-Z timestamp relative to now."""
    dt = datetime.now(UTC) + timedelta(seconds=offset_seconds)
    return dt.isoformat().replace("+00:00", "Z")


def _row(
    *,
    tenant_id: str = "tenant-a",
    team_id: str = "team-1",
    project_id: str = "proj-1",
    detected_endpoint: str = "api.anthropic.com",
    selected_provider: str = "anthropic",
    first_seen_at: str | None = None,
    # body-like fields that the classifier must NOT read
    request_body: str = "secret prompt content",
    response_body: str = "secret response content",
) -> Any:
    return SimpleNamespace(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        detected_endpoint=detected_endpoint,
        selected_provider=selected_provider,
        first_seen_at=first_seen_at or _ts(),
        # payload-like fields that must stay untouched
        request_body=request_body,
        response_body=response_body,
    )


_BUCKET = "2026-06-24"
_TENANT = "tenant-test"


# ---------------------------------------------------------------------------
# Vector 3: surfaced as candidate with label=="candidate", never verdict
# ---------------------------------------------------------------------------


class TestDetectionSurfacedAsCandidate:
    """ADR-0021 §9 vector 3 — candidates carry label='candidate', never verdict."""

    def test_candidate_label_is_literal_candidate(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert len(candidates) == 1
        c = candidates[0]
        assert c.label == "candidate"

    def test_candidate_has_confidence_band(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].confidence_band in (C.BAND_LOW, C.BAND_MEDIUM, C.BAND_HIGH)

    def test_candidate_has_fired_signals(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        fired = candidates[0].fired_signals
        assert C.SIGNAL_DISALLOWED in fired

    def test_verdict_words_absent_from_candidate(self) -> None:
        """The words 'confirmed', 'verdict', 'violation', 'guilty' never appear."""
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        c = candidates[0]
        forbidden = {"confirmed", "verdict", "violation", "guilty"}
        all_text = " ".join(
            [
                c.label,
                c.confidence_band,
                " ".join(c.fired_signals),
            ]
        )
        for word in forbidden:
            assert word not in all_text.lower(), f"Forbidden word {word!r} found in candidate"

    def test_candidate_is_frozen_dataclass(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        c = candidates[0]
        with pytest.raises((TypeError, AttributeError)):
            c.label = "verdict"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Vector 4: false-attribution guard — no raw rows -> zero candidates
# ---------------------------------------------------------------------------


class TestFalseAttributionGuard:
    """ADR-0021 §9 vector 4 — allow-listed tenant with no raw rows gets zero candidates."""

    def test_empty_rows_produces_no_candidates(self) -> None:
        candidates = classify([], _TENANT, window_bucket=_BUCKET)
        assert candidates == []

    def test_zero_candidates_means_no_false_attribution(self) -> None:
        """A tenant with only allow-listed egress has no rows -> no candidate."""
        # Simulate: allow-listed traffic never emits shadow_ai_detected_outbound.
        # So the classifier sees an empty list and must return [].
        result = classify([], "tenant-clean", window_bucket=_BUCKET)
        assert result == []


# ---------------------------------------------------------------------------
# Vector 5: disallowed endpoint flagged -> candidate produced
# ---------------------------------------------------------------------------


class TestDisallowedEndpointFlagged:
    """ADR-0021 §9 vector 5 — raw rows produce candidates."""

    def test_single_raw_row_produces_one_candidate(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert len(candidates) == 1

    def test_candidate_endpoint_matches_raw_row(self) -> None:
        rows = [_row(tenant_id=_TENANT, detected_endpoint="api.anthropic.com")]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].endpoint == "api.anthropic.com"

    def test_candidate_provider_matches_raw_row(self) -> None:
        rows = [_row(tenant_id=_TENANT, selected_provider="anthropic")]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].provider == "anthropic"

    def test_disallowed_signal_always_present(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert C.SIGNAL_DISALLOWED in candidates[0].fired_signals

    def test_low_band_for_single_row(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].confidence_band == C.BAND_LOW

    def test_medium_band_for_volume_threshold(self) -> None:
        # Use timestamps spread far apart so frequency does NOT fire, ensuring
        # only the volume signal fires -> MEDIUM band, not HIGH.
        rows = [
            _row(tenant_id=_TENANT, first_seen_at=_ts(-i * C.FREQUENCY_WINDOW_SECONDS * 2))
            for i in range(C.VOLUME_THRESHOLD)
        ]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].confidence_band == C.BAND_MEDIUM
        assert C.SIGNAL_VOLUME in candidates[0].fired_signals
        assert C.SIGNAL_FREQUENCY not in candidates[0].fired_signals

    def test_medium_band_for_frequency_threshold(self) -> None:
        # FREQUENCY_MIN_EVENTS events within FREQUENCY_WINDOW_SECONDS
        rows = [
            _row(tenant_id=_TENANT, first_seen_at=_ts(-i * 5))
            for i in range(C.FREQUENCY_MIN_EVENTS)
        ]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].confidence_band == C.BAND_MEDIUM
        assert C.SIGNAL_FREQUENCY in candidates[0].fired_signals

    def test_high_band_for_volume_and_frequency(self) -> None:
        # Volume threshold + frequency threshold simultaneously
        count = max(C.VOLUME_THRESHOLD, C.FREQUENCY_MIN_EVENTS) + 2
        rows = [_row(tenant_id=_TENANT, first_seen_at=_ts(-i * 5)) for i in range(count)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].confidence_band == C.BAND_HIGH
        assert C.SIGNAL_VOLUME in candidates[0].fired_signals
        assert C.SIGNAL_FREQUENCY in candidates[0].fired_signals

    def test_call_count_equals_row_count(self) -> None:
        n = 7
        rows = [_row(tenant_id=_TENANT) for _ in range(n)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].call_count == n

    def test_multiple_groups_produce_multiple_candidates(self) -> None:
        rows = [
            _row(tenant_id=_TENANT, team_id="t1", detected_endpoint="api.openai.com"),
            _row(tenant_id=_TENANT, team_id="t2", detected_endpoint="api.anthropic.com"),
        ]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert len(candidates) == 2

    def test_candidates_sorted_by_call_count_desc(self) -> None:
        rows = [_row(tenant_id=_TENANT, team_id="t1")] * 3 + [
            _row(tenant_id=_TENANT, team_id="t2")
        ] * 1
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert candidates[0].call_count >= candidates[1].call_count

    def test_candidate_key_is_stable(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        c1 = classify(rows, _TENANT, window_bucket=_BUCKET)
        c2 = classify(rows, _TENANT, window_bucket=_BUCKET)
        assert c1[0].candidate_key == c2[0].candidate_key

    def test_candidate_key_differs_across_window_buckets(self) -> None:
        rows = [_row(tenant_id=_TENANT)]
        c1 = classify(rows, _TENANT, window_bucket="2026-06-24")
        c2 = classify(rows, _TENANT, window_bucket="2026-06-25")
        assert c1[0].candidate_key != c2[0].candidate_key


# ---------------------------------------------------------------------------
# Vector 6: allow-listed endpoint not flagged
# ---------------------------------------------------------------------------


class TestAllowlistedEndpointNotFlagged:
    """ADR-0021 §9 vector 6 — no raw rows -> no candidate."""

    def test_no_rows_no_candidate(self) -> None:
        """Allow-listed egress never emits a raw row -> zero candidates."""
        candidates = classify([], "tenant-allowlisted", window_bucket=_BUCKET)
        assert candidates == []

    def test_classifier_only_processes_what_it_receives(self) -> None:
        """Classifier does not query anything; it processes only its input rows."""
        # This ensures no hidden DB side-effect pulls in allow-listed rows.
        rows = []  # Empty: allow-listed tenant has zero raw events
        candidates = classify(rows, "tenant-b", window_bucket=_BUCKET)
        assert len(candidates) == 0


# ---------------------------------------------------------------------------
# Vector 11: classifier observes metadata, not payload
# ---------------------------------------------------------------------------


class TestDetectionObservesMetadataNotPayload:
    """ADR-0021 §9 vector 11 — no request/response body field is read or stored."""

    def test_candidate_does_not_contain_request_body(self) -> None:
        marker = "SUPER_MARKER_PROMPT_CONTENT_12345"  # noqa: S105 — marker, not a credential
        rows = [_row(tenant_id=_TENANT, request_body=marker)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        c = candidates[0]
        # Serialise candidate to a string and ensure body marker is absent
        candidate_str = repr(c)
        assert marker not in candidate_str

    def test_candidate_does_not_contain_response_body(self) -> None:
        marker = "SUPER_MARKER_RESPONSE_CONTENT_99999"  # noqa: S105 — marker, not a credential
        rows = [_row(tenant_id=_TENANT, response_body=marker)]
        candidates = classify(rows, _TENANT, window_bucket=_BUCKET)
        candidate_str = repr(candidates[0])
        assert marker not in candidate_str

    def test_classifier_source_reads_only_metadata_columns(self) -> None:
        """Inspect classifier.py source: it must not reference 'body', 'content',
        'payload', 'prompt', 'response' in attribute accesses."""
        import shadow_ai.classifier as clf_mod

        source = inspect.getsource(clf_mod)
        # These are body-payload attribute names that must never appear in the
        # classifier logic (they can appear in comments — check .attribute access).
        forbidden_attrs = [
            ".request_body",
            ".response_body",
            ".prompt",
            ".response_content",
        ]
        for attr in forbidden_attrs:
            assert attr not in source, (
                f"classifier.py accesses a body field: {attr!r}. "
                "The classifier must touch only metadata (R7)."
            )

    def test_candidate_fields_are_metadata_only(self) -> None:
        """Candidate dataclass has no body/content/prompt fields."""
        from shadow_ai.models import Candidate as _Candidate

        field_names = {f.name for f in _Candidate.__dataclass_fields__.values()}
        body_fields = {
            n
            for n in field_names
            if any(kw in n for kw in ("body", "content", "prompt", "payload", "response"))
        }
        assert body_fields == set(), f"Candidate has body-like fields: {body_fields}"

    def test_frequency_analysis_uses_only_timestamps(self) -> None:
        """_frequency_fires only accesses timestamps — no body data."""
        source = inspect.getsource(_frequency_fires)
        assert "body" not in source
        assert "content" not in source
        assert "prompt" not in source


# ---------------------------------------------------------------------------
# Band logic unit tests
# ---------------------------------------------------------------------------


class TestBandLogic:
    def test_low_band_only_disallowed(self) -> None:
        assert _band_for({C.SIGNAL_DISALLOWED}) == C.BAND_LOW

    def test_medium_band_volume_only(self) -> None:
        assert _band_for({C.SIGNAL_DISALLOWED, C.SIGNAL_VOLUME}) == C.BAND_MEDIUM

    def test_medium_band_frequency_only(self) -> None:
        assert _band_for({C.SIGNAL_DISALLOWED, C.SIGNAL_FREQUENCY}) == C.BAND_MEDIUM

    def test_high_band_volume_and_frequency(self) -> None:
        assert _band_for({C.SIGNAL_DISALLOWED, C.SIGNAL_VOLUME, C.SIGNAL_FREQUENCY}) == C.BAND_HIGH


# ---------------------------------------------------------------------------
# Frequency-fires unit tests
# ---------------------------------------------------------------------------


class TestFrequencyFires:
    def test_fires_when_events_within_window(self) -> None:
        now = datetime.now(UTC).timestamp()
        epochs = [now, now + 10, now + 20]
        assert _frequency_fires(epochs) is True

    def test_does_not_fire_when_too_few_events(self) -> None:
        now = datetime.now(UTC).timestamp()
        epochs = [now, now + 10]  # only 2, need FREQUENCY_MIN_EVENTS (3)
        assert _frequency_fires(epochs) is False

    def test_does_not_fire_when_events_spread_outside_window(self) -> None:
        now = datetime.now(UTC).timestamp()
        # 3 events but spread over more than FREQUENCY_WINDOW_SECONDS
        epochs = [
            now,
            now + C.FREQUENCY_WINDOW_SECONDS + 10,
            now + 2 * C.FREQUENCY_WINDOW_SECONDS + 20,
        ]
        assert _frequency_fires(epochs) is False

    def test_empty_list_returns_false(self) -> None:
        assert _frequency_fires([]) is False
