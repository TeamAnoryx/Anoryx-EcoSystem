"""F-007 seam tests (F-018, ADR-0021 §3, R2).

Vector covered:
  7  test_detection_consumes_f007_seam — classify reads existing
     shadow_ai_detected_outbound rows; no duplicate raw event is emitted;
     the candidate event_type differs from the raw event_type; the httpx
     egress hook is NOT rebuilt.

Pure unit tests — no DB, no I/O.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

from shadow_ai import constants as C
from shadow_ai.classifier import classify

# ---------------------------------------------------------------------------
# Vector 7: detection consumes F-007 seam without rebuilding it
# ---------------------------------------------------------------------------


class TestDetectionConsumesF007Seam:
    """ADR-0021 §9 vector 7."""

    def test_candidate_event_type_differs_from_raw_event_type(self) -> None:
        assert C.CANDIDATE_EVENT_TYPE != C.RAW_EGRESS_EVENT_TYPE

    def test_candidate_event_type_is_shadow_ai_candidate_detected(self) -> None:
        assert C.CANDIDATE_EVENT_TYPE == "shadow_ai_candidate_detected"

    def test_raw_event_type_is_shadow_ai_detected_outbound(self) -> None:
        assert C.RAW_EGRESS_EVENT_TYPE == "shadow_ai_detected_outbound"

    def test_classifier_does_not_import_egress_monitor(self) -> None:
        """classifier.py must not import or rebuild the egress hook (R2)."""
        import shadow_ai.classifier as clf

        source = inspect.getsource(clf)
        assert "egress_monitor" not in source, (
            "classifier.py imports egress_monitor — it must only consume rows, "
            "never rebuild the hook (R2)."
        )
        assert "emit_shadow_ai_outbound_event" not in source, (
            "classifier.py calls emit_shadow_ai_outbound_event — it must only "
            "consume existing rows (R2)."
        )

    def test_service_does_not_rebuild_httpx_hook(self) -> None:
        """service.py must not rebuild the httpx event hook."""
        import shadow_ai.service as svc

        source = inspect.getsource(svc)
        assert "egress_request_hook" not in source
        assert "httpx" not in source
        # The service may use httpx via import but must not call hook registration
        assert "event_hooks" not in source

    def test_no_raw_event_emitted_by_classifier(self) -> None:
        """The classify() function returns candidates, never emits raw events."""
        # classify() is pure — it returns a list, no side-effect emitters
        row = SimpleNamespace(
            team_id="t1",
            project_id="p1",
            detected_endpoint="api.anthropic.com",
            selected_provider="anthropic",
            first_seen_at="2026-06-24T12:00:00Z",
        )
        # If classify emitted a raw event we'd get an error (no session injected).
        # The call must complete without error, returning only Candidate objects.
        result = classify([row], "tenant-x", window_bucket="2026-06-24")
        assert len(result) == 1
        assert result[0].label == "candidate"

    def test_constants_module_has_both_event_type_names(self) -> None:
        """constants.py defines the two distinct event type strings."""
        assert hasattr(C, "CANDIDATE_EVENT_TYPE")
        assert hasattr(C, "RAW_EGRESS_EVENT_TYPE")

    def test_classifier_output_has_no_event_type_field_set_to_raw(self) -> None:
        """Candidate objects carry no 'event_type' attribute at all (they are
        domain objects, not audit events)."""
        from shadow_ai.models import Candidate

        field_names = set(Candidate.__dataclass_fields__.keys())
        assert "event_type" not in field_names, (
            "Candidate has an event_type field — this model is for domain use "
            "only; the event is built in service.py's _candidate_event()."
        )
