"""F-030 EU AI Act framework registration + control-map validity tests."""

from __future__ import annotations

from compliance.constants import FRAMEWORKS
from compliance.mapping import load_all, load_framework
from persistence.models.events_audit_log import VALID_EVENT_TYPES


def test_eu_ai_act_is_registered():
    assert "EU_AI_ACT" in FRAMEWORKS


def test_eu_ai_act_loads_and_is_schema_valid():
    fw = load_framework("EU_AI_ACT")
    assert fw.framework == "EU_AI_ACT"
    assert fw.framework_version
    assert len(fw.controls) >= 8


def test_load_all_includes_eu_ai_act():
    allmaps = load_all()
    assert "EU_AI_ACT" in allmaps
    assert set(allmaps.keys()) == set(FRAMEWORKS)


def test_every_evidence_event_type_is_contract_valid():
    fw = load_framework("EU_AI_ACT")
    for control in fw.controls:
        for event_type in control.evidence_event_types:
            assert event_type in VALID_EVENT_TYPES, (
                f"EU_AI_ACT control {control.control_id} references unknown event type "
                f"{event_type!r} — would require a contracts/ change"
            )


def test_article_12_record_keeping_is_evidenced():
    fw = load_framework("EU_AI_ACT")
    art12 = next(c for c in fw.controls if c.control_id == "Art.12")
    # The record-keeping obligation is the one Sentinel most directly evidences.
    assert art12.sentinel_controls
    assert "usage" in art12.evidence_event_types


def test_conformity_assessment_is_not_applicable():
    fw = load_framework("EU_AI_ACT")
    art43 = next(c for c in fw.controls if c.control_id == "Art.43")
    assert art43.status_override == "not_applicable"
