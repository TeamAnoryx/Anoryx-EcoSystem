"""F-029 HIPAA framework registration + control-map validity tests.

Verifies HIPAA is a first-class registered framework (loads, schema-valid,
every evidence_event_type is a real contract event type) — no DB required.
"""

from __future__ import annotations

from compliance.constants import FRAMEWORKS
from compliance.mapping import load_all, load_framework
from persistence.models.events_audit_log import VALID_EVENT_TYPES


def test_hipaa_is_registered():
    assert "HIPAA" in FRAMEWORKS


def test_hipaa_framework_loads_and_is_schema_valid():
    fw = load_framework("HIPAA")
    assert fw.framework == "HIPAA"
    assert fw.framework_version
    assert len(fw.controls) >= 10


def test_load_all_includes_hipaa():
    allmaps = load_all()
    assert "HIPAA" in allmaps
    assert set(allmaps.keys()) == set(FRAMEWORKS)


def test_every_hipaa_evidence_event_type_is_contract_valid():
    # Contract-free guarantee: HIPAA references only EXISTING event types, so it
    # needs no contracts/events.schema.json change.
    fw = load_framework("HIPAA")
    for control in fw.controls:
        for event_type in control.evidence_event_types:
            assert event_type in VALID_EVENT_TYPES, (
                f"HIPAA control {control.control_id} references unknown event type "
                f"{event_type!r} — would require a contracts/ change"
            )


def test_hipaa_has_technical_safeguards_and_honest_not_covered():
    fw = load_framework("HIPAA")
    ids = {c.control_id for c in fw.controls}
    # Core technical safeguards present
    assert "164.312(a)(1)" in ids  # access control
    assert "164.312(b)" in ids  # audit controls
    # Transmission security honestly reported as no-evidence (empty controls)
    transmission = next(c for c in fw.controls if c.control_id == "164.312(e)(1)")
    assert transmission.sentinel_controls == ()
