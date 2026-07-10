"""Unit tests for F-030 Article 13 disclosure template generation (no DB)."""

from __future__ import annotations

from compliance.eu_ai_act.disclosure import build_disclosure, render_disclosure_markdown


def test_build_disclosure_shape():
    doc = build_disclosure(system_name="TriageBot", provider_name="Acme")
    assert doc["document_type"] == "sentinel-eu-ai-act-art13-disclosure/v1"
    assert doc["system"]["name"] == "TriageBot"
    assert doc["provider"]["name"] == "Acme"
    # unfilled provider fields are explicit placeholders, not silently blank
    assert doc["system"]["intended_purpose"] == "<<PROVIDER TO COMPLETE>>"
    assert doc["performance"]["accuracy_metrics"] == "<<PROVIDER TO COMPLETE>>"
    # Sentinel-evidenced sections are pre-filled
    assert "audit log" in doc["record_keeping"]["mechanism"]
    assert "injection" in doc["input_output_controls"]["measures"]


def test_intended_purpose_used_when_provided():
    doc = build_disclosure(
        system_name="S", provider_name="P", intended_purpose="triage patient messages"
    )
    assert doc["system"]["intended_purpose"] == "triage patient messages"


def test_render_markdown_has_sections_and_disclaimer():
    doc = build_disclosure(system_name="S", provider_name="P")
    md = render_disclosure_markdown(doc)
    assert "# EU AI Act — Article 13 Instructions for Use (TEMPLATE)" in md
    assert "## Human oversight" in md
    assert "## Record-keeping" in md
    assert "Art.12" in md
    assert "<<PROVIDER TO COMPLETE>>" in md
    # honest framing — not a completed disclosure
    assert "not a completed" in md.lower() or "template" in md.lower()


def test_render_is_deterministic():
    doc = build_disclosure(system_name="S", provider_name="P")
    assert render_disclosure_markdown(doc) == render_disclosure_markdown(doc)
