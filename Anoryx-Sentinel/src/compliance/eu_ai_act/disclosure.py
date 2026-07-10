"""Article 13 transparency-disclosure / instructions-for-use generator (F-030).

Article 13 of the EU AI Act requires high-risk AI systems to be accompanied by
instructions for use that convey specified information to deployers. This module
produces a STRUCTURED TEMPLATE for that document, pre-filled with the technical
controls Sentinel provides (logging, input/output filtering, human-oversight
control point) and clearly-marked PLACEHOLDERS for the provider-supplied fields
(intended purpose, accuracy metrics, known limitations, etc.).

HONEST FRAMING: this is a documentation AID that pre-fills the Sentinel-evidenced
portions and scaffolds the rest. It is NOT a completed Article 13 disclosure and
does NOT discharge the obligation — the provider must complete the placeholders
and validate the content.
"""

from __future__ import annotations

from typing import Any

from compliance.constants import SENTINEL_VERSION

_PLACEHOLDER = "<<PROVIDER TO COMPLETE>>"

_FRAMING = (
    "Article 13 instructions-for-use TEMPLATE. Sentinel-evidenced sections are "
    "pre-filled; sections marked '<<PROVIDER TO COMPLETE>>' are the provider's "
    "responsibility. This template does not by itself satisfy Article 13."
)


def build_disclosure(
    *,
    system_name: str,
    provider_name: str,
    intended_purpose: str | None = None,
) -> dict[str, Any]:
    """Build a structured Article 13 disclosure template.

    intended_purpose is optional; when omitted the field is left as an explicit
    provider placeholder (Article 13(3)(b)(i)).
    """
    return {
        "document_type": "sentinel-eu-ai-act-art13-disclosure/v1",
        "sentinel_version": SENTINEL_VERSION,
        "framing": _FRAMING,
        # Art.13(3)(a)
        "provider": {
            "name": provider_name or _PLACEHOLDER,
            "contact": _PLACEHOLDER,
        },
        # Art.13(3)(b)(i)-(ii)
        "system": {
            "name": system_name or _PLACEHOLDER,
            "intended_purpose": intended_purpose or _PLACEHOLDER,
            "characteristics_capabilities": _PLACEHOLDER,
            "known_limitations": _PLACEHOLDER,
        },
        # Art.13(3)(b)(ii) accuracy — provider-supplied metrics
        "performance": {
            "accuracy_metrics": _PLACEHOLDER,
            "robustness_cybersecurity_metrics": _PLACEHOLDER,
            "foreseeable_misuse": _PLACEHOLDER,
        },
        # Art.13(3)(d) human oversight — Sentinel provides a technical control point
        "human_oversight": {
            "measures": (
                "Sentinel enforces human-authored, ECDSA-signed governance policies "
                "(F-008) at the gateway and records every allow/deny decision, giving "
                "human overseers a technical control point and an auditable intervention "
                "record. The provider must additionally define WHO exercises oversight "
                "and HOW (Article 14)."
            ),
            "provider_oversight_assignment": _PLACEHOLDER,
        },
        # Art.13(3)(e) + Art.12 — the logging/record-keeping Sentinel supplies
        "record_keeping": {
            "mechanism": (
                "Sentinel maintains an append-only, hash-chained audit log (F-003) of "
                "all requests and control events, providing the automatically-generated "
                "logs referenced by Article 12; retention duration is a deployer policy."
            ),
        },
        # Art.13(3)(b) — the input controls Sentinel applies
        "input_output_controls": {
            "measures": (
                "Sentinel applies prompt-injection detection (F-007), secret-leak "
                "detection, PII masking (F-005), and per-tenant policy/rate limits to "
                "inputs and outputs, contributing to Article 15 robustness."
            ),
        },
        "disclaimer": (
            "This is a pre-filled TEMPLATE, not a completed Article 13 disclosure. "
            "Complete every '<<PROVIDER TO COMPLETE>>' field and validate before use."
        ),
    }


def render_disclosure_markdown(doc: dict[str, Any]) -> str:
    """Render an Article 13 disclosure template as Markdown."""
    lines: list[str] = []
    lines.append("# EU AI Act — Article 13 Instructions for Use (TEMPLATE)")
    lines.append("")
    lines.append(f"> {doc['framing']}")
    lines.append("")
    lines.append(f"- **Generated with Sentinel version:** {doc['sentinel_version']}")
    prov = doc["provider"]
    lines.append(f"- **Provider:** {prov['name']} (contact: {prov['contact']})")
    lines.append("")
    sysinfo = doc["system"]
    lines.append("## System")
    lines.append(f"- **Name:** {sysinfo['name']}")
    lines.append(f"- **Intended purpose (Art.13(3)(b)(i)):** {sysinfo['intended_purpose']}")
    lines.append(f"- **Characteristics & capabilities:** {sysinfo['characteristics_capabilities']}")
    lines.append(f"- **Known limitations:** {sysinfo['known_limitations']}")
    lines.append("")
    perf = doc["performance"]
    lines.append("## Performance (Art.13(3)(b)(ii)) — provider to supply")
    lines.append(f"- **Accuracy metrics:** {perf['accuracy_metrics']}")
    lines.append(
        f"- **Robustness/cybersecurity metrics:** {perf['robustness_cybersecurity_metrics']}"
    )
    lines.append(f"- **Reasonably foreseeable misuse:** {perf['foreseeable_misuse']}")
    lines.append("")
    ho = doc["human_oversight"]
    lines.append("## Human oversight (Art.13(3)(d) / Art.14)")
    lines.append(ho["measures"])
    lines.append(f"\n- **Provider oversight assignment:** {ho['provider_oversight_assignment']}")
    lines.append("")
    lines.append("## Record-keeping (Art.12 / Art.13(3)(e))")
    lines.append(doc["record_keeping"]["mechanism"])
    lines.append("")
    lines.append("## Input/output controls (Art.15)")
    lines.append(doc["input_output_controls"]["measures"])
    lines.append("")
    lines.append(f"---\n\n_{doc['disclaimer']}_")
    return "\n".join(lines)
