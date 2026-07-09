"""BAA-ready evidence summary for HIPAA (F-029, ADR-0035).

Renders the HIPAA gap report (produced by the existing F-011 engine) into a
Business-Associate-Agreement-oriented document: a readiness summary, a
Technical-Safeguards (§164.312) status table, an audit-control (§164.312(b))
attestation grounded in the F-003 hash-chain, and a PHI-safeguard statement
grounded in the built-in PHI pattern set. Pure functions over a GapReport — no
DB, no I/O — so they are unit-testable with a synthetic report.

HONEST FRAMING (non-negotiable, mirrors compliance.constants.DISCLAIMER): this
is evidence for BAA DUE DILIGENCE and audit PREPARATION. HIPAA has no
certification; this document does NOT make anyone "HIPAA compliant", and a
signed BAA plus the full administrative and physical safeguard program remain
the operator's responsibility. Sentinel evidences only the technical safeguards
within its code boundary.
"""

from __future__ import annotations

from typing import Any

from compliance.constants import DISCLAIMER, SENTINEL_VERSION
from compliance.gap_analysis import GapReport
from compliance.hipaa.phi_patterns import PHI_PATTERN_SPECS

_BAA_FRAMING = (
    "BAA due-diligence evidence. HIPAA has no certification; this is not a "
    "compliance attestation. A signed Business Associate Agreement and the "
    "operator's full administrative and physical safeguard program remain "
    "required. Sentinel evidences only the technical safeguards within its "
    "application code boundary."
)

# Technical-Safeguard control-id prefixes (§164.312) — highlighted separately in
# the BAA summary because they are the safeguards Sentinel most directly evidences.
_TECHNICAL_SAFEGUARD_PREFIX = "164.312"


def build_baa_summary(gap_report: GapReport, *, tenant_id: str) -> dict[str, Any]:
    """Build a structured BAA-ready evidence summary from a HIPAA GapReport.

    Raises ValueError if the report is not for the HIPAA framework (fail-closed —
    a BAA summary built from a SOC2/ISO report would be dishonest).
    """
    if gap_report.framework != "HIPAA":
        raise ValueError(f"BAA summary requires a HIPAA gap report, got {gap_report.framework!r}")

    technical = [
        r for r in gap_report.results if r.control_id.startswith(_TECHNICAL_SAFEGUARD_PREFIX)
    ]
    technical_passed = sum(1 for r in technical if r.status == "passed")

    return {
        "document_type": "sentinel-hipaa-baa-evidence/v1",
        "sentinel_version": SENTINEL_VERSION,
        "tenant_id": tenant_id,
        "framework": gap_report.framework,
        "framework_version": gap_report.framework_version,
        "window": {"t0": gap_report.t0.isoformat(), "t1": gap_report.t1.isoformat()},
        "readiness": {
            "score": gap_report.readiness,
            "passed": gap_report.passed,
            "applicable": gap_report.applicable,
            "total": gap_report.total,
            "gap": gap_report.gap,
            "not_covered": gap_report.not_covered,
            "not_applicable": gap_report.not_applicable,
        },
        "technical_safeguards_164_312": {
            "total": len(technical),
            "passed": technical_passed,
        },
        "controls": [
            {
                "control_id": r.control_id,
                "title": r.title,
                "status": r.status,
                "evidence_count": r.evidence_count,
                "evidence_event_types": list(r.evidence_event_types),
            }
            for r in gap_report.results
        ],
        "audit_control_attestation": {
            "safeguard": "164.312(b)",
            "mechanism": "append-only hash-chained audit log (F-003)",
            "statement": (
                "Every gateway event is recorded in an append-only audit log whose "
                "sequence_number/prev_hash/row_hash chain makes any alteration or "
                "deletion of recorded activity detectable — the technical mechanism "
                "for the HIPAA §164.312(b) audit-controls safeguard."
            ),
        },
        "phi_safeguard_statement": {
            "built_in_phi_pattern_count": len(PHI_PATTERN_SPECS),
            "phi_pattern_labels": [s.name for s in PHI_PATTERN_SPECS],
            "statement": (
                "Sentinel provides high-coverage detection of common structured PHI "
                "identifiers (built-in patterns) plus F-005 free-text PII detection; "
                "matches are masked/blocked and recorded as pii_blocked events. This "
                "is high-coverage detection, NOT 100% PHI detection; de-identification "
                "under 45 CFR 164.514 remains the covered entity's determination."
            ),
        },
        "framing": _BAA_FRAMING,
        "disclaimer": DISCLAIMER,
    }


def render_baa_markdown(summary: dict[str, Any]) -> str:
    """Render a BAA summary dict as an operator-readable Markdown document."""
    r = summary["readiness"]
    ts = summary["technical_safeguards_164_312"]
    lines: list[str] = []
    lines.append("# HIPAA BAA-Readiness Evidence Summary")
    lines.append("")
    lines.append(f"> {summary['framing']}")
    lines.append("")
    lines.append(f"- **Sentinel version:** {summary['sentinel_version']}")
    lines.append(f"- **Tenant:** {summary['tenant_id']}")
    lines.append(f"- **Framework:** {summary['framework']} (v{summary['framework_version']})")
    lines.append(f"- **Window:** {summary['window']['t0']} → {summary['window']['t1']}")
    lines.append("")
    lines.append(
        f"**Readiness (audit-ready evidence):** {r['score']:.1%} "
        f"({r['passed']} passed / {r['applicable']} applicable)"
    )
    lines.append(f"**Technical Safeguards §164.312:** {ts['passed']}/{ts['total']} evidenced")
    lines.append("")
    lines.append("## Control status")
    lines.append("")
    lines.append("| Control | Status | Evidence | Title |")
    lines.append("|---|---|---|---|")
    for c in summary["controls"]:
        lines.append(
            f"| {c['control_id']} | {c['status']} | {c['evidence_count']} | {c['title']} |"
        )
    lines.append("")
    aca = summary["audit_control_attestation"]
    lines.append(f"## Audit Controls — §{aca['safeguard']}")
    lines.append("")
    lines.append(aca["statement"])
    lines.append("")
    phi = summary["phi_safeguard_statement"]
    lines.append("## PHI Safeguards")
    lines.append("")
    lines.append(phi["statement"])
    lines.append("")
    lines.append(
        f"Built-in PHI pattern set ({phi['built_in_phi_pattern_count']}): "
        + ", ".join(phi["phi_pattern_labels"])
    )
    lines.append("")
    lines.append(f"---\n\n_{summary['disclaimer']}_")
    return "\n".join(lines)
