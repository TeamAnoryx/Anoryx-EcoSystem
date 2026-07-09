"""Unit tests for the F-029 BAA evidence summary (synthetic GapReport, no DB)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from compliance.gap_analysis import ControlResult, GapReport
from compliance.hipaa.baa_export import build_baa_summary, render_baa_markdown


def _control(control_id, status, count=0, title="t"):
    return ControlResult(
        control_id=control_id,
        title=title,
        status=status,
        evidence_event_types=("usage",),
        evidence_count=count,
        rationale=None,
    )


def _hipaa_report(results) -> GapReport:
    passed = sum(1 for r in results if r.status == "passed")
    gap = sum(1 for r in results if r.status == "gap")
    na = sum(1 for r in results if r.status == "not_applicable")
    nc = sum(1 for r in results if r.status == "not_covered")
    applicable = len(results) - na
    return GapReport(
        framework="HIPAA",
        framework_version="2013-Omnibus-45CFR164-SubpartC",
        t0=datetime(2026, 1, 1, tzinfo=UTC),
        t1=datetime(2026, 2, 1, tzinfo=UTC),
        results=tuple(results),
        total=len(results),
        passed=passed,
        gap=gap,
        not_applicable=na,
        not_covered=nc,
        applicable=applicable,
        readiness=(passed / applicable if applicable else 0.0),
        disclaimer="Automated evidence for audit preparation.",
    )


def test_build_summary_shape():
    report = _hipaa_report(
        [
            _control("164.312(a)(1)", "passed", 5),
            _control("164.312(b)", "passed", 9),
            _control("164.312(e)(1)", "not_covered"),
            _control("164.310(a)(1)", "not_applicable"),
        ]
    )
    summary = build_baa_summary(report, tenant_id="tenant-x")
    assert summary["document_type"] == "sentinel-hipaa-baa-evidence/v1"
    assert summary["framework"] == "HIPAA"
    assert summary["tenant_id"] == "tenant-x"
    # 3 technical safeguards (164.312*), 2 passed
    assert summary["technical_safeguards_164_312"]["total"] == 3
    assert summary["technical_safeguards_164_312"]["passed"] == 2
    assert summary["audit_control_attestation"]["safeguard"] == "164.312(b)"
    assert summary["phi_safeguard_statement"]["built_in_phi_pattern_count"] >= 1
    assert "disclaimer" in summary


def test_build_summary_rejects_non_hipaa_report():
    report = _hipaa_report([_control("CC6.1", "passed", 1)])
    # tamper the framework to a non-HIPAA value
    object.__setattr__(report, "framework", "SOC2")
    with pytest.raises(ValueError):
        build_baa_summary(report, tenant_id="t")


def test_render_markdown_contains_key_sections_and_disclaimer():
    report = _hipaa_report([_control("164.312(b)", "passed", 3, title="Audit Controls")])
    summary = build_baa_summary(report, tenant_id="tenant-y")
    md = render_baa_markdown(summary)
    assert "# HIPAA BAA-Readiness Evidence Summary" in md
    assert "Audit Controls" in md
    assert "PHI Safeguards" in md
    assert "164.312(b)" in md
    # honest framing must be present (never claims certification)
    assert "not a" in md.lower() or "no certification" in md.lower()
    assert summary["disclaimer"] in md


def test_render_markdown_is_deterministic():
    report = _hipaa_report([_control("164.312(a)(1)", "passed", 1)])
    s = build_baa_summary(report, tenant_id="t")
    assert render_baa_markdown(s) == render_baa_markdown(s)
