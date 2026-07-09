"""Unit tests for the F-029 built-in PHI pattern set (no DB, no spacy)."""

from __future__ import annotations

from compliance.hipaa.phi_patterns import (
    PHI_PATTERN_SPECS,
    get_compiled_phi_patterns,
    scan_phi,
)


def _labels(spans):
    return {s.name for s in spans}


def test_all_specs_compile():
    compiled = get_compiled_phi_patterns()
    assert len(compiled) == len(PHI_PATTERN_SPECS)


def test_detects_ssn():
    spans, timed = scan_phi("patient ssn 123-45-6789 on file")
    assert timed == []
    assert "PHI_SSN" in _labels(spans)


def test_detects_labelled_mrn():
    spans, _ = scan_phi("record MRN: AB12345 admitted")
    assert "PHI_MRN" in _labels(spans)


def test_detects_labelled_npi():
    spans, _ = scan_phi("provider NPI 1234567890")
    assert "PHI_NPI" in _labels(spans)


def test_detects_dea():
    spans, _ = scan_phi("script from AB1234567 today")
    assert "PHI_DEA" in _labels(spans)


def test_unlabelled_bare_10_digits_not_matched_as_npi():
    # A bare 10-digit run with no NPI context must NOT be flagged as NPI
    # (false-positive control — the pattern requires the label).
    spans, _ = scan_phi("order number 1234567890 shipped")
    assert "PHI_NPI" not in _labels(spans)


def test_clean_text_no_matches():
    spans, timed = scan_phi("the weather is nice today")
    assert spans == []
    assert timed == []


def test_scan_is_bounded_by_max_chars():
    # Content past max_chars is not scanned.
    huge = "x" * 100 + " 123-45-6789"
    spans, _ = scan_phi(huge, max_chars=50)
    assert "PHI_SSN" not in _labels(spans)
