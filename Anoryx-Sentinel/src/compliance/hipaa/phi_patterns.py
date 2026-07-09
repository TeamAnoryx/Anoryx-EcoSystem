"""Curated built-in PHI (Protected Health Information) patterns (F-029, ADR-0035).

Reuses F-028's ReDoS-safe regex engine (data_protection.custom_pii.engine) —
same compile + timeout-guarded scan — but sources patterns from this CURATED,
version-controlled BUILT-IN set rather than F-028's per-tenant DB store. This is
the "PHI patterns" deliverable of F-029: a defensible starting set of the HIPAA
§164.514(b)(2) "Safe Harbor" identifier types that show up as structured tokens
in AI traffic.

HONEST SCOPE (mandatory): this is HIGH-COVERAGE DETECTION of common structured
PHI identifiers, NOT "100% PHI detection". Free-text PHI (a patient's name/
condition in prose) is the built-in Presidio detector's job (F-005 PERSON/
LOCATION), and even that is not exhaustive. Several identifiers below REQUIRE a
context label (e.g. "MRN:") to keep false positives acceptable — an unlabeled
bare number is intentionally NOT matched. De-identification per §164.514
remains the covered entity's determination; this set aids it, it does not
certify it.

Every pattern is validated by F-028's validator at module import (compile +
length + ReDoS heuristic) so a malformed addition fails loudly, and each is
matched under the same per-call timeout backstop as F-028.
"""

from __future__ import annotations

from dataclasses import dataclass

from data_protection.custom_pii.engine import CompiledPattern, CustomPiiSpan, compile_pattern, scan
from data_protection.custom_pii.validator import validate_pattern

# Per-match timeout for the built-in PHI scan (seconds) — same backstop rationale
# as F-028's custom_pii_match_timeout_seconds.
PHI_MATCH_TIMEOUT_SECONDS = 0.25
# Max chars scanned in one call (latency cap).
PHI_MAX_INSPECT_CHARS = 50_000


@dataclass(frozen=True)
class PhiPatternSpec:
    """A curated built-in PHI pattern definition."""

    name: str  # entity label, e.g. "PHI_MRN"
    pattern: str  # regex text
    score: float  # confidence attached to matches
    note: str  # short description of what it targets


# Curated set. Context-labelled where a bare token would be too ambiguous
# (MRN, NPI, health-plan/account numbers). ReDoS-safe by construction (no
# nested quantifiers) — validated at import below.
PHI_PATTERN_SPECS: tuple[PhiPatternSpec, ...] = (
    PhiPatternSpec(
        name="PHI_SSN",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        score=0.9,
        note="US Social Security Number (PHI when linked to health data).",
    ),
    PhiPatternSpec(
        name="PHI_MEDICARE_MBI",
        # Medicare Beneficiary Identifier: 11 chars, position-typed
        # (digit-letter mix), no S,L,O,I,B,Z in letter positions.
        pattern=r"\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d"
        r"[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d"
        r"[ACDEFGHJKMNPQRTUVWXY]{2}\d{2}\b",
        score=0.85,
        note="Medicare Beneficiary Identifier (MBI).",
    ),
    PhiPatternSpec(
        name="PHI_DEA",
        pattern=r"\b[A-Za-z]{2}\d{7}\b",
        score=0.6,
        note="DEA registration number (2 letters + 7 digits).",
    ),
    PhiPatternSpec(
        name="PHI_NPI",
        # Requires an NPI context label — a bare 10-digit run is far too common.
        pattern=r"(?i:NPI)\s*[:#]?\s*\d{10}\b",
        score=0.8,
        note="National Provider Identifier (context-labelled).",
    ),
    PhiPatternSpec(
        name="PHI_MRN",
        # Medical Record Numbers are site-specific; require an MRN context label.
        pattern=r"(?i:MRN)\s*[:#]?\s*[A-Za-z0-9-]{5,16}\b",
        score=0.75,
        note="Medical Record Number (context-labelled).",
    ),
    PhiPatternSpec(
        name="PHI_ICD10",
        # ICD-10-CM diagnosis code: letter (not U placeholder rules simplified) +
        # 2 digits + optional dotted 1-4 alnum subcode.
        pattern=r"(?i:ICD-?10)?\s*[:#]?\s*\b[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b",
        score=0.55,
        note="ICD-10-CM diagnosis code.",
    ),
    PhiPatternSpec(
        name="PHI_HEALTH_PLAN_ID",
        # Context-labelled subscriber/member/policy number.
        pattern=r"(?i:member|subscriber|policy|plan)\s*(?:id|no|number|#)?\s*[:#]?\s*[A-Za-z0-9-]{6,20}\b",
        score=0.6,
        note="Health-plan member/subscriber/policy identifier (context-labelled).",
    ),
)


def _validate_all() -> None:
    """Fail loudly at import if any curated pattern is malformed/ReDoS-risky."""
    for spec in PHI_PATTERN_SPECS:
        # max_length generous — these are maintainer-authored, not client input.
        validate_pattern(spec.pattern, max_length=1024)


_validate_all()


def get_compiled_phi_patterns() -> list[CompiledPattern]:
    """Return the curated PHI patterns compiled for the F-028 engine."""
    return [
        compile_pattern(spec.name, spec.pattern, score=spec.score, action=None)
        for spec in PHI_PATTERN_SPECS
    ]


def scan_phi(
    text: str,
    *,
    timeout_seconds: float = PHI_MATCH_TIMEOUT_SECONDS,
    max_chars: int = PHI_MAX_INSPECT_CHARS,
) -> tuple[list[CustomPiiSpan], list[str]]:
    """Scan text for curated PHI identifiers. Returns (spans, timed_out_names).

    Bounded input + per-match timeout — the same ReDoS-safe posture as F-028.
    """
    patterns = get_compiled_phi_patterns()
    return scan(text[:max_chars], patterns, timeout_seconds=timeout_seconds)
