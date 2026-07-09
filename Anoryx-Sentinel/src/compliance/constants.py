"""Compliance Evidence Engine — module-level constants (F-011).

Honest-language rule: "audit-ready" throughout; never "compliant".
"""

from __future__ import annotations

# Frameworks with a shipped control-map YAML in frameworks/.  HIPAA (F-029) is
# CLI/engine-only — the HTTP export surface (routes/compliance.py) stays
# SOC2+ISO27001 as pinned in contracts/openapi.yaml (api-architect-owned; a
# HIPAA HTTP enum entry is deferred, see docs/adr/0035).  GDPR / EU_AI_ACT
# remain deferred extension points.
FRAMEWORKS: tuple[str, ...] = ("SOC2", "ISO27001", "HIPAA")

# Mandatory disclaimer — MUST appear on every evidence artifact and UI element.
DISCLAIMER: str = (
    "Automated evidence for audit preparation. " "Certification requires an accredited auditor."
)

# Control-status literals (D4 — gap analysis).
STATUS_PASSED: str = "passed"
STATUS_GAP: str = "gap"
STATUS_NOT_APPLICABLE: str = "not_applicable"
STATUS_NOT_COVERED: str = "not_covered"

# Set of all valid status values (for internal validation convenience).
VALID_STATUSES: frozenset[str] = frozenset(
    {STATUS_PASSED, STATUS_GAP, STATUS_NOT_APPLICABLE, STATUS_NOT_COVERED}
)

# Sentinel release version string — single source of truth for compliance artifacts.
SENTINEL_VERSION: str = "1.0.0"
