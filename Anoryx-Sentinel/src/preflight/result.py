"""CheckResult value object + status constants for the F-031 preflight gate."""

from __future__ import annotations

from dataclasses import dataclass, field

# Status ordering by severity (used to compute the overall gate outcome).
STATUS_PASS = "pass"  # noqa: S105 — a status label, not a credential
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_SKIP = "skip"

_SEVERITY = {STATUS_PASS: 0, STATUS_SKIP: 0, STATUS_WARN: 1, STATUS_FAIL: 2}


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single preflight check.

    status:
        "pass" — verified good.
        "warn" — a soft concern; does NOT fail the gate but is surfaced.
        "fail" — a hard blocker; fails the launch gate (non-zero exit).
        "skip" — the check could not run (e.g. no DB configured) and was
                 intentionally not evaluated. Does NOT fail the gate on its own,
                 but is reported so the operator knows coverage was incomplete.
    detail:
        Human-readable explanation of what was observed.
    remediation:
        What to do about a warn/fail (empty for pass).
    evidence:
        Optional structured facts (e.g. rows_checked, backend name).
    """

    name: str
    status: str
    detail: str
    remediation: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.status == STATUS_FAIL


def worst_status(results: list[CheckResult]) -> str:
    """Return the highest-severity status across results (pass if empty)."""
    worst = STATUS_PASS
    for r in results:
        if _SEVERITY[r.status] > _SEVERITY[worst]:
            worst = r.status
    return worst


def gate_passed(results: list[CheckResult]) -> bool:
    """The launch gate passes iff NO check is a hard fail. warn/skip do not
    block (they are surfaced for the operator's judgement)."""
    return not any(r.is_blocking for r in results)
