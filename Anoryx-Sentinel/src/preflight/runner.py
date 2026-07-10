"""Runs the F-031 preflight checks and aggregates the gate outcome (ADR-0037)."""

from __future__ import annotations

from preflight.checks import (
    check_audit_chain_integrity,
    check_config_sane,
    check_migrations_at_head,
    check_no_open_critical_high,
    check_secrets_vaulted,
)
from preflight.result import CheckResult, gate_passed, worst_status

# Names of the DB-dependent checks (so callers can opt to skip them offline).
DB_CHECKS = frozenset({"migrations-at-head", "audit-chain-integrity"})


async def run_all_checks(*, skip: frozenset[str] = frozenset()) -> list[CheckResult]:
    """Run every preflight check (except those named in `skip`).

    Sync checks run first (cheap, no I/O), then the async DB checks. Returns
    results in a stable order.
    """
    results: list[CheckResult] = []

    for fn in (check_secrets_vaulted, check_config_sane, check_no_open_critical_high):
        result = fn()
        if result.name not in skip:
            results.append(result)

    for coro_fn in (check_migrations_at_head, check_audit_chain_integrity):
        # Peek at the name via a cheap call is not possible; map by known names.
        name = {
            check_migrations_at_head: "migrations-at-head",
            check_audit_chain_integrity: "audit-chain-integrity",
        }[coro_fn]
        if name in skip:
            continue
        results.append(await coro_fn())

    return results


def summarize(results: list[CheckResult]) -> dict:
    """Return a JSON-serialisable summary of a preflight run."""
    return {
        "gate_passed": gate_passed(results),
        "worst_status": worst_status(results),
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "detail": r.detail,
                "remediation": r.remediation,
                "evidence": r.evidence,
            }
            for r in results
        ],
    }
