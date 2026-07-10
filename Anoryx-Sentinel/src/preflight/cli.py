"""sentinel-preflight — production due-diligence gate CLI (F-031, ADR-0037).

    sentinel-preflight run [--json] [--skip secrets-vaulted,...] [--offline]

Runs the pre-launch checklist and EXITS NON-ZERO if any check hard-fails — wire
it into a deploy pipeline as a launch gate. --offline skips the DB-dependent
checks (migrations, audit chain) for a config-only preflight. Warnings and
skips do NOT fail the gate but are always surfaced.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from preflight.result import STATUS_FAIL, STATUS_PASS, STATUS_SKIP, STATUS_WARN
from preflight.runner import DB_CHECKS, run_all_checks, summarize

_STATUS_TAG = {
    STATUS_PASS: "PASS",
    STATUS_WARN: "WARN",
    STATUS_FAIL: "FAIL",
    STATUS_SKIP: "SKIP",
}


def _print_human(results) -> None:
    print("Sentinel production due-diligence gate (F-031)\n")
    for r in results:
        print(f"  [{_STATUS_TAG[r.status]}] {r.name}")
        print(f"        {r.detail}")
        if r.remediation and r.status in (STATUS_WARN, STATUS_FAIL):
            print(f"        -> {r.remediation}")
    fails = [r for r in results if r.status == STATUS_FAIL]
    warns = [r for r in results if r.status == STATUS_WARN]
    print()
    if fails:
        print(f"GATE: BLOCKED — {len(fails)} hard failure(s), {len(warns)} warning(s).")
    else:
        print(f"GATE: PASS — 0 hard failures, {len(warns)} warning(s).")


async def _run(skip: frozenset[str], as_json: bool) -> int:
    results = await run_all_checks(skip=skip)
    if as_json:
        print(json.dumps(summarize(results), indent=2))
    else:
        _print_human(results)
    # Non-zero exit iff any hard failure (the gate).
    return 1 if any(r.status == STATUS_FAIL for r in results) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-preflight",
        description="Anoryx Sentinel production due-diligence gate (F-031).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run", help="Run all checks; exit non-zero on any hard failure.")
    run_p.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON.")
    run_p.add_argument(
        "--skip",
        default="",
        help="Comma-separated check names to skip (e.g. audit-chain-integrity).",
    )
    run_p.add_argument(
        "--offline",
        action="store_true",
        help="Skip DB-dependent checks (migrations, audit chain) for a config-only preflight.",
    )

    args = parser.parse_args(argv)
    if args.cmd == "run":
        skip = {s.strip() for s in args.skip.split(",") if s.strip()}
        if args.offline:
            skip |= set(DB_CHECKS)
        return asyncio.run(_run(frozenset(skip), args.as_json))
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
