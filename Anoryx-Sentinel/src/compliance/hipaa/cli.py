"""sentinel-hipaa — operator CLI for the F-029 HIPAA module (ADR-0035).

    sentinel-hipaa phi-scan --text "..."            (preview PHI detection)
    sentinel-hipaa baa-summary --tenant <id> --t0 <iso> --t1 <iso> [--out f.md] [--json]

phi-scan runs the built-in curated PHI pattern set (reusing F-028's ReDoS-safe
engine); matched VALUES are never printed (only label + span). baa-summary
builds a HIPAA gap report over an audit-log window and renders a BAA-readiness
evidence document (Markdown by default, or --json).

The HIPAA framework's per-control evidence is ALSO available via the generic
compliance CLI: `sentinel-cli compliance evidence --framework HIPAA ...`. This
CLI adds the HIPAA-specific PHI scan + BAA rendering on top.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime

import structlog

log = structlog.get_logger(__name__)


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _cmd_phi_scan(text: str) -> int:
    from compliance.hipaa.phi_patterns import scan_phi

    spans, timed_out = scan_phi(text)
    if timed_out:
        print(f"WARNING: patterns timed out (ReDoS guard): {timed_out}", file=sys.stderr)
    if not spans:
        print("no PHI identifiers detected")
        return 0
    print(f"{len(spans)} PHI match(es) (values NOT printed):")
    for s in sorted(spans, key=lambda x: x.start):
        print(f"  {s.name}\t[{s.start}:{s.end}]\tscore={s.score}")
    return 0


async def _run_baa_summary(
    tenant: str, t0: datetime, t1: datetime, out: str | None, as_json: bool
) -> int:
    from compliance.errors import ComplianceError
    from compliance.evidence import generate_evidence
    from compliance.gap_analysis import analyze_gaps
    from compliance.hipaa.baa_export import build_baa_summary, render_baa_markdown
    from compliance.mapping import load_framework

    try:
        fw_map = load_framework("HIPAA")
        projection = await generate_evidence(fw_map, t0, t1, tenant_id=tenant)
        gap_report = analyze_gaps(fw_map, projection)
    except ComplianceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = build_baa_summary(gap_report, tenant_id=tenant)
    rendered = json.dumps(summary, indent=2) if as_json else render_baa_markdown(summary)

    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"wrote BAA summary to {out}")
    else:
        print(rendered)
    return 0


def _cmd_baa_summary(
    tenant: str, t0: datetime, t1: datetime, out: str | None, as_json: bool
) -> int:
    return asyncio.run(_run_baa_summary(tenant, t0, t1, out, as_json))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-hipaa", description="Anoryx Sentinel HIPAA module CLI (F-029)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("phi-scan", help="Preview built-in PHI detection on text.")
    scan_p.add_argument("--text", required=True)

    baa_p = sub.add_parser("baa-summary", help="Render a BAA-readiness evidence summary.")
    baa_p.add_argument("--tenant", required=True)
    baa_p.add_argument("--t0", required=True, help="Window start (ISO-8601).")
    baa_p.add_argument("--t1", required=True, help="Window end (ISO-8601).")
    baa_p.add_argument("--out", default=None, help="Write to a file instead of stdout.")
    baa_p.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit JSON not Markdown."
    )

    args = parser.parse_args(argv)

    if args.cmd == "phi-scan":
        return _cmd_phi_scan(args.text)
    if args.cmd == "baa-summary":
        try:
            t0 = _parse_iso(args.t0)
            t1 = _parse_iso(args.t1)
        except ValueError as exc:
            print(f"error: invalid --t0/--t1 (use ISO-8601): {exc}", file=sys.stderr)
            return 2
        return _cmd_baa_summary(args.tenant, t0, t1, args.out, args.as_json)
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
