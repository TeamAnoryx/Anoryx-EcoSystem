"""Compliance CLI sub-commands for sentinel-cli (F-011, ADR-0013 §CLI).

Exposes operator/dev commands under the ``compliance`` group:

    sentinel-cli compliance keygen   --out priv.pem --pub-out pub.pem
    sentinel-cli compliance evidence  --framework {SOC2|ISO27001} \\
                                       --t0 <iso> --t1 <iso> --tenant <id>
    sentinel-cli compliance export    --framework {SOC2|ISO27001} \\
                                       --t0 <iso> --t1 <iso> --tenant <id> \\
                                       --out <pack.zip>

Honest-language rule: "audit-ready" throughout; never "compliant".
Every evidence artifact carries: "Certification requires an accredited auditor."

NOTE: these are operator/dev tools that accept --tenant explicitly because
there is no Bearer-key context in the CLI.  This is the local operator path,
distinct from the tenant-self-service HTTP endpoint.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_iso(value: str, name: str) -> datetime:
    """Parse an ISO-8601 string; raise argparse.ArgumentTypeError on failure."""
    try:
        dt = datetime.fromisoformat(value)
        # Make timezone-aware (UTC) if naive so window comparisons are consistent.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name}: invalid ISO-8601 datetime: {value!r}") from exc


def _cli_validate_window(t0: datetime, t1: datetime) -> None:
    """Raise SystemExit(1) with a clean error message when t0 >= t1.

    Wraps compliance.evidence.validate_window so the CLI exits cleanly
    rather than propagating EvidenceWindowError.
    """
    from compliance.errors import EvidenceWindowError
    from compliance.evidence import validate_window

    try:
        validate_window(t0, t1)
    except EvidenceWindowError:
        print(
            f"error: --t0 must be strictly before --t1 "
            f"(got t0={t0.isoformat()!r} >= t1={t1.isoformat()!r})",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# compliance keygen
# ---------------------------------------------------------------------------


def _cmd_keygen(out: str, pub_out: str) -> int:
    """Generate an ES256 P-256 keypair for compliance pack signing."""
    from policy.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

    private_key, public_key = generate_keypair()
    Path(out).write_bytes(private_key_to_pem(private_key))
    Path(pub_out).write_bytes(public_key_to_pem(public_key))
    with contextlib.suppress(OSError):
        os.chmod(out, 0o600)  # best-effort POSIX permissions
    if sys.platform == "win32":
        print(
            f"WARNING: file permissions are not enforced on Windows — " f"protect {out} manually."
        )
    print(f"wrote compliance pack signing key (private) -> {out}")
    print(f"wrote compliance pack signing key (public)  -> {pub_out}")
    print(
        "NOTE: these are compliance pack signing keys — protect the private key. "
        "Production keys must be deploy-injected, never stored in code or version control."
    )
    return 0


# ---------------------------------------------------------------------------
# compliance evidence
# ---------------------------------------------------------------------------


def _print_evidence_summary(gap_report) -> None:  # type: ignore[no-untyped-def]
    """Print a readable per-control status table + readiness score."""
    from compliance.constants import DISCLAIMER

    print(
        f"\nAudit-ready evidence summary — {gap_report.framework} "
        f"(v{gap_report.framework_version})"
    )
    print(f"Window: {gap_report.t0.isoformat()} -> {gap_report.t1.isoformat()}")
    print(
        f"Readiness score: {gap_report.readiness:.1%}  "
        f"({gap_report.passed} passed / {gap_report.applicable} applicable)"
    )
    print(
        f"Controls: {gap_report.total} total | "
        f"{gap_report.passed} passed | "
        f"{gap_report.gap} gap | "
        f"{gap_report.not_covered} not_covered | "
        f"{gap_report.not_applicable} not_applicable"
    )
    print()

    for r in gap_report.results:
        tag = r.status.upper().ljust(15)
        count_info = f"  evidence_count={r.evidence_count}" if r.evidence_count else ""
        print(f"  [{tag}] {r.control_id}  {r.title}{count_info}")

    gaps = [r for r in gap_report.results if r.status in ("gap", "not_covered")]
    if gaps:
        print(f"\nGap/not-covered controls ({len(gaps)}):")
        for r in gaps:
            hint = (
                "No Sentinel control mapping — add one in the framework YAML."
                if r.status == "not_covered"
                else "Sentinel control mapped but no evidence events in this window."
            )
            print(f"  {r.control_id}: {hint}")

    print(f"\nDISCLAIMER: {DISCLAIMER}\n")


async def _run_evidence(framework: str, t0: datetime, t1: datetime, tenant: str) -> int:
    from compliance.errors import ComplianceError
    from compliance.evidence import generate_evidence
    from compliance.gap_analysis import analyze_gaps
    from compliance.mapping import load_framework

    try:
        fw_map = load_framework(framework)
        projection = await generate_evidence(fw_map, t0, t1, tenant_id=tenant)
        gap_report = analyze_gaps(fw_map, projection)
    except ComplianceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _print_evidence_summary(gap_report)
    return 0


def _cmd_evidence(framework: str, t0: datetime, t1: datetime, tenant: str) -> int:
    """Run generate_evidence + analyze_gaps; print a readable summary."""
    return asyncio.run(_run_evidence(framework, t0, t1, tenant))


# ---------------------------------------------------------------------------
# compliance export
# ---------------------------------------------------------------------------


async def _run_export(
    framework: str,
    t0: datetime,
    t1: datetime,
    tenant: str,
    out: str,
) -> int:
    from compliance.constants import DISCLAIMER
    from compliance.errors import ComplianceError, PackSigningKeyError
    from compliance.evidence import generate_evidence, read_chain_segment
    from compliance.gap_analysis import analyze_gaps
    from compliance.mapping import load_framework
    from compliance.pack import (
        build_pack_record,
        export_pack_zip,
        load_pack_signing_keys,
        sign_pack,
    )
    from policy.crypto import canonical_claims

    try:
        private_key, public_key = load_pack_signing_keys()
    except PackSigningKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "Ensure COMPLIANCE_PACK_SIGNING_KEY_PATH and COMPLIANCE_PACK_PUBKEY_PATH "
            "are set to valid P-256 PEM files.",
            file=sys.stderr,
        )
        return 1

    try:
        fw_map = load_framework(framework)
        projection = await generate_evidence(fw_map, t0, t1, tenant_id=tenant)
        chain_links = await read_chain_segment(t0, t1, tenant_id=tenant)
        gap_report = analyze_gaps(fw_map, projection)
    except ComplianceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    from compliance.constants import SENTINEL_VERSION

    record = build_pack_record(
        gap_report,
        projection,
        chain_links,
        tenant_id=tenant,
        sentinel_version=SENTINEL_VERSION,
    )
    jws = sign_pack(record, private_key)
    out_path = export_pack_zip(record, jws, public_key, out_path=out)

    content_hash = hashlib.sha256(canonical_claims(record)).hexdigest()
    print(f"Audit-ready evidence pack written -> {out_path}")
    print(f"Content hash (signed canonical): {content_hash}")
    print(f"DISCLAIMER: {DISCLAIMER}")
    return 0


def _cmd_export(framework: str, t0: datetime, t1: datetime, tenant: str, out: str) -> int:
    """Run the full pipeline and write a signed ZIP evidence pack."""
    return asyncio.run(_run_export(framework, t0, t1, tenant, out))


# ---------------------------------------------------------------------------
# Parser registration (called from policy.cli.main)
# ---------------------------------------------------------------------------

_FRAMEWORKS = ("SOC2", "ISO27001")


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the ``compliance`` group to *subparsers* (top-level sentinel-cli)."""
    comp_p = subparsers.add_parser(
        "compliance",
        help="Compliance audit-readiness commands (F-011).",
    )
    cmds = comp_p.add_subparsers(dest="cmd", required=True)

    # --- keygen ---------------------------------------------------------------
    kg = cmds.add_parser(
        "keygen",
        help="Generate an ES256 P-256 keypair for compliance pack signing.",
    )
    kg.add_argument("--out", required=True, help="Path to write the private key PEM.")
    kg.add_argument("--pub-out", required=True, help="Path to write the public key PEM.")

    # --- evidence -------------------------------------------------------------
    ev = cmds.add_parser(
        "evidence",
        help="Generate an audit-ready evidence summary (no DB export).",
    )
    ev.add_argument(
        "--framework",
        required=True,
        choices=_FRAMEWORKS,
        help="Framework identifier.",
    )
    ev.add_argument(
        "--t0",
        required=True,
        metavar="ISO",
        help="Window start (inclusive) as an ISO-8601 datetime.",
    )
    ev.add_argument(
        "--t1",
        required=True,
        metavar="ISO",
        help="Window end (exclusive) as an ISO-8601 datetime.",
    )
    ev.add_argument(
        "--tenant",
        required=True,
        metavar="TENANT_ID",
        help=(
            "Tenant identifier.  Operator/dev path: tenant is explicit "
            "here because there is no Bearer context in the CLI."
        ),
    )

    # --- export ---------------------------------------------------------------
    ex = cmds.add_parser(
        "export",
        help="Build and sign a compliance evidence pack ZIP.",
    )
    ex.add_argument(
        "--framework",
        required=True,
        choices=_FRAMEWORKS,
        help="Framework identifier.",
    )
    ex.add_argument("--t0", required=True, metavar="ISO", help="Window start (inclusive).")
    ex.add_argument("--t1", required=True, metavar="ISO", help="Window end (exclusive).")
    ex.add_argument(
        "--tenant",
        required=True,
        metavar="TENANT_ID",
        help="Tenant identifier (operator/dev path — no Bearer context in CLI).",
    )
    ex.add_argument("--out", required=True, help="Destination path for the signed ZIP.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``compliance`` sub-command; return process exit code."""
    if args.cmd == "keygen":
        return _cmd_keygen(args.out, args.pub_out)

    # Shared window parsing for evidence + export.
    t0 = _parse_iso(args.t0, "--t0")
    t1 = _parse_iso(args.t1, "--t1")
    _cli_validate_window(t0, t1)

    if args.cmd == "evidence":
        return _cmd_evidence(args.framework, t0, t1, args.tenant)
    if args.cmd == "export":
        return _cmd_export(args.framework, t0, t1, args.tenant, args.out)

    print(f"error: unknown compliance command: {args.cmd!r}", file=sys.stderr)
    return 2
