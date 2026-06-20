"""Tests for compliance CLI sub-commands (F-011, ADR-0013 §CLI).

Coverage:
- keygen: writes two valid PEMs, loadable by crypto.load_*_pem.
- arg parsing: evidence/export parse required args; missing framework -> SystemExit(2).
- DISCLAIMER appears in evidence output.
- export without signing-key env -> clean non-zero exit + no traceback leak.

DB dependency: evidence/export happy-path tests require DATABASE_URL; they are
skipped cleanly when it is absent (DB-optional).
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _invoke(argv: list[str]) -> tuple[int, str, str]:
    """Invoke sentinel-cli (policy.cli.main) with *argv*; return (rc, stdout, stderr)."""
    from policy.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = captured_out, captured_err
    try:
        try:
            rc = main(argv)
            if rc is None:
                rc = 0
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return rc, captured_out.getvalue(), captured_err.getvalue()


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def test_keygen_writes_valid_pems(tmp_path: Path) -> None:
    """keygen writes two PEM files that load back as valid P-256 key objects."""
    from policy.crypto import load_private_key_pem, load_public_key_pem

    priv = str(tmp_path / "test_priv.pem")
    pub = str(tmp_path / "test_pub.pem")

    rc, out, err = _invoke(["compliance", "keygen", "--out", priv, "--pub-out", pub])

    assert rc == 0, f"keygen returned non-zero: {err}"
    assert Path(priv).exists(), "private key PEM not written"
    assert Path(pub).exists(), "public key PEM not written"

    # Both files must be loadable as P-256 key objects.
    private_key = load_private_key_pem(Path(priv).read_bytes())
    public_key = load_public_key_pem(Path(pub).read_bytes())
    assert private_key is not None
    assert public_key is not None


def test_keygen_prints_paths(tmp_path: Path) -> None:
    """keygen stdout mentions both output paths."""
    priv = str(tmp_path / "p.pem")
    pub = str(tmp_path / "q.pem")

    rc, out, _ = _invoke(["compliance", "keygen", "--out", priv, "--pub-out", pub])

    assert rc == 0
    assert priv in out
    assert pub in out


def test_keygen_notes_protect_private(tmp_path: Path) -> None:
    """keygen output reminds the operator to protect the private key."""
    priv = str(tmp_path / "p.pem")
    pub = str(tmp_path / "q.pem")

    _, out, _ = _invoke(["compliance", "keygen", "--out", priv, "--pub-out", pub])

    assert "protect" in out.lower() or "private key" in out.lower()


# ---------------------------------------------------------------------------
# Arg parsing — SystemExit on bad/missing framework
# ---------------------------------------------------------------------------


def test_evidence_missing_framework_exits_2() -> None:
    """compliance evidence without --framework -> SystemExit(2)."""
    rc, _, _ = _invoke(
        [
            "compliance",
            "evidence",
            "--t0",
            "2025-01-01T00:00:00",
            "--t1",
            "2025-02-01T00:00:00",
            "--tenant",
            "t-abc",
        ]
    )
    assert rc == 2


def test_export_missing_framework_exits_2(tmp_path: Path) -> None:
    """compliance export without --framework -> SystemExit(2)."""
    rc, _, _ = _invoke(
        [
            "compliance",
            "export",
            "--t0",
            "2025-01-01T00:00:00",
            "--t1",
            "2025-02-01T00:00:00",
            "--tenant",
            "t-abc",
            "--out",
            str(tmp_path / "pack.zip"),
        ]
    )
    assert rc == 2


def test_evidence_invalid_framework_exits_2() -> None:
    """compliance evidence with an unrecognised framework -> SystemExit(2) (argparse choices)."""
    rc, _, _ = _invoke(
        [
            "compliance",
            "evidence",
            "--framework",
            "GDPR",
            "--t0",
            "2025-01-01T00:00:00",
            "--t1",
            "2025-02-01T00:00:00",
            "--tenant",
            "t-abc",
        ]
    )
    assert rc == 2


def test_evidence_missing_tenant_exits_2() -> None:
    """compliance evidence without --tenant -> SystemExit(2)."""
    rc, _, _ = _invoke(
        [
            "compliance",
            "evidence",
            "--framework",
            "SOC2",
            "--t0",
            "2025-01-01T00:00:00",
            "--t1",
            "2025-02-01T00:00:00",
        ]
    )
    assert rc == 2


def test_evidence_reversed_window_exits_1() -> None:
    """compliance evidence with t0 >= t1 -> exit(1) + clean error message."""
    rc, _, err = _invoke(
        [
            "compliance",
            "evidence",
            "--framework",
            "SOC2",
            "--t0",
            "2025-06-01T00:00:00",
            "--t1",
            "2025-01-01T00:00:00",
            "--tenant",
            "t-abc",
        ]
    )
    assert rc == 1
    assert "t0" in err or "t1" in err or "strictly before" in err


# ---------------------------------------------------------------------------
# compliance --help wires correctly
# ---------------------------------------------------------------------------


def test_compliance_help_shows_subcommands() -> None:
    """compliance --help (via sentinel-cli) does not crash and lists subcommands."""
    rc, out, _ = _invoke(["compliance", "--help"])
    # argparse exits 0 on --help.
    assert rc == 0
    assert "keygen" in out
    assert "evidence" in out
    assert "export" in out


# ---------------------------------------------------------------------------
# DISCLAIMER in evidence output (mocked DB)
# ---------------------------------------------------------------------------


def _make_fake_gap_report():
    """Build a minimal GapReport-like object for mocking."""
    from datetime import datetime, timezone

    from compliance.constants import DISCLAIMER
    from compliance.gap_analysis import GapReport

    t0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    t1 = datetime(2025, 2, 1, tzinfo=timezone.utc)
    return GapReport(
        framework="SOC2",
        framework_version="2017-TSC-rev2022",
        t0=t0,
        t1=t1,
        results=(),
        total=0,
        passed=0,
        gap=0,
        not_applicable=0,
        not_covered=0,
        applicable=0,
        readiness=0.0,
        disclaimer=DISCLAIMER,
    )


def test_evidence_disclaimer_in_output(tmp_path: Path) -> None:
    """compliance evidence prints DISCLAIMER in stdout (mocked DB calls)."""
    from compliance.constants import DISCLAIMER

    gap_report = _make_fake_gap_report()

    with (
        patch("compliance.mapping.load_framework") as mock_load,
        patch("compliance.evidence.generate_evidence", new_callable=AsyncMock) as mock_gen,
        patch("compliance.gap_analysis.analyze_gaps", return_value=gap_report),
    ):
        # generate_evidence returns a minimal EvidenceProjection-like object
        mock_projection = MagicMock()
        mock_gen.return_value = mock_projection
        mock_load.return_value = MagicMock(framework="SOC2", framework_version="2017-TSC-rev2022")

        rc, out, _ = _invoke(
            [
                "compliance",
                "evidence",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-abc",
            ]
        )

    assert rc == 0
    assert DISCLAIMER in out, f"DISCLAIMER not found in output:\n{out}"


# ---------------------------------------------------------------------------
# export without signing-key env -> clean non-zero, no traceback
# ---------------------------------------------------------------------------


def test_export_no_signing_key_env_clean_error(tmp_path: Path) -> None:
    """compliance export without signing-key env vars -> non-zero exit, no traceback."""
    out_zip = str(tmp_path / "pack.zip")

    env_without_keys = {
        k: v
        for k, v in os.environ.items()
        if k not in ("COMPLIANCE_PACK_SIGNING_KEY_PATH", "COMPLIANCE_PACK_PUBKEY_PATH")
    }
    with patch.dict(os.environ, env_without_keys, clear=True):
        rc, stdout, stderr = _invoke(
            [
                "compliance",
                "export",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-abc",
                "--out",
                out_zip,
            ]
        )

    assert rc != 0, "Expected non-zero exit when signing keys are absent"
    combined = stdout + stderr
    assert "Traceback" not in combined, "Traceback leaked to output"
    # A helpful error message must be present (no secret leakage).
    assert (
        "COMPLIANCE_PACK_SIGNING_KEY_PATH" in combined
        or "signing key" in combined.lower()
        or "error" in combined.lower()
    )


def test_export_no_signing_key_does_not_create_zip(tmp_path: Path) -> None:
    """No ZIP file is created when signing keys are absent (fail-closed)."""
    out_zip = tmp_path / "pack.zip"

    env_without_keys = {
        k: v
        for k, v in os.environ.items()
        if k not in ("COMPLIANCE_PACK_SIGNING_KEY_PATH", "COMPLIANCE_PACK_PUBKEY_PATH")
    }
    with patch.dict(os.environ, env_without_keys, clear=True):
        _invoke(
            [
                "compliance",
                "export",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-abc",
                "--out",
                str(out_zip),
            ]
        )

    assert not out_zip.exists(), "ZIP was created despite missing signing keys"


# ---------------------------------------------------------------------------
# DB-backed happy-path tests (skipped when DATABASE_URL unset)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set — skipping DB-backed CLI evidence test",
)
def test_evidence_happy_path_db(tmp_path: Path) -> None:
    """compliance evidence with a live DB runs without error and prints DISCLAIMER."""
    from compliance.constants import DISCLAIMER

    rc, out, err = _invoke(
        [
            "compliance",
            "evidence",
            "--framework",
            "SOC2",
            "--t0",
            "2024-01-01T00:00:00Z",
            "--t1",
            "2024-02-01T00:00:00Z",
            "--tenant",
            "test-cli-tenant",
        ]
    )
    assert rc == 0, f"evidence returned non-zero: {err}"
    assert DISCLAIMER in out


# ---------------------------------------------------------------------------
# _parse_iso — invalid datetime string (lines 44-45 in cli.py)
# ---------------------------------------------------------------------------


def test_parse_iso_invalid_string_raises_argument_type_error() -> None:
    """_parse_iso raises argparse.ArgumentTypeError for a non-datetime string."""
    import argparse

    from compliance.cli import _parse_iso

    with pytest.raises(argparse.ArgumentTypeError, match="invalid ISO-8601 datetime"):
        _parse_iso("not-a-date", "--t0")


def test_parse_iso_empty_string_raises_argument_type_error() -> None:
    """_parse_iso raises argparse.ArgumentTypeError for an empty string."""
    import argparse

    from compliance.cli import _parse_iso

    with pytest.raises(argparse.ArgumentTypeError, match="invalid ISO-8601 datetime"):
        _parse_iso("", "--t1")


# ---------------------------------------------------------------------------
# _run_evidence ComplianceError branch (lines 151-153 in cli.py)
# ---------------------------------------------------------------------------


def test_evidence_compliance_error_exits_1(tmp_path: Path) -> None:
    """compliance evidence returns exit code 1 when generate_evidence raises ComplianceError."""
    from compliance.errors import ComplianceError

    with (
        patch("compliance.mapping.load_framework") as mock_load,
        patch(
            "compliance.evidence.generate_evidence",
            new_callable=AsyncMock,
            side_effect=ComplianceError("simulated mapping failure"),
        ),
    ):
        mock_load.return_value = MagicMock(framework="SOC2", framework_version="2017-TSC-rev2022")

        rc, _, err = _invoke(
            [
                "compliance",
                "evidence",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-abc",
            ]
        )

    assert rc == 1
    assert "error" in err.lower() or "simulated" in err.lower()


# ---------------------------------------------------------------------------
# dispatch unknown cmd fallback (lines 326-327 in cli.py)
# ---------------------------------------------------------------------------


def test_dispatch_unknown_cmd_returns_2() -> None:
    """dispatch() with an unrecognised cmd prints error and returns 2.

    The dispatch() function parses t0/t1 before the unknown-cmd branch, so
    the Namespace must carry valid ISO t0/t1 strings alongside the fake cmd.
    """
    import argparse
    import io
    import sys

    from compliance.cli import dispatch

    # Must supply t0/t1 because dispatch() parses them before the unknown-cmd guard.
    args = argparse.Namespace(
        cmd="nonexistent",
        t0="2025-01-01T00:00:00",
        t1="2025-02-01T00:00:00",
    )

    old_err = sys.stderr
    sys.stderr = io.StringIO()
    try:
        rc = dispatch(args)
        captured = sys.stderr.getvalue()
    finally:
        sys.stderr = old_err

    assert rc == 2
    assert "nonexistent" in captured or "unknown" in captured


# ---------------------------------------------------------------------------
# export happy-path (lines 200-225 in cli.py)
# ---------------------------------------------------------------------------


def test_export_happy_path_writes_zip_and_prints_hash(tmp_path: Path) -> None:
    """compliance export happy path: writes ZIP, prints content hash, exits 0."""
    from compliance.constants import DISCLAIMER
    from policy.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

    priv_key, pub_key = generate_keypair()
    priv_path = tmp_path / "signing.pem"
    pub_path = tmp_path / "pubkey.pem"
    priv_path.write_bytes(private_key_to_pem(priv_key))
    pub_path.write_bytes(public_key_to_pem(pub_key))

    out_zip = str(tmp_path / "pack.zip")

    gap_report = _make_fake_gap_report()

    import types

    from compliance.evidence import ChainTip, EvidenceProjection

    fake_projection = EvidenceProjection(
        framework="SOC2",
        framework_version="2017-TSC-rev2022",
        t0=gap_report.t0,
        t1=gap_report.t1,
        event_counts=types.MappingProxyType({}),
        total_events_in_window=0,
        chain_tip=ChainTip(sequence_number=1, row_hash="a" * 64),
    )

    with (
        patch.dict(
            os.environ,
            {
                "COMPLIANCE_PACK_SIGNING_KEY_PATH": str(priv_path),
                "COMPLIANCE_PACK_PUBKEY_PATH": str(pub_path),
            },
        ),
        patch("compliance.mapping.load_framework") as mock_load,
        patch("compliance.evidence.generate_evidence", new_callable=AsyncMock) as mock_gen,
        patch("compliance.evidence.read_chain_segment", new_callable=AsyncMock) as mock_chain,
        patch("compliance.gap_analysis.analyze_gaps", return_value=gap_report),
    ):
        mock_load.return_value = MagicMock(
            framework="SOC2",
            framework_version="2017-TSC-rev2022",
        )
        mock_gen.return_value = fake_projection
        mock_chain.return_value = ()

        rc, out, err = _invoke(
            [
                "compliance",
                "export",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-export-cli",
                "--out",
                out_zip,
            ]
        )

    assert rc == 0, f"export returned non-zero: rc={rc}\nstdout={out}\nstderr={err}"
    assert Path(out_zip).exists(), "ZIP was not written"
    assert Path(out_zip).read_bytes()[:2] == b"PK", "Output is not a valid ZIP"
    assert "Content hash" in out or "content hash" in out.lower()
    assert DISCLAIMER in out


def test_export_compliance_error_in_evidence_exits_1(tmp_path: Path) -> None:
    """compliance export returns exit 1 when generate_evidence raises ComplianceError.

    Drives lines 205-207 in _run_export: the except ComplianceError branch after
    load_framework/generate_evidence/read_chain_segment/analyze_gaps.
    """
    from compliance.errors import ComplianceError
    from policy.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

    priv_key, pub_key = generate_keypair()
    priv_path = tmp_path / "signing.pem"
    pub_path = tmp_path / "pubkey.pem"
    priv_path.write_bytes(private_key_to_pem(priv_key))
    pub_path.write_bytes(public_key_to_pem(pub_key))

    out_zip = str(tmp_path / "pack.zip")

    with (
        patch.dict(
            os.environ,
            {
                "COMPLIANCE_PACK_SIGNING_KEY_PATH": str(priv_path),
                "COMPLIANCE_PACK_PUBKEY_PATH": str(pub_path),
            },
        ),
        patch("compliance.mapping.load_framework") as mock_load,
        patch(
            "compliance.evidence.generate_evidence",
            new_callable=AsyncMock,
            side_effect=ComplianceError("framework DB query failed"),
        ),
    ):
        mock_load.return_value = MagicMock(
            framework="SOC2",
            framework_version="2017-TSC-rev2022",
        )

        rc, _, err = _invoke(
            [
                "compliance",
                "export",
                "--framework",
                "SOC2",
                "--t0",
                "2025-01-01T00:00:00",
                "--t1",
                "2025-02-01T00:00:00",
                "--tenant",
                "t-export-err",
                "--out",
                out_zip,
            ]
        )

    assert rc == 1, f"expected exit 1 on ComplianceError, got {rc}"
    assert "error" in err.lower() or "framework DB query failed" in err
    assert not Path(out_zip).exists(), "ZIP should not exist on ComplianceError"
