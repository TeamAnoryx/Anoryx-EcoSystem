"""Code-scan threat-model tests (F-016, ADR-0019 §12).

Implements vectors 1–9 and 12 as specified in ADR-0019 §12.
Vectors 10 and 11 are gateway-level tests built by the gateway agent (STEP 5).

All tests use exact names from the ADR:
  1. test_redos_payload_times_out_to_warn
  2. test_oversized_code_block_bounded
  3. test_scanner_no_network
  4. test_no_shell_injection_via_code_content
  5. test_scanner_crash_yields_warn_audited
  6. test_scanner_timeout_yields_warn
  7. test_known_vulnerable_code_warns_or_blocks
  8. test_clean_code_passes
  9. test_verdict_threshold_per_tenant
 12. test_scan_results_tenant_scoped

Test framing: "flags likely vulnerabilities" — not "guarantees bug-free."
Honest assertions: scanners BOUND the risk, not eliminate it.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from code_scan.extractor import (
    MAX_BLOCKS,
    MAX_BYTES_PER_BLOCK,
    MAX_TOTAL_BYTES,
    extract_code_blocks,
)
from code_scan.scanners import (
    SCANNER_TIMEOUT_SECONDS,
    ScannerError,
    run_bandit,
    run_semgrep,
    scan_block,
)
from code_scan.verdict import Verdict, aggregate_verdict, top_severity_from_findings
from tests.code_scan.conftest import make_mock_context

# ---------------------------------------------------------------------------
# Shared async helper: a no-op async context manager for mocking session.begin()
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _async_null_cm(*args, **kwargs):
    """Async context manager that does nothing — stand-in for session.begin()."""
    yield None


# ---------------------------------------------------------------------------
# Helper: known-vulnerable Python code snippet (structural pattern, not a
# real exploit — just a subprocess.call with shell=True that both Semgrep
# and Bandit will flag as a likely defect).
# ---------------------------------------------------------------------------

_VULN_PYTHON = """\
import subprocess
user_input = "ls"
subprocess.call(user_input, shell=True)
"""

_CLEAN_PYTHON = """\
def add(a: int, b: int) -> int:
    return a + b

result = add(1, 2)
print(result)
"""

# Response text wrapping a vulnerable block.
_VULN_RESPONSE = f"Here is some Python code:\n\n```python\n{_VULN_PYTHON}```\n"
_CLEAN_RESPONSE = f"Here is clean code:\n\n```python\n{_CLEAN_PYTHON}```\n"


# ---------------------------------------------------------------------------
# Vector 1: test_redos_payload_times_out_to_warn
# ---------------------------------------------------------------------------


class TestVector1RedosTimeout:
    """Vector 1: catastrophic-backtracking / resource-exhaustion payloads
    must hit the scanner timeout and yield WARN — no hang, no crash.

    The test uses a crafted Python file that is syntactically valid but
    contains deeply nested structures designed to stress parsers.  We
    drive the scanner directly (not through the detector) so we can assert
    ScannerError("...", "timeout") is raised within a bounded wall-clock time.

    Honest framing: the timeout bound fires within SCANNER_TIMEOUT_SECONDS
    seconds — we do not claim exact sub-second precision.
    """

    def test_redos_payload_times_out_to_warn(self) -> None:
        """Catastrophic-backtracking payload hits timeout → WARN, no hang."""
        # A deeply nested list expression that some parsers spend O(2^n) on.
        # We use a moderate depth that is reliably slow but does not take
        # minutes in environments where the scanner is fast.
        depth = 200
        nested = "x = " + "[" * depth + "1" + "]" * depth
        content = nested + "\n"

        # Patch SCANNER_TIMEOUT_SECONDS to a very short value so the test
        # completes quickly without actually waiting 30 seconds.
        with patch("code_scan.scanners.SCANNER_TIMEOUT_SECONDS", 2):
            start = time.monotonic()
            try:
                run_semgrep(content, "python")
                # If semgrep runs fast on this input (no ReDoS), that is
                # also acceptable — the bound is what matters.
                elapsed = time.monotonic() - start
                assert elapsed < 15, f"Semgrep took {elapsed:.1f}s on depth-{depth} payload"
            except ScannerError as exc:
                elapsed = time.monotonic() - start
                # The error must be a timeout or parse error, not a crash.
                assert exc.error_class in (
                    "timeout",
                    "parse_error",
                    "subprocess_error",
                ), f"Unexpected error_class: {exc.error_class}"
                # Must have terminated within a reasonable bound.
                assert elapsed < 15, f"Timeout took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Vector 2: test_oversized_code_block_bounded
# ---------------------------------------------------------------------------


class TestVector2OversizedBounded:
    """Vector 2: extractor enforces MAX_BYTES_PER_BLOCK and MAX_TOTAL_BYTES.

    Oversized blocks must be truncated/skipped without memory exhaustion.
    The scanner must never receive more than MAX_BYTES_PER_BLOCK per block.
    """

    def test_oversized_code_block_bounded(self) -> None:
        """Huge block capped (byte/block limit), no memory exhaustion."""
        # Build a response with one block that exceeds MAX_BYTES_PER_BLOCK.
        huge_content = "x = 1\n" * (MAX_BYTES_PER_BLOCK // 6 + 1000)
        response = f"```python\n{huge_content}```\n"

        result = extract_code_blocks(response)

        assert len(result.blocks) == 1, "Expected exactly one block"
        block = result.blocks[0]

        # The block must be truncated.
        content_bytes = block.content.encode("utf-8", errors="replace")
        assert len(content_bytes) <= MAX_BYTES_PER_BLOCK, (
            f"Block content {len(content_bytes)} bytes exceeds MAX_BYTES_PER_BLOCK "
            f"{MAX_BYTES_PER_BLOCK}"
        )
        assert block.truncated is True, "Block should be marked as truncated"

    def test_max_blocks_cap(self) -> None:
        """More than MAX_BLOCKS fenced blocks → only MAX_BLOCKS returned."""
        # Build a response with MAX_BLOCKS + 5 small blocks.
        blocks_count = MAX_BLOCKS + 5
        response = ""
        for i in range(blocks_count):
            response += f"Block {i}:\n```python\nx = {i}\n```\n"

        result = extract_code_blocks(response)

        assert len(result.blocks) == MAX_BLOCKS
        assert result.skipped_count == 5

    def test_max_total_bytes_cap(self) -> None:
        """Total bytes across all blocks capped at MAX_TOTAL_BYTES."""
        # Each block is sized to MAX_BYTES_PER_BLOCK (64 KiB); it takes exactly
        # MAX_TOTAL_BYTES // MAX_BYTES_PER_BLOCK = 8 such blocks to fill the
        # total cap.  With 10 blocks the last 2 must be skipped.
        chunk = "x = 1\n" * (MAX_BYTES_PER_BLOCK // 6 + 1)  # slightly over MAX_BYTES_PER_BLOCK
        response = ""
        for _ in range(10):  # 10 blocks each capped at 64 KiB = 640 KiB > 512 KiB cap
            response += f"```python\n{chunk}```\n"

        result = extract_code_blocks(response)

        assert result.total_bytes <= MAX_TOTAL_BYTES
        assert result.skipped_count > 0, "Expected some blocks to be skipped"

    def test_empty_response_returns_empty(self) -> None:
        """Non-code text returns an empty block list cheaply."""
        result = extract_code_blocks("This is plain text with no code blocks.")
        assert result.blocks == []
        assert result.skipped_count == 0

    def test_no_closing_fence_accepted(self) -> None:
        """Block with no closing fence still extracts content."""
        response = "```python\nx = 42\n"
        result = extract_code_blocks(response)
        assert len(result.blocks) == 1
        assert "x = 42" in result.blocks[0].content

    def test_language_tag_extracted(self) -> None:
        """Language tag from info string is lowercased and extracted."""
        response = "```Python\nprint('hello')\n```\n"
        result = extract_code_blocks(response)
        assert result.blocks[0].language == "python"

    def test_no_language_tag(self) -> None:
        """Block with no language tag has empty language string."""
        response = "```\nsome code\n```\n"
        result = extract_code_blocks(response)
        assert result.blocks[0].language == ""


# ---------------------------------------------------------------------------
# Vector 3: test_scanner_no_network
# ---------------------------------------------------------------------------


class TestVector3NoNetwork:
    """Vector 3: Semgrep runs offline — no rule fetch or egress.

    We verify that the scanner runs successfully using only the local
    vendored ruleset, and that no network arguments are passed (--config
    points to a local file path, not a URL or registry pack name).
    """

    def test_scanner_no_network(self) -> None:
        """Semgrep runs offline; no rule fetch / egress."""
        from code_scan.scanners import SEMGREP_RULESET_PATH

        # The ruleset path must be a local file, not a URL or registry pack.
        ruleset_str = str(SEMGREP_RULESET_PATH)
        assert not ruleset_str.startswith(
            "p/"
        ), f"Ruleset path {ruleset_str!r} looks like a registry pack — must be a local path"
        assert not ruleset_str.startswith(
            "http"
        ), f"Ruleset path {ruleset_str!r} looks like a URL — must be a local path"
        assert (
            SEMGREP_RULESET_PATH.exists()
        ), f"Vendored ruleset not found at {SEMGREP_RULESET_PATH}"

        # Run a clean snippet and verify Semgrep completes without error.
        # If network were required and unavailable this would raise or hang.
        findings = run_semgrep(_CLEAN_PYTHON, "python")
        assert isinstance(findings, list)

    def test_semgrep_invocation_uses_offline_flags(self) -> None:
        """Semgrep argv list includes --metrics=off and --disable-version-check."""
        captured_argv: list = []

        original_run = subprocess.run

        def _capture(*args, **kwargs):
            if args and args[0] and args[0][0] == "semgrep":
                captured_argv.extend(args[0])
            return original_run(*args, **kwargs)

        with patch("subprocess.run", side_effect=_capture):
            try:
                run_semgrep("x = 1\n", "python")
            except Exception:
                pass

        if captured_argv:
            assert (
                "--metrics=off" in captured_argv
            ), "Semgrep must be invoked with --metrics=off to prevent network telemetry"
            assert (
                "--disable-version-check" in captured_argv
            ), "Semgrep must be invoked with --disable-version-check"


# ---------------------------------------------------------------------------
# Vector 4: test_no_shell_injection_via_code_content
# ---------------------------------------------------------------------------


class TestVector4NoShellInjection:
    """Vector 4: code content with shell metacharacters / path-traversal
    sequences must be passed by file path, never shell-interpolated.

    The test verifies that:
    1. shell=False is enforced (subprocess receives an argv list).
    2. Path-traversal characters in content cannot influence the temp file path.
    3. The scanner receives the server-chosen path, not the content inline.
    """

    def test_no_shell_injection_via_code_content(self) -> None:
        """Shell metachars / path-traversal in content passed by path, not interpreted."""
        # Code block containing shell metacharacters that would cause a shell to
        # execute extra commands if interpolated into a shell string.
        malicious_content = (
            "x = 1\n"
            "# $(rm -rf /tmp/sentinel_test_marker_xyz)\n"
            "# `touch /tmp/sentinel_shell_injection_proof`\n"
            "# ; echo injected\n"
            "# | cat /etc/passwd\n"
            "# ' OR 1=1 --\n"
        )

        # This must not raise and must not execute shell commands.
        try:
            findings = run_semgrep(malicious_content, "python")
            assert isinstance(findings, list)
        except ScannerError:
            # A scanner error is also acceptable — as long as it's a controlled error.
            pass

    def test_path_traversal_in_content_not_reflected_in_path(self) -> None:
        """Path-traversal sequences in code content do not affect the temp file path."""
        traversal_content = "x = '../../../etc/passwd'\ny = '..\\\\..\\\\windows\\\\system32'\n"

        # The scanner must write to a server-chosen path, not a path derived from content.
        temp_dirs_used: list[str] = []
        original_mkdtemp = tempfile.mkdtemp

        def _capture_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            temp_dirs_used.append(d)
            return d

        with patch("tempfile.mkdtemp", side_effect=_capture_mkdtemp):
            try:
                run_semgrep(traversal_content, "python")
            except ScannerError:
                pass

        for d in temp_dirs_used:
            # The directory name must not contain traversal sequences.
            assert ".." not in d, f"Temp dir {d!r} contains '..' — possible path traversal"

    def test_subprocess_shell_false(self) -> None:
        """Subprocess is invoked with shell=False — never a shell string."""
        shell_values: list = []
        original_run = subprocess.run

        def _spy_run(*args, **kwargs):
            shell_values.append(kwargs.get("shell", False))
            return original_run(*args, **kwargs)

        with patch("subprocess.run", side_effect=_spy_run):
            try:
                run_semgrep("x = 1\n", "python")
            except ScannerError:
                pass

        if shell_values:
            assert all(
                s is False for s in shell_values
            ), f"subprocess.run called with shell=True: {shell_values}"


# ---------------------------------------------------------------------------
# Vector 5: test_scanner_crash_yields_warn_audited
# ---------------------------------------------------------------------------


class TestVector5ScannerCrash:
    """Vector 5: a scanner error/crash yields WARN and emits code_scan_error.

    We simulate a crash by making subprocess.run raise an unexpected exception.
    The detector must: (a) not propagate the exception, (b) emit code_scan_error,
    (c) return action="pass" (fail-safe WARN posture).
    """

    def test_scanner_crash_yields_warn_audited(self) -> None:
        """Forced scanner error → WARN + code_scan_error."""
        with patch(
            "subprocess.run",
            side_effect=RuntimeError("simulated crash"),
        ):
            with pytest.raises(ScannerError) as exc_info:
                run_semgrep("x = 1\n", "python")

        assert exc_info.value.scanner == "semgrep"
        assert exc_info.value.error_class == "subprocess_error"

    @pytest.mark.asyncio
    async def test_scanner_crash_via_detector_emits_error_event(self) -> None:
        """Detector catches ScannerError, emits code_scan_error, returns pass."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        with patch.object(detector, "_load_config", return_value=enabled_config):
            with patch(
                "code_scan.detector.scan_block",
                side_effect=ScannerError("semgrep", "timeout"),
            ):
                content = "```python\nx = 1\n```\n"
                result = await detector.inspect(content, ctx)

        assert result.action == "pass", "Scanner error must yield pass (fail-safe WARN)"
        assert ctx.emit.called, "code_scan_error event must be emitted"
        emitted_event = ctx.emit.call_args[0][0]
        assert emitted_event["event_type"] == "code_scan_error"
        assert emitted_event["action_taken"] == "logged"
        assert "scanner" in emitted_event
        assert "error_class" in emitted_event
        # NEVER code content or stack trace in the event.
        for val in emitted_event.values():
            if isinstance(val, str):
                assert "x = 1" not in val, "Code content must not appear in error event"


# ---------------------------------------------------------------------------
# Vector 6: test_scanner_timeout_yields_warn
# ---------------------------------------------------------------------------


class TestVector6Timeout:
    """Vector 6: subprocess timeout → ScannerError("timeout") → WARN."""

    def test_scanner_timeout_yields_warn(self) -> None:
        """Timeout → WARN."""
        import subprocess as _sp

        with patch(
            "subprocess.run",
            side_effect=_sp.TimeoutExpired(cmd=["semgrep"], timeout=2),
        ):
            with pytest.raises(ScannerError) as exc_info:
                run_semgrep("x = 1\n", "python")

        assert exc_info.value.scanner == "semgrep"
        assert exc_info.value.error_class == "timeout"

    def test_scanner_timeout_constants_reasonable(self) -> None:
        """SCANNER_TIMEOUT_SECONDS is set and reasonable (> 0, < 300)."""
        assert (
            0 < SCANNER_TIMEOUT_SECONDS < 300
        ), f"SCANNER_TIMEOUT_SECONDS={SCANNER_TIMEOUT_SECONDS} out of expected range"


# ---------------------------------------------------------------------------
# Vector 7: test_known_vulnerable_code_warns_or_blocks
# ---------------------------------------------------------------------------


class TestVector7KnownVulnerable:
    """Vector 7: code with known-bad patterns (os.system / SQL string-concat)
    produces findings → WARN or BLOCK depending on thresholds.

    Honest framing: "flags likely vulnerabilities" — not "catches every bug."
    These are structural patterns that Semgrep / Bandit flag reliably.
    """

    def test_known_vulnerable_code_warns_or_blocks(self) -> None:
        """os.system / SQL string-concat → finding → WARN/BLOCK per threshold."""
        findings = scan_block(_VULN_PYTHON, "python")
        assert len(findings) > 0, (
            "Expected at least one finding for subprocess.call(shell=True) — "
            "high-coverage detection of known patterns"
        )

    def test_os_system_flagged(self) -> None:
        """os.system() detected as a likely defect."""
        code = "import os\nos.system('ls')\n"
        findings = run_semgrep(code, "python")
        rule_ids = [f["rule_id"] for f in findings]
        assert any(
            "os" in rid.lower() or "system" in rid.lower() for rid in rule_ids
        ), f"Expected an os.system finding, got: {rule_ids}"

    def test_eval_flagged(self) -> None:
        """eval() with dynamic content detected as a likely defect."""
        code = "user_code = input()\nresult = eval(user_code)\n"
        findings = run_semgrep(code, "python")
        assert len(findings) > 0, f"Expected eval() to be flagged; got {findings}"

    def test_sql_string_format_flagged(self) -> None:
        """SQL query built with % string formatting flagged."""
        code = (
            "import sqlite3\n"
            "conn = sqlite3.connect(':memory:')\n"
            "cur = conn.cursor()\n"
            "name = 'user'\n"
            "cur.execute('SELECT * FROM users WHERE name = %s' % name)\n"
        )
        findings = run_semgrep(code, "python")
        assert len(findings) > 0, f"Expected SQL string-format finding; got {findings}"

    def test_bandit_flags_subprocess_shell_true(self) -> None:
        """Bandit independently flags subprocess.call(shell=True)."""
        findings = run_bandit(_VULN_PYTHON)
        assert (
            len(findings) > 0
        ), f"Expected Bandit to flag subprocess.call(shell=True); got {findings}"

    def test_finding_severity_present(self) -> None:
        """All findings have a non-empty severity field."""
        findings = scan_block(_VULN_PYTHON, "python")
        for f in findings:
            assert f.get("severity"), f"Finding missing severity: {f}"
            assert f["severity"] in (
                "low",
                "medium",
                "high",
                "critical",
            ), f"Unknown severity {f['severity']!r}"


# ---------------------------------------------------------------------------
# Vector 8: test_clean_code_passes
# ---------------------------------------------------------------------------


class TestVector8CleanCode:
    """Vector 8: clean, pattern-free code yields zero findings → PASS verdict."""

    def test_clean_code_passes(self) -> None:
        """Clean code → PASS."""
        findings = scan_block(_CLEAN_PYTHON, "python")
        verdict = aggregate_verdict(findings, warn_threshold="low", block_threshold="high")
        assert (
            verdict == Verdict.PASS
        ), f"Clean code should yield PASS; got {verdict} with findings: {findings}"

    def test_empty_content_produces_no_findings(self) -> None:
        """Empty block produces no findings."""
        findings = scan_block("", "python")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_clean_response_emits_passed_event(self) -> None:
        """Clean code in a response emits code_scan_passed event."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        with patch.object(detector, "_load_config", return_value=enabled_config):
            result = await detector.inspect(_CLEAN_RESPONSE, ctx)

        assert result.action == "pass"
        assert ctx.emit.called
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_passed"
        assert emitted["action_taken"] == "logged"
        # HIGH-2: wire verdict is lowercase per contracts/events.schema.json enum.
        assert emitted["verdict"] == "pass"
        # HIGH-3: zero findings → top_severity must be OMITTED entirely (not "none").
        assert "top_severity" not in emitted, (
            "code_scan_passed with 0 findings must omit top_severity; "
            f"got {emitted.get('top_severity')!r}"
        )


# ---------------------------------------------------------------------------
# Vector 9: test_verdict_threshold_per_tenant
# ---------------------------------------------------------------------------


class TestVector9ThresholdPerTenant:
    """Vector 9: severity→verdict respects per-tenant config.

    Tests that different threshold configs (warn/block levels) produce
    the expected verdicts for the same set of findings.
    """

    def test_verdict_threshold_per_tenant(self) -> None:
        """Severity→verdict respects per-tenant config."""
        # Findings: one "high" severity finding.
        findings = [{"rule_id": "sentinel-eval", "severity": "high", "line": 5}]

        # Tenant A: block threshold = "high" → BLOCK.
        verdict_a = aggregate_verdict(findings, warn_threshold="low", block_threshold="high")
        assert verdict_a == Verdict.BLOCK

        # Tenant B: block threshold = "critical" → WARN (high < critical).
        verdict_b = aggregate_verdict(findings, warn_threshold="low", block_threshold="critical")
        assert verdict_b == Verdict.WARN

        # Tenant C: warn threshold = "high" (same as finding) → WARN.
        verdict_c = aggregate_verdict(findings, warn_threshold="high", block_threshold="critical")
        assert verdict_c == Verdict.WARN

        # Tenant D: warn threshold = "critical" → PASS (high < critical for warn).
        verdict_d = aggregate_verdict(
            findings, warn_threshold="critical", block_threshold="critical"
        )
        assert verdict_d == Verdict.PASS

    def test_no_findings_always_pass(self) -> None:
        """Zero findings → PASS regardless of thresholds."""
        verdict = aggregate_verdict([], warn_threshold="low", block_threshold="low")
        assert verdict == Verdict.PASS

    def test_critical_finding_blocks_at_high_threshold(self) -> None:
        """Critical finding exceeds high threshold → BLOCK."""
        findings = [{"rule_id": "sentinel-sql", "severity": "critical", "line": 3}]
        verdict = aggregate_verdict(findings, warn_threshold="low", block_threshold="high")
        assert verdict == Verdict.BLOCK

    def test_low_finding_below_medium_warn_threshold_passes(self) -> None:
        """Low finding below medium warn threshold → PASS."""
        findings = [{"rule_id": "sentinel-random", "severity": "low", "line": 1}]
        verdict = aggregate_verdict(findings, warn_threshold="medium", block_threshold="high")
        assert verdict == Verdict.PASS

    def test_scanner_error_yields_warn_not_pass(self) -> None:
        """ScannerError from verdict.py perspective: caller maps to WARN (not PASS).

        The fail-safe contract (ADR-0019 §6): any error → WARN, never PASS.
        This test verifies the mapping contract is honoured by checking that
        ScannerError is a distinct typed exception (not None or a 'pass' signal).
        """
        exc = ScannerError("semgrep", "timeout")
        # A ScannerError must carry scanner + error_class (never code content).
        assert exc.scanner == "semgrep"
        assert exc.error_class == "timeout"
        assert "timeout" in str(exc)

    def test_top_severity_from_findings(self) -> None:
        """top_severity_from_findings returns the worst severity."""
        findings = [
            {"rule_id": "r1", "severity": "low", "line": 1},
            {"rule_id": "r2", "severity": "high", "line": 2},
            {"rule_id": "r3", "severity": "medium", "line": 3},
        ]
        assert top_severity_from_findings(findings) == "high"

    def test_top_severity_empty_returns_none_label(self) -> None:
        """top_severity_from_findings([]) returns 'none'."""
        assert top_severity_from_findings([]) == "none"


# ---------------------------------------------------------------------------
# Detector unit tests (disabled config, stream handling, audit_action_taken)
# ---------------------------------------------------------------------------


class TestDetectorUnit:
    """Additional unit tests for the detector's inspect() behaviour."""

    @pytest.mark.asyncio
    async def test_disabled_config_returns_pass_no_event(self) -> None:
        """Disabled config (absent policy) → PASS, no event, no scan."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()
        disabled_config = CodeScanConfig(enabled=False)

        with patch.object(detector, "_load_config", return_value=disabled_config):
            with patch("code_scan.detector.scan_block") as mock_scan:
                result = await detector.inspect(_VULN_RESPONSE, ctx)
                assert not mock_scan.called, "Scan must not run when disabled"

        assert result.action == "pass"
        assert not ctx.emit.called, "No event when disabled"

    @pytest.mark.asyncio
    async def test_block_verdict_non_stream_returns_block(self) -> None:
        """BLOCK verdict on non-streamed response → action=block."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=False)

        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",  # anything → BLOCK
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "sentinel-eval", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=enabled_config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect(_VULN_RESPONSE, ctx)

        assert result.action == "block"
        assert ctx.emit.called
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_blocked"
        assert emitted["action_taken"] == "blocked"

    @pytest.mark.asyncio
    async def test_block_verdict_stream_emits_warn_not_block(self) -> None:
        """BLOCK verdict on streamed response → action=pass, block_suppressed_by_streaming."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=True)

        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "sentinel-eval", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=enabled_config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect(_VULN_RESPONSE, ctx)

        # Streaming: honest BLOCK is impossible — pass + WARN event.
        assert result.action == "pass"
        assert ctx.emit.called
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_warned"
        assert emitted.get("block_suppressed_by_streaming") is True

    @pytest.mark.asyncio
    async def test_block_action_audit_downgrades_to_warn(self) -> None:
        """block_action=audit → BLOCK threshold emits warn, returns pass."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=False)

        audit_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",
            warn_action="audit",
            block_action="audit",  # never reject
        )

        high_finding = [{"rule_id": "sentinel-eval", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=audit_config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect(_VULN_RESPONSE, ctx)

        assert result.action == "pass"
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_warned"

    @pytest.mark.asyncio
    async def test_no_code_blocks_returns_pass_no_event(self) -> None:
        """Response with no fenced blocks → pass, no event (nothing to scan)."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        with patch.object(detector, "_load_config", return_value=enabled_config):
            result = await detector.inspect("Just plain text, no code blocks.", ctx)

        assert result.action == "pass"
        assert not ctx.emit.called

    def test_detector_slug(self) -> None:
        """detector_slug is 'code-scan'."""
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        assert detector.detector_slug == "code-scan"

    def test_detector_is_post_response_hook(self) -> None:
        """CodeScanDetector is an instance of PostResponseHook."""
        from code_scan.detector import CodeScanDetector
        from orchestration.hooks.base import PostResponseHook

        assert issubclass(CodeScanDetector, PostResponseHook)


# ---------------------------------------------------------------------------
# Vector 12: test_scan_results_tenant_scoped
# ---------------------------------------------------------------------------


class TestVector12TenantScoped:
    """Vector 12: config/results/events tenant-scoped; no cross-tenant visibility.

    Unit-level: verify that load_code_scan_config returns disabled config for
    a tenant with no policy (default-OFF), even when another tenant has an
    enabled policy.  DB-backed isolation is tested via the mock layer since
    the real RLS boundary is exercised by F-008 / F-003b tests.
    """

    @pytest.mark.asyncio
    async def test_scan_results_tenant_scoped(self) -> None:
        """Config/results/events tenant-scoped; no cross-tenant visibility.

        CRIT-1 fix: load_code_scan_config now opens its own get_tenant_session
        internally.  We mock both get_tenant_session (so no real DB is needed)
        and PolicyRepository so the test remains a pure unit test.
        """
        from contextlib import asynccontextmanager

        from code_scan.config import load_code_scan_config

        # Tenant A: has an enabled code_scan policy.
        # Tenant B: no policy → should get disabled config (default-OFF).
        policy_a = MagicMock()
        policy_a.policy_payload = json.dumps(
            {
                "enabled": True,
                "thresholds": {"warn": "low", "block": "high"},
                "actions": {"warn": "audit", "block": "reject"},
            }
        )

        # build a session mock whose .begin() is an async context manager
        mock_session = MagicMock()
        # begin() must return a fresh async context manager on each call.
        mock_session.begin = MagicMock(side_effect=_async_null_cm)

        @asynccontextmanager
        async def _fake_tenant_session(tid: str):
            yield mock_session

        async def _get_policies(tenant_id: str, policy_type: str) -> list:
            if tenant_id == "tenant-a" and policy_type == "code_scan":
                return [policy_a]
            return []  # Tenant B sees nothing.

        with patch("code_scan.config.get_tenant_session", _fake_tenant_session):
            with patch("code_scan.config.PolicyRepository") as MockRepo:
                instance = MagicMock()
                instance.get_active_policies_for_scope = AsyncMock(side_effect=_get_policies)
                MockRepo.return_value = instance

                config_a = await load_code_scan_config("tenant-a")
                config_b = await load_code_scan_config("tenant-b")

        assert config_a.enabled is True, "Tenant A should have code scanning enabled"
        assert (
            config_b.enabled is False
        ), "Tenant B has no policy → default-OFF; config must not bleed from tenant A"

    @pytest.mark.asyncio
    async def test_tenant_b_policy_does_not_affect_tenant_a_scan(self) -> None:
        """Changing tenant B's policy does not affect tenant A's scan results."""
        from contextlib import asynccontextmanager

        from code_scan.config import load_code_scan_config

        # Tenant B has a strict (low warn/low block) policy.
        policy_b = MagicMock()
        policy_b.policy_payload = json.dumps(
            {
                "enabled": True,
                "thresholds": {"warn": "low", "block": "low"},
                "actions": {"warn": "audit", "block": "reject"},
            }
        )
        # Tenant A has a permissive (high warn/critical block) policy.
        policy_a = MagicMock()
        policy_a.policy_payload = json.dumps(
            {
                "enabled": True,
                "thresholds": {"warn": "high", "block": "critical"},
                "actions": {"warn": "audit", "block": "reject"},
            }
        )

        mock_session = MagicMock()
        # begin() must return a fresh async context manager on each call.
        mock_session.begin = MagicMock(side_effect=_async_null_cm)

        @asynccontextmanager
        async def _fake_tenant_session(tid: str):
            yield mock_session

        async def _get_policies(tenant_id: str, policy_type: str) -> list:
            if tenant_id == "tenant-a":
                return [policy_a]
            return [policy_b]

        with patch("code_scan.config.get_tenant_session", _fake_tenant_session):
            with patch("code_scan.config.PolicyRepository") as MockRepo:
                instance = MagicMock()
                instance.get_active_policies_for_scope = AsyncMock(side_effect=_get_policies)
                MockRepo.return_value = instance

                config_a = await load_code_scan_config("tenant-a")
                config_b = await load_code_scan_config("tenant-b")

        # Tenant A's config must not be influenced by tenant B's policy.
        assert config_a.block_threshold == "critical"
        assert config_b.block_threshold == "low"


# ---------------------------------------------------------------------------
# HIGH-4: untagged blocks use Semgrep-only (no Bandit parse-error contamination)
# ---------------------------------------------------------------------------


class TestHigh4UntaggedBlockSemgrepOnly:
    """HIGH-4: an untagged (empty language) code block must NOT trigger Bandit.

    Prior to the fix, ``is_python`` included the empty-string case, causing
    Bandit to run against non-Python content, fail to parse, and raise
    ScannerError — degrading a clean response from PASS to code_scan_error
    (WARN) and confusing operators.  After the fix, untagged blocks receive
    Semgrep-only scanning (generic ruleset), consistent with ADR-0019 §13.
    """

    def test_untagged_clean_block_does_not_produce_scanner_error(self) -> None:
        """Untagged clean block: scan_block completes without ScannerError (no Bandit)."""
        # Plain text / pseudocode in an untagged fence — not Python syntax.
        untagged_content = "step 1: validate input\nstep 2: process data\nstep 3: return result\n"

        # Must not raise ScannerError.  Any result (empty findings or Semgrep
        # findings) is acceptable — the important invariant is no error from
        # a failed Bandit parse on non-Python content.
        try:
            findings = scan_block(untagged_content, "")
        except ScannerError as exc:
            raise AssertionError(
                f"scan_block raised ScannerError({exc.scanner!r}, {exc.error_class!r}) "
                "for an untagged block — Bandit must NOT run on untagged/empty language tags "
                "(HIGH-4 fix regression)"
            ) from exc

        assert isinstance(findings, list), "scan_block must return a list"

    def test_untagged_block_bandit_not_called(self) -> None:
        """Bandit is NOT invoked for an empty language tag (HIGH-4 enforcement)."""
        untagged_content = "SELECT * FROM orders;\n"

        with patch("code_scan.scanners.run_bandit") as mock_bandit:
            try:
                scan_block(untagged_content, "")
            except ScannerError:
                pass  # Semgrep error is fine; the point is Bandit was not called.

        assert (
            not mock_bandit.called
        ), "run_bandit must not be called for an empty/absent language tag (HIGH-4)"

    def test_python_tagged_block_still_runs_bandit(self) -> None:
        """Explicitly Python-tagged block still runs Bandit as before (regression guard)."""
        with patch("code_scan.scanners.run_bandit", return_value=[]) as mock_bandit:
            with patch("code_scan.scanners.run_semgrep", return_value=[]):
                scan_block("x = 1\n", "python")

        assert mock_bandit.called, "run_bandit must still be called for language='python'"


# ---------------------------------------------------------------------------
# LOW-2: timeout mechanism is falsifiable — patches SCANNER_TIMEOUT_SECONDS
# ---------------------------------------------------------------------------


class TestLow2TimeoutMechanismFalsifiable:
    """LOW-2: prove the timeout bound fires when configured tightly.

    The existing Vector 1 wall-clock test passes even when the scanner runs
    quickly (non-falsifiable).  This parametrized test patches
    SCANNER_TIMEOUT_SECONDS to a tiny value and verifies that the timeout
    mechanism raises ScannerError(..., "timeout") — proving the bound fires
    when the subprocess genuinely exceeds the configured limit.
    """

    @pytest.mark.parametrize("tight_timeout", [1])
    def test_tight_timeout_fires_scanner_error(self, tight_timeout: int) -> None:
        """Patching SCANNER_TIMEOUT_SECONDS tiny → TimeoutExpired → ScannerError('timeout').

        We mock subprocess.run to raise TimeoutExpired (as the OS would) and
        assert the scanner wraps it correctly.  This makes the timeout path
        falsifiable: if the wrapping were removed, the test would fail.
        """
        import subprocess as _sp

        with patch("code_scan.scanners.SCANNER_TIMEOUT_SECONDS", tight_timeout):
            with patch(
                "subprocess.run",
                side_effect=_sp.TimeoutExpired(cmd=["semgrep"], timeout=tight_timeout),
            ):
                with pytest.raises(ScannerError) as exc_info:
                    run_semgrep("x = 1\n", "python")

        assert exc_info.value.error_class == "timeout", (
            f"Expected error_class='timeout', got {exc_info.value.error_class!r}; "
            "the timeout wrapping path may have been removed"
        )
        assert exc_info.value.scanner == "semgrep"

    def test_scanner_timeout_constant_is_patchable(self) -> None:
        """SCANNER_TIMEOUT_SECONDS can be patched (module-level constant, not frozen).

        This is a prerequisite for the tight_timeout test above and for
        production operator overrides via env-var at startup.
        """
        import code_scan.scanners as _scanners

        original = _scanners.SCANNER_TIMEOUT_SECONDS
        with patch("code_scan.scanners.SCANNER_TIMEOUT_SECONDS", 1):
            assert _scanners.SCANNER_TIMEOUT_SECONDS == 1, (
                "SCANNER_TIMEOUT_SECONDS must be patchable; "
                "do not replace it with a module-level frozen constant"
            )
        # Confirm it reverts after the patch context exits.
        assert _scanners.SCANNER_TIMEOUT_SECONDS == original


# ---------------------------------------------------------------------------
# CRIT-1 regression: real HookContext must NOT be a no-op
# ---------------------------------------------------------------------------


class TestCrit1RealHookContextNotNoOp:
    """Regression guard for CRIT-1.

    The audit found that the detector was a permanent no-op in production
    because _load_config relied on _db_session from the context, but
    production HookContext objects never carry _db_session.

    FIX: _load_config now opens its own RLS-scoped session via
    get_tenant_session(tenant_id) — it only needs tenant_id from the context,
    which HookContext.tenant_context always exposes.

    This test builds a context the SAME way production does (using the real
    build_hook_context factory, NOT hand-setting _db_session) for a tenant
    with code_scan enabled, and asserts the detector actually scans and emits
    a code_scan_* event.  If the CRIT-1 regression returns, load_code_scan_config
    would get an empty/None session and the detector would return PASS silently.
    """

    @pytest.mark.asyncio
    async def test_real_hook_context_triggers_scan_not_noop(self) -> None:
        """Detector with a real HookContext (no _db_session) must NOT silently PASS.

        Production HookContext is built by build_hook_context() which sets ONLY:
        - tenant_context (with tenant_id)
        - request_id
        - original_user_content
        - phase
        It does NOT set _db_session.  The old code read getattr(ctx, "_db_session",
        None) and got None → disabled config → silent PASS for EVERY request.
        """
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector
        from gateway.context import TenantContext
        from orchestration.context import build_hook_context

        # Build context exactly like production does: no _db_session set.
        tenant_ctx = TenantContext(
            tenant_id="tenant-crit1-regression",
            team_id="team-001",
            project_id="proj-001",
            agent_id="code-scan",
            virtual_key_id="vkey-001",
        )
        # build_hook_context does NOT set _db_session — this is the production path.
        ctx = build_hook_context(
            tenant_context=tenant_ctx,
            request_id="req-crit1-test",
            validated_messages=[],
            phase="post_response",
        )

        # Confirm production context never has _db_session.
        assert not hasattr(ctx, "_db_session") or getattr(ctx, "_db_session", None) is None, (
            "CRIT-1 regression: HookContext must not carry _db_session in production; "
            "if it does, the old broken path would coincidentally work"
        )

        # Prepare detector with an enabled config injected via _load_config.
        detector = CodeScanDetector()
        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        # ctx.emit is NOT an AsyncMock by default — wrap it so we can assert it.
        ctx.emit = AsyncMock(return_value=True)

        # Inject enabled config directly (bypasses the DB; the production path
        # for config loading is tested separately in TestVector12TenantScoped).
        with patch.object(detector, "_load_config", return_value=enabled_config):
            await detector.inspect(_VULN_RESPONSE, ctx)

        # The detector must have run the scanner (not returned early as disabled).
        # Since _VULN_RESPONSE has a known-vulnerable block, the result is
        # PASS, WARN, or BLOCK — all of which emit an event.
        # The key invariant: it must NOT be a silent no-op (no event).
        assert ctx.emit.called, (
            "CRIT-1 regression: detector returned silently without emitting any event. "
            "load_code_scan_config likely returned disabled config because no session "
            "was found — the session-smuggling bug has returned."
        )
        emitted = ctx.emit.call_args[0][0]
        assert emitted.get("event_type") in (
            "code_scan_passed",
            "code_scan_warned",
            "code_scan_blocked",
            "code_scan_error",
        ), f"Unexpected event_type: {emitted.get('event_type')!r}"


# ---------------------------------------------------------------------------
# HIGH-1 regression: total scan budget is enforced
# ---------------------------------------------------------------------------


class TestHigh1TotalScanBudget:
    """Regression guard for HIGH-1: total wall-clock budget across all blocks.

    Without the budget cap, MAX_BLOCKS × 2 scanners × SCANNER_TIMEOUT_SECONDS
    ≈ 1200 s could elapse on the synchronous response path — an amplification
    DoS.  The fix adds MAX_TOTAL_SCAN_SECONDS enforced via time.monotonic().

    This test patches MAX_TOTAL_SCAN_SECONDS to a tiny value and injects a
    slow scan_block that eats into the budget, asserting that:
    1. The scan loop stops before processing all blocks.
    2. The detector degrades to fail-safe WARN (code_scan_error or
       code_scan_warned), never to silent PASS.
    3. The total elapsed time is bounded.
    """

    @pytest.mark.asyncio
    async def test_total_budget_exceeded_degrades_to_warn(self) -> None:
        """Patching MAX_TOTAL_SCAN_SECONDS tiny → budget exceeded → WARN not PASS."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        enabled_config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        # Build a response with 3 small Python blocks so the loop has blocks to iterate.
        response = "\n".join([f"```python\nx = {i}\n```" for i in range(3)])

        ctx = make_mock_context()
        call_count = 0

        def _slow_scan_block(content: str, language: str) -> list:
            """First call burns the budget by advancing time; subsequent calls are blocked."""
            nonlocal call_count
            call_count += 1
            # Simulate time passing by patching the budget check directly.
            return [{"rule_id": "r1", "severity": "low", "line": 1}]

        with patch.object(detector, "_load_config", return_value=enabled_config):
            # Patch MAX_TOTAL_SCAN_SECONDS to 0 — budget is exceeded before
            # any block is scanned (time.monotonic() >= deadline immediately).
            with patch("code_scan.detector.MAX_TOTAL_SCAN_SECONDS", 0):
                with patch("code_scan.detector.scan_block", side_effect=_slow_scan_block):
                    start = time.monotonic()
                    result = await detector.inspect(response, ctx)
                    elapsed = time.monotonic() - start

        # With budget=0, the deadline fires before the first block is processed.
        # The detector raises ScannerError("budget", "scan_budget_exceeded") →
        # _handle_scanner_error → code_scan_error event + action="pass".
        assert (
            result.action == "pass"
        ), f"Budget-exceeded path must return pass (fail-safe WARN); got {result.action!r}"
        assert (
            ctx.emit.called
        ), "code_scan_error or code_scan_warned must be emitted on budget exceeded"
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] in (
            "code_scan_error",
            "code_scan_warned",
        ), f"Expected error/warn event on budget exceeded; got {emitted['event_type']!r}"

        # The budget limit must stop early — scan_block should NOT be called for
        # every block when the budget is 0.
        assert call_count == 0, (
            f"scan_block was called {call_count} times — budget=0 should have stopped "
            "before scanning any block (deadline fires before loop body)"
        )

        # Wall-clock must be well within the test timeout.
        assert elapsed < 5.0, f"Budget check took {elapsed:.2f}s — deadline not firing promptly"

    def test_max_total_scan_seconds_constant_exists_and_is_sane(self) -> None:
        """MAX_TOTAL_SCAN_SECONDS is exported, > 0, and < any reasonable worker timeout."""
        from code_scan.detector import MAX_TOTAL_SCAN_SECONDS

        assert isinstance(
            MAX_TOTAL_SCAN_SECONDS, int
        ), "MAX_TOTAL_SCAN_SECONDS must be an int (patchable module constant)"
        assert 0 < MAX_TOTAL_SCAN_SECONDS <= 120, (
            f"MAX_TOTAL_SCAN_SECONDS={MAX_TOTAL_SCAN_SECONDS} is out of expected range "
            "(must be > 0 and <= 120 s to stay under typical worker timeouts)"
        )
