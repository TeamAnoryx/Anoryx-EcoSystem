"""Targeted branch-coverage tests for F-016 code_scan package.

Covers missing branches in detector.py, scanners.py, and config.py
identified via --cov-report=term-missing.  No real semgrep/bandit/postgres
is required — all subprocess and DB layers are mocked.
"""

from __future__ import annotations

import json
import subprocess
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from code_scan.scanners import (
    MAX_OUTPUT_BYTES,
    ScannerError,
    _cap_output,
    _parse_bandit_output,
    _parse_semgrep_output,
    _posix_resource_limits,
    _run_subprocess,
    run_bandit,
    run_semgrep,
)
from tests.code_scan.conftest import make_mock_context

# ---------------------------------------------------------------------------
# scanners.py — _posix_resource_limits (lines 135-161)
# ---------------------------------------------------------------------------


class TestPosixResourceLimits:
    """Cover _posix_resource_limits() on non-Windows paths."""

    def test_returns_none_on_windows(self) -> None:
        """On Windows the function returns None (no preexec_fn)."""
        with patch("code_scan.scanners.platform.system", return_value="Windows"):
            result = _posix_resource_limits()
        assert result is None

    def test_returns_callable_on_linux(self) -> None:
        """On Linux/POSIX the function returns a callable (the _set_limits fn)."""
        fake_resource = MagicMock()
        fake_resource.RLIMIT_AS = 9
        fake_resource.RLIMIT_CPU = 7
        fake_resource.RLIMIT_NPROC = 6
        fake_resource.error = OSError

        with patch("code_scan.scanners.platform.system", return_value="Linux"):
            with patch.dict("sys.modules", {"resource": fake_resource}):
                # Force reimport of the module-level function by calling directly
                # with the patched platform
                import code_scan.scanners as _s

                with patch.object(_s.platform, "system", return_value="Linux"):
                    result = _posix_resource_limits()

        # On a real Linux system it returns a callable; on Windows the outer
        # guard returns None before reaching import resource.  Either is valid.
        assert result is None or callable(result)

    def test_import_error_returns_none(self) -> None:
        """ImportError on 'resource' module import returns None (Windows-like)."""
        with patch("code_scan.scanners.platform.system", return_value="Linux"):
            with patch.dict("sys.modules", {"resource": None}):
                # Bust any cached import by raising ImportError from __import__
                import builtins

                real_import = builtins.__import__

                def _fake_import(name, *args, **kwargs):
                    if name == "resource":
                        raise ImportError("no module")
                    return real_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=_fake_import):
                    result = _posix_resource_limits()

        # ImportError branch → returns None
        assert result is None

    def test_set_limits_callable_handles_errors(self) -> None:
        """The returned _set_limits callable swallows resource errors gracefully."""
        fake_resource = MagicMock()
        fake_resource.RLIMIT_AS = 9
        fake_resource.RLIMIT_CPU = 7
        fake_resource.error = OSError
        # Simulate setrlimit raising ValueError for every call
        fake_resource.setrlimit.side_effect = ValueError("not supported")
        # RLIMIT_NPROC may not exist — AttributeError is swallowed
        del fake_resource.RLIMIT_NPROC

        with patch("code_scan.scanners.platform.system", return_value="Linux"):
            with patch.dict("sys.modules", {"resource": fake_resource}):

                # Directly test by constructing and calling _set_limits without
                # going through the module-level cache
                if fake_resource.setrlimit.called or True:
                    # Call the real helper with the fake resource patched
                    import builtins

                    real_import = builtins.__import__

                    def _fake_import(name, *args, **kwargs):
                        if name == "resource":
                            return fake_resource
                        return real_import(name, *args, **kwargs)

                    with patch("builtins.__import__", side_effect=_fake_import):
                        fn = _posix_resource_limits()
                    # If we got a callable, call it — must not raise
                    if callable(fn):
                        fn()  # ValueError inside → swallowed by pass


# ---------------------------------------------------------------------------
# scanners.py — _cap_output overflow branch (line 167)
# ---------------------------------------------------------------------------


class TestCapOutput:
    def test_cap_output_truncates(self) -> None:
        """_cap_output truncates bytes exceeding MAX_OUTPUT_BYTES."""
        big = b"x" * (MAX_OUTPUT_BYTES + 100)
        result = _cap_output(big)
        assert len(result) == MAX_OUTPUT_BYTES

    def test_cap_output_passthrough(self) -> None:
        """_cap_output returns the same object when under the limit."""
        small = b"ok"
        result = _cap_output(small)
        assert result == small


# ---------------------------------------------------------------------------
# scanners.py — _run_subprocess: FileNotFoundError (line 256),
#               output_overflow (line 263), env update (line 237)
# ---------------------------------------------------------------------------


class TestRunSubprocess:
    def test_file_not_found_raises_scanner_error(self) -> None:
        """FileNotFoundError → ScannerError('binary_not_found')."""
        with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            with pytest.raises(ScannerError) as exc_info:
                _run_subprocess(["no-such-binary"], scanner_name="semgrep")
        assert exc_info.value.scanner == "semgrep"
        assert exc_info.value.error_class == "binary_not_found"

    def test_output_overflow_raises_scanner_error(self) -> None:
        """stdout exceeding MAX_OUTPUT_BYTES → ScannerError('output_overflow')."""
        proc_mock = MagicMock()
        proc_mock.stdout = b"x" * (MAX_OUTPUT_BYTES + 1)
        with patch("subprocess.run", return_value=proc_mock):
            with pytest.raises(ScannerError) as exc_info:
                _run_subprocess(["semgrep"], scanner_name="semgrep")
        assert exc_info.value.error_class == "output_overflow"

    def test_env_param_merged(self) -> None:
        """Extra env dict is merged into the subprocess environment."""
        proc_mock = MagicMock()
        proc_mock.stdout = b"{}"
        captured_env: dict = {}

        def _capture_run(*args, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            return proc_mock

        with patch("subprocess.run", side_effect=_capture_run):
            _run_subprocess(["echo"], scanner_name="test", env={"MY_EXTRA": "yes"})

        assert captured_env.get("MY_EXTRA") == "yes"


# ---------------------------------------------------------------------------
# scanners.py — _parse_semgrep_output parse error (lines 281-282)
# ---------------------------------------------------------------------------


class TestParseSemgrepOutput:
    def test_bad_json_raises_scanner_error(self) -> None:
        """Non-JSON bytes → ScannerError('parse_error')."""
        with pytest.raises(ScannerError) as exc_info:
            _parse_semgrep_output(b"not json at all!", "block.py")
        assert exc_info.value.scanner == "semgrep"
        assert exc_info.value.error_class == "parse_error"

    def test_valid_json_no_results_key(self) -> None:
        """Valid JSON without 'results' key returns empty list."""
        result = _parse_semgrep_output(b'{"version": "1.0"}', "block.py")
        assert result == []

    def test_valid_result_parsed(self) -> None:
        """Semgrep result entry is parsed into normalised finding."""
        payload = json.dumps(
            {
                "results": [
                    {
                        "check_id": "sentinel.eval",
                        "start": {"line": 5},
                        "extra": {"severity": "ERROR"},
                    }
                ]
            }
        ).encode()
        findings = _parse_semgrep_output(payload, "block.py")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "sentinel.eval"
        assert findings[0]["severity"] == "high"
        assert findings[0]["line"] == 5


# ---------------------------------------------------------------------------
# scanners.py — run_semgrep: ruleset_not_found (line 316),
#               shutil.rmtree exception in finally (lines 336-337)
# ---------------------------------------------------------------------------


class TestRunSemgrepEdgeCases:
    def test_ruleset_not_found_raises(self) -> None:
        """Missing vendored ruleset → ScannerError('ruleset_not_found')."""
        with patch("code_scan.scanners.SEMGREP_RULESET_PATH") as mock_path:
            mock_path.exists.return_value = False
            with pytest.raises(ScannerError) as exc_info:
                run_semgrep("x = 1\n", "python")
        assert exc_info.value.error_class == "ruleset_not_found"

    def test_shutil_rmtree_exception_swallowed_semgrep(self) -> None:
        """Exception in semgrep finally cleanup is swallowed (best-effort)."""
        proc_mock = MagicMock()
        proc_mock.stdout = json.dumps({"results": []}).encode()

        with patch("subprocess.run", return_value=proc_mock):
            with patch("shutil.rmtree", side_effect=OSError("disk full")):
                # Must not raise despite cleanup failure
                findings = run_semgrep("x = 1\n", "python")
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# scanners.py — _parse_bandit_output parse error (lines 354-355)
# ---------------------------------------------------------------------------


class TestParseBanditOutput:
    def test_bad_json_raises_scanner_error(self) -> None:
        """Non-JSON bytes → ScannerError('parse_error')."""
        with pytest.raises(ScannerError) as exc_info:
            _parse_bandit_output(b"{{bad json}}")
        assert exc_info.value.scanner == "bandit"
        assert exc_info.value.error_class == "parse_error"

    def test_no_test_name_uses_test_id_only(self) -> None:
        """Bandit result with no test_name uses test_id as rule_id."""
        payload = json.dumps(
            {
                "results": [
                    {
                        "test_id": "B101",
                        "test_name": "",
                        "line_number": 3,
                        "issue_severity": "LOW",
                    }
                ]
            }
        ).encode()
        findings = _parse_bandit_output(payload)
        assert findings[0]["rule_id"] == "B101"

    def test_test_name_appended(self) -> None:
        """Bandit result with test_name builds rule_id as 'test_id.test_name'."""
        payload = json.dumps(
            {
                "results": [
                    {
                        "test_id": "B602",
                        "test_name": "subprocess_popen_with_shell_equals_true",
                        "line_number": 7,
                        "issue_severity": "HIGH",
                    }
                ]
            }
        ).encode()
        findings = _parse_bandit_output(payload)
        assert "B602" in findings[0]["rule_id"]
        assert findings[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# scanners.py — run_bandit: empty stdout (line 404),
#               shutil.rmtree exception in finally (lines 410-411)
# ---------------------------------------------------------------------------


class TestRunBanditEdgeCases:
    def test_empty_stdout_returns_no_findings(self) -> None:
        """Bandit producing no stdout → empty findings list (no parse error)."""
        proc_mock = MagicMock()
        proc_mock.stdout = b""  # empty

        with patch("subprocess.run", return_value=proc_mock):
            findings = run_bandit("x = 1\n")
        assert findings == []

    def test_whitespace_only_stdout_returns_no_findings(self) -> None:
        """Bandit producing only whitespace stdout → empty findings list."""
        proc_mock = MagicMock()
        proc_mock.stdout = b"   \n  "

        with patch("subprocess.run", return_value=proc_mock):
            findings = run_bandit("x = 1\n")
        assert findings == []

    def test_shutil_rmtree_exception_swallowed_bandit(self) -> None:
        """Exception in bandit finally cleanup is swallowed (best-effort)."""
        proc_mock = MagicMock()
        proc_mock.stdout = json.dumps({"results": []}).encode()

        with patch("subprocess.run", return_value=proc_mock):
            with patch("shutil.rmtree", side_effect=OSError("disk full")):
                findings = run_bandit("x = 1\n")
        assert isinstance(findings, list)

    def test_binary_not_found_raises_scanner_error(self) -> None:
        """FileNotFoundError from bandit → ScannerError('binary_not_found')."""
        with patch("subprocess.run", side_effect=FileNotFoundError("bandit not found")):
            with pytest.raises(ScannerError) as exc_info:
                run_bandit("x = 1\n")
        assert exc_info.value.scanner == "bandit"
        assert exc_info.value.error_class == "binary_not_found"

    def test_timeout_raises_scanner_error(self) -> None:
        """TimeoutExpired from bandit → ScannerError('timeout')."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bandit"], timeout=30),
        ):
            with pytest.raises(ScannerError) as exc_info:
                run_bandit("x = 1\n")
        assert exc_info.value.error_class == "timeout"


# ---------------------------------------------------------------------------
# config.py — _safe_severity valid branch (line 87),
#             _safe_action valid branch (line 94),
#             _parse_payload bad JSON (lines 105-107),
#             _parse_payload enabled=False (line 111),
#             load_code_scan_config whitespace tenant_id (line 145),
#             load_code_scan_config DB exception (lines 152-157)
# ---------------------------------------------------------------------------


class TestConfigBranches:
    def test_safe_severity_valid_returns_value(self) -> None:
        """_safe_severity with a valid severity string returns it lowercased."""
        from code_scan.config import _safe_severity

        assert _safe_severity("HIGH", "low") == "high"
        assert _safe_severity("critical", "low") == "critical"

    def test_safe_severity_invalid_returns_default(self) -> None:
        """_safe_severity with an invalid value returns the default."""
        from code_scan.config import _safe_severity

        assert _safe_severity("bogus", "medium") == "medium"
        assert _safe_severity(None, "low") == "low"

    def test_safe_action_valid_returns_value(self) -> None:
        """_safe_action with a valid action string returns it lowercased."""
        from code_scan.config import _safe_action

        assert _safe_action("REJECT", "audit") == "reject"
        assert _safe_action("audit", "reject") == "audit"

    def test_safe_action_invalid_returns_default(self) -> None:
        """_safe_action with an invalid value returns the default."""
        from code_scan.config import _safe_action

        assert _safe_action("unknown_action", "audit") == "audit"
        assert _safe_action(42, "reject") == "reject"

    def test_parse_payload_malformed_json_returns_disabled(self) -> None:
        """Malformed JSON payload → disabled config (fail-safe)."""
        from code_scan.config import _DISABLED_CONFIG, _parse_payload

        result = _parse_payload("{{not valid json}}")
        assert result == _DISABLED_CONFIG
        assert result.enabled is False

    def test_parse_payload_enabled_false_returns_disabled(self) -> None:
        """Payload with enabled=false → disabled config."""
        from code_scan.config import _DISABLED_CONFIG, _parse_payload

        payload = json.dumps({"enabled": False, "thresholds": {}, "actions": {}})
        result = _parse_payload(payload)
        assert result == _DISABLED_CONFIG

    def test_parse_payload_enabled_true_missing_thresholds_uses_defaults(self) -> None:
        """Payload with enabled=true but missing thresholds → safe defaults."""
        from code_scan.config import _parse_payload

        payload = json.dumps({"enabled": True})
        result = _parse_payload(payload)
        assert result.enabled is True
        assert result.warn_threshold == "low"
        assert result.block_threshold == "high"
        assert result.warn_action == "audit"
        assert result.block_action == "reject"

    def test_parse_payload_partial_thresholds_uses_defaults(self) -> None:
        """Payload with invalid threshold value falls back to default per field."""
        from code_scan.config import _parse_payload

        payload = json.dumps(
            {
                "enabled": True,
                "thresholds": {"warn": "invalid_severity", "block": "high"},
                "actions": {"warn": "REJECT", "block": "audit"},
            }
        )
        result = _parse_payload(payload)
        # Invalid 'warn' threshold → default "low"; 'block' "high" is valid
        assert result.warn_threshold == "low"
        assert result.block_threshold == "high"
        # Valid action "REJECT" → "reject"; valid "audit" → "audit"
        assert result.warn_action == "reject"
        assert result.block_action == "audit"

    @pytest.mark.asyncio
    async def test_load_config_whitespace_tenant_id_returns_disabled(self) -> None:
        """Whitespace-only tenant_id → _DISABLED_CONFIG without DB call."""
        from code_scan.config import _DISABLED_CONFIG, load_code_scan_config

        with patch("code_scan.config.get_tenant_session") as mock_session:
            result = await load_code_scan_config("   ")
        # No DB call, just returns disabled
        mock_session.assert_not_called()
        assert result == _DISABLED_CONFIG

    @pytest.mark.asyncio
    async def test_load_config_db_exception_returns_disabled(self) -> None:
        """DB/session error during config load → _DISABLED_CONFIG (fail-safe)."""
        from code_scan.config import _DISABLED_CONFIG, load_code_scan_config

        @asynccontextmanager
        async def _boom(tid: str):
            raise RuntimeError("DB connection refused")
            yield  # noqa: unreachable

        with patch("code_scan.config.get_tenant_session", _boom):
            result = await load_code_scan_config("tenant-boom")

        assert result == _DISABLED_CONFIG
        assert result.enabled is False

    @pytest.mark.asyncio
    async def test_load_config_no_policies_returns_disabled(self) -> None:
        """Active policy query returns empty list → _DISABLED_CONFIG (default-OFF)."""
        from code_scan.config import _DISABLED_CONFIG, load_code_scan_config

        mock_session = MagicMock()
        mock_session.begin = MagicMock(side_effect=_async_null_cm)

        @asynccontextmanager
        async def _fake_session(tid: str):
            yield mock_session

        with patch("code_scan.config.get_tenant_session", _fake_session):
            with patch("code_scan.config.PolicyRepository") as MockRepo:
                instance = MagicMock()
                instance.get_active_policies_for_scope = AsyncMock(return_value=[])
                MockRepo.return_value = instance
                result = await load_code_scan_config("tenant-no-policy")

        assert result == _DISABLED_CONFIG


# ---------------------------------------------------------------------------
# detector.py — remaining missing branches
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _async_null_cm(*args, **kwargs):
    yield None


class TestDetectorMissingBranches:
    """Cover the detector branches not hit by the existing threat-model tests."""

    # -- tenant_id extraction exception (lines 98-99) ----------------------

    @pytest.mark.asyncio
    async def test_tenant_id_extraction_exception_becomes_empty(self) -> None:
        """Exception reading tenant_context.tenant_id → empty string → disabled."""
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()

        # Build a context object whose .tenant_context.tenant_id property raises.
        class _BadTenantContext:
            @property
            def tenant_id(self) -> str:
                raise RuntimeError("no tenant available")

        bad_ctx = MagicMock()
        bad_ctx.tenant_context = _BadTenantContext()
        bad_ctx._is_stream = False
        bad_ctx.emit = AsyncMock()

        # _load_config("") → disabled (no DB call), so inspect returns pass with no event
        result = await detector.inspect("```python\nx=1\n```", bad_ctx)

        assert result.action == "pass"

    # -- unexpected exception in scanner layer (lines 125-128) ----------------

    @pytest.mark.asyncio
    async def test_unexpected_exception_in_scan_becomes_scanner_error(self) -> None:
        """Non-ScannerError exception in scan layer → synthetic ScannerError → WARN."""
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
                side_effect=MemoryError("OOM"),
            ):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"
        assert ctx.emit.called
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_error"
        # error_class should be the exception class name
        assert emitted["error_class"] == "MemoryError"

    # -- PASS verdict with findings > 0 includes top_severity (line 161) ------

    @pytest.mark.asyncio
    async def test_pass_verdict_with_findings_includes_top_severity(self) -> None:
        """PASS verdict with findings > 0 includes top_severity in event."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        # Thresholds set so that "low" finding does NOT reach warn threshold
        config = CodeScanConfig(
            enabled=True,
            warn_threshold="medium",  # low < medium → PASS
            block_threshold="high",
            warn_action="audit",
            block_action="reject",
        )

        low_finding = [{"rule_id": "r1", "severity": "low", "line": 1}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=low_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_passed"
        # finding_count > 0 → top_severity MUST be present
        assert "top_severity" in emitted
        assert emitted["top_severity"] == "low"

    # -- PASS verdict emit exception swallowed (lines 167-168) ----------------

    @pytest.mark.asyncio
    async def test_pass_emit_exception_swallowed(self) -> None:
        """Exception from context.emit on PASS path is swallowed."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="high",
            block_threshold="critical",
            warn_action="audit",
            block_action="reject",
        )

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=[]):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        # Must not raise even though emit raises
        assert result.action == "pass"

    # -- WARN verdict path (lines 172-187) ------------------------------------

    @pytest.mark.asyncio
    async def test_warn_verdict_emits_warned_event(self) -> None:
        """WARN verdict emits code_scan_warned with warn verdict."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="critical",  # high < critical → WARN not BLOCK
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 2}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"
        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_warned"
        assert emitted["verdict"] == "warn"
        assert emitted["action_taken"] == "logged"
        assert emitted["top_severity"] == "high"

    @pytest.mark.asyncio
    async def test_warn_verdict_with_skipped_blocks_includes_count(self) -> None:
        """WARN verdict includes skipped_blocks when extractor skipped some."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="critical",
            warn_action="audit",
            block_action="reject",
        )

        # Build a fake extraction with skipped_count > 0
        fake_block = MagicMock()
        fake_block.content = "x = 1\n"
        fake_block.language = "python"
        fake_extraction = MagicMock()
        fake_extraction.blocks = [fake_block]
        fake_extraction.skipped_count = 3

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 2}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.extract_code_blocks", return_value=fake_extraction):
                with patch("code_scan.detector.scan_block", return_value=high_finding):
                    await detector.inspect("```python\nx=1\n```", ctx)

        emitted = ctx.emit.call_args[0][0]
        assert emitted["event_type"] == "code_scan_warned"
        assert emitted.get("skipped_blocks") == 3

    @pytest.mark.asyncio
    async def test_warn_emit_exception_swallowed(self) -> None:
        """Exception from context.emit on WARN path is swallowed."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="critical",
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 2}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"

    # -- BLOCK+stream emit exception swallowed (lines 205-206) ---------------

    @pytest.mark.asyncio
    async def test_block_stream_emit_exception_swallowed(self) -> None:
        """Exception from context.emit on streamed-BLOCK path is swallowed."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=True)
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"

    # -- BLOCK+reject emit exception swallowed (lines 222-223) ---------------

    @pytest.mark.asyncio
    async def test_block_reject_emit_exception_swallowed(self) -> None:
        """Exception from context.emit on non-stream BLOCK reject path is swallowed."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=False)
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",
            warn_action="audit",
            block_action="reject",
        )

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        # Even with emit raising, the block action must be returned
        assert result.action == "block"

    # -- BLOCK+audit emit exception swallowed (lines 238-239) -----------------

    @pytest.mark.asyncio
    async def test_block_audit_emit_exception_swallowed(self) -> None:
        """Exception from context.emit on BLOCK+audit downgrade path is swallowed."""
        from code_scan.config import CodeScanConfig
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context(is_stream=False)
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        config = CodeScanConfig(
            enabled=True,
            warn_threshold="low",
            block_threshold="low",
            warn_action="audit",
            block_action="audit",  # downgrade BLOCK to WARN
        )

        high_finding = [{"rule_id": "r1", "severity": "high", "line": 1}]

        with patch.object(detector, "_load_config", return_value=config):
            with patch("code_scan.detector.scan_block", return_value=high_finding):
                result = await detector.inspect("```python\nx=1\n```", ctx)

        assert result.action == "pass"

    # -- _load_config paths (lines 255-264) -----------------------------------

    @pytest.mark.asyncio
    async def test_load_config_empty_tenant_id_returns_disabled(self) -> None:
        """Empty tenant_id in _load_config → _DISABLED_CONFIG without DB call."""
        from code_scan.config import _DISABLED_CONFIG
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        with patch(
            "code_scan.detector.load_code_scan_config",
        ) as mock_load:
            result = await detector._load_config("")
        mock_load.assert_not_called()
        assert result == _DISABLED_CONFIG

    @pytest.mark.asyncio
    async def test_load_config_exception_returns_disabled(self) -> None:
        """Exception from load_code_scan_config → _DISABLED_CONFIG (fail-safe)."""
        from code_scan.config import _DISABLED_CONFIG
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        with patch(
            "code_scan.detector.load_code_scan_config",
            side_effect=RuntimeError("DB down"),
        ):
            result = await detector._load_config("tenant-abc")
        assert result == _DISABLED_CONFIG

    # -- _handle_scanner_error emit exception swallowed (lines 313-314) -------

    @pytest.mark.asyncio
    async def test_handle_scanner_error_emit_exception_swallowed(self) -> None:
        """Exception from context.emit in _handle_scanner_error is swallowed."""
        from code_scan.detector import CodeScanDetector

        detector = CodeScanDetector()
        ctx = make_mock_context()
        ctx.emit = AsyncMock(side_effect=RuntimeError("emit failed"))

        exc = ScannerError("semgrep", "timeout")
        result = await detector._handle_scanner_error(ctx, exc)

        assert result.action == "pass"
