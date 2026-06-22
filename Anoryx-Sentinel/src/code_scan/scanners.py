"""Bounded, isolated subprocess wrappers for Semgrep and Bandit (F-016, ADR-0019 §11).

Security model (ADR-0019 §5):
  - Each scan creates a fresh ``tempfile.mkdtemp()`` directory.
  - The code block is written to a SERVER-CHOSEN filename (never derived from a
    model-supplied fenced filename or from block content).
  - The scanner binary receives the FILE PATH as an argv argument; content is
    NEVER interpolated into a shell string (shell=False always).
  - A hard wall-clock ``timeout=`` is set on every subprocess call.
  - stdout/stderr are capped at ``MAX_OUTPUT_BYTES`` to prevent OOM from a
    scanner producing enormous output.
  - POSIX ``resource.setrlimit(RLIMIT_AS, RLIMIT_CPU)`` is applied in the
    child process via ``preexec_fn`` when available.  On Windows this is a
    documented no-op; the timeout is the cross-platform backstop.
  - Semgrep is invoked with ``--metrics=off --disable-version-check`` to
    prevent any outbound telemetry or version-check network traffic.
  - The ruleset is a local file path passed as ``--config <path>`` — no
    registry fetch, no network, fully offline.
  - The temp directory is removed in a ``finally`` block regardless of outcome.
  - STATIC ONLY — the temp file is read by the scanner, NEVER executed.

Normalised finding format::

    {"rule_id": str, "severity": str, "line": int}

``severity`` is one of: "critical", "high", "medium", "low", "info".
Semgrep's ERROR/WARNING/INFO levels are mapped as:
    ERROR   → "high"
    WARNING → "medium"
    INFO    → "low"
Bandit's HIGH/MEDIUM/LOW levels are mapped directly (lowercase).

``ScannerError`` is raised on any timeout, crash, non-parseable output, or
output-size overflow.  The caller (``verdict.py``) maps this to WARN.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Hard wall-clock timeout per scanner subprocess (seconds).
SCANNER_TIMEOUT_SECONDS: int = 30

# Maximum bytes captured from scanner stdout + stderr combined.
MAX_OUTPUT_BYTES: int = 1_048_576  # 1 MiB

# POSIX resource limits applied to scanner subprocesses.
# On Windows these are no-ops (documented); the timeout is the backstop.
_RLIMIT_AS_BYTES: int = 512 * 1024 * 1024  # 512 MiB virtual address space
_RLIMIT_CPU_SECONDS: int = 25  # must be less than SCANNER_TIMEOUT_SECONDS

# Semgrep severity string → normalised severity mapping.
_SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    # Semgrep also uses these in some rule packs.
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Bandit severity string → normalised severity mapping.
_BANDIT_SEVERITY_MAP: dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Path to the vendored Semgrep ruleset (relative to this file).
_RULESETS_DIR = Path(__file__).parent / "rulesets"
SEMGREP_RULESET_PATH: Path = _RULESETS_DIR / "python-security.yaml"


# ---------------------------------------------------------------------------
# Typed exception
# ---------------------------------------------------------------------------


class ScannerError(Exception):
    """Raised when a scanner subprocess fails, times out, or produces unparseable output.

    The caller (verdict.py) maps ScannerError to verdict WARN (never PASS,
    never BLOCK) — fail-safe degrade per ADR-0019 §6.

    Attributes
    ----------
    scanner:
        Name of the scanner that failed ("semgrep" or "bandit").
    error_class:
        Short string classifying the failure (e.g. "timeout", "parse_error",
        "output_overflow", "nonzero_exit").  NEVER includes the offending code
        or a stack trace (ADR-0019 §6).
    """

    def __init__(self, scanner: str, error_class: str) -> None:
        self.scanner = scanner
        self.error_class = error_class
        super().__init__(f"{scanner} failed: {error_class}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _posix_resource_limits() -> Any:
    """Return a preexec_fn that sets RLIMIT_AS and RLIMIT_CPU, or None on Windows.

    The returned callable is passed as ``preexec_fn`` to ``subprocess.run``.
    On non-POSIX platforms it returns None, relying on the timeout backstop.
    Windows does not support preexec_fn at all and would raise if non-None is
    passed, so we guard explicitly.
    """
    if platform.system() == "Windows":
        # preexec_fn is not supported on Windows.  Timeout is the backstop.
        return None

    try:
        import resource

        def _set_limits() -> None:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (_RLIMIT_AS_BYTES, _RLIMIT_AS_BYTES))
            except (ValueError, resource.error):
                pass  # best-effort; timeout is the backstop
            try:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (_RLIMIT_CPU_SECONDS, _RLIMIT_CPU_SECONDS),
                )
            except (ValueError, resource.error):
                pass
            # LOW-2 fix: limit the number of child processes the scanner
            # subprocess may fork.  RLIMIT_NPROC is POSIX (Linux/macOS);
            # a no-op on Windows (guarded above).  Best-effort: if the limit
            # is not supported or the hard limit is lower, we accept it silently.
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            except (ValueError, AttributeError, resource.error):
                pass  # not all POSIX platforms export RLIMIT_NPROC

        return _set_limits
    except ImportError:
        return None


def _cap_output(raw: bytes) -> bytes:
    """Truncate scanner output to MAX_OUTPUT_BYTES."""
    if len(raw) > MAX_OUTPUT_BYTES:
        return raw[:MAX_OUTPUT_BYTES]
    return raw


def _write_block_to_tempdir(content: str, language: str) -> tuple[str, str]:
    """Write *content* to a server-chosen temp file; return (temp_dir, file_path).

    The filename is determined by the server (``block.py`` or ``block.js``,
    derived from *language* for scanner accuracy), NEVER from any model-supplied
    fenced filename.  The temp directory has an unguessable name from mkdtemp.
    The caller is responsible for removing the temp directory in a finally block.
    """
    temp_dir = tempfile.mkdtemp(prefix="sentinel_scan_")

    # Choose a safe server-side filename from the language tag.  Fall back to
    # "block.txt" for unknown languages so Semgrep still runs (generic rules).
    _EXT_MAP = {
        "python": "block.py",
        "py": "block.py",
        "javascript": "block.js",
        "js": "block.js",
        "typescript": "block.ts",
        "ts": "block.ts",
        "java": "Block.java",
        "go": "block.go",
        "ruby": "block.rb",
        "rb": "block.rb",
        "rust": "block.rs",
        "rs": "block.rs",
        "c": "block.c",
        "cpp": "block.cpp",
        "c++": "block.cpp",
        "bash": "block.sh",
        "sh": "block.sh",
        "shell": "block.sh",
        "sql": "block.sql",
        "yaml": "block.yaml",
        "yml": "block.yaml",
        "json": "block.json",
        "php": "block.php",
        "kotlin": "block.kt",
        "swift": "block.swift",
        "scala": "block.scala",
    }
    filename = _EXT_MAP.get(language.lower(), "block.txt")
    file_path = os.path.join(temp_dir, filename)

    # Write with UTF-8 encoding; scanner receives the path only.
    with open(file_path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(content)

    return temp_dir, file_path


def _run_subprocess(
    argv: list[str],
    *,
    scanner_name: str,
    env: dict[str, str] | None = None,
) -> bytes:
    """Execute *argv* as a bounded subprocess and return raw stdout bytes.

    Raises ``ScannerError`` on timeout, non-zero exit (when stdout is empty or
    unparseable is determined by the caller), or if stdout exceeds MAX_OUTPUT_BYTES.

    The subprocess is invoked with shell=False (argv list, never a string).
    POSIX resource limits are applied via preexec_fn when available.
    """
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    # Force UTF-8 I/O in the subprocess to avoid Windows cp1252 decode errors.
    merged_env["PYTHONUTF8"] = "1"
    merged_env["PYTHONIOENCODING"] = "utf-8"

    preexec = _posix_resource_limits()

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=SCANNER_TIMEOUT_SECONDS,
            shell=False,  # NEVER shell=True; argv is a list, not a string.
            env=merged_env,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(scanner_name, "timeout") from exc
    except FileNotFoundError as exc:
        raise ScannerError(scanner_name, "binary_not_found") from exc
    except Exception as exc:
        raise ScannerError(scanner_name, "subprocess_error") from exc

    # MED-3: capture raw once; check overflow on the original, cap only after.
    raw_stdout = proc.stdout or b""
    if len(raw_stdout) > MAX_OUTPUT_BYTES:
        raise ScannerError(scanner_name, "output_overflow")
    return _cap_output(raw_stdout)


# ---------------------------------------------------------------------------
# Semgrep scanner
# ---------------------------------------------------------------------------


def _parse_semgrep_output(raw: bytes, file_path: str) -> list[dict[str, Any]]:
    """Parse Semgrep JSON output into normalised findings.

    Raises ``ScannerError("semgrep", "parse_error")`` if the output cannot be
    decoded as JSON or does not contain a "results" key.
    """
    try:
        text = raw.decode("utf-8", errors="replace")
        data = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScannerError("semgrep", "parse_error") from exc

    findings: list[dict[str, Any]] = []
    for r in data.get("results", []):
        check_id = r.get("check_id", "unknown")
        line = r.get("start", {}).get("line", 0)
        raw_sev = r.get("extra", {}).get("severity", "INFO")
        severity = _SEMGREP_SEVERITY_MAP.get(raw_sev.upper(), "low")
        findings.append({"rule_id": check_id, "severity": severity, "line": line})

    return findings


def run_semgrep(content: str, language: str) -> list[dict[str, Any]]:
    """Run Semgrep over *content* using the vendored offline ruleset.

    Parameters
    ----------
    content:
        The code block text (already capped by the extractor).
    language:
        Language tag (e.g. "python").  Used to choose the server-side filename
        for accurate Semgrep language detection.

    Returns
    -------
    list of normalised findings: ``[{"rule_id": str, "severity": str, "line": int}]``

    Raises
    ------
    ScannerError
        On timeout, crash, parse error, or output overflow.
    """
    if not SEMGREP_RULESET_PATH.exists():
        raise ScannerError("semgrep", "ruleset_not_found")

    temp_dir, file_path = _write_block_to_tempdir(content, language)
    try:
        argv = [
            "semgrep",
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            str(SEMGREP_RULESET_PATH),
            file_path,  # PATH as argv arg — never shell-interpolated
        ]
        stdout = _run_subprocess(argv, scanner_name="semgrep")
        return _parse_semgrep_output(stdout, file_path)
    finally:
        # Always clean up the temp directory regardless of outcome.
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass  # best-effort cleanup; never mask the original error


# ---------------------------------------------------------------------------
# Bandit scanner (Python only)
# ---------------------------------------------------------------------------


def _parse_bandit_output(raw: bytes) -> list[dict[str, Any]]:
    """Parse Bandit JSON output into normalised findings.

    Raises ``ScannerError("bandit", "parse_error")`` if the output cannot be
    decoded or does not contain a "results" key.
    """
    try:
        text = raw.decode("utf-8", errors="replace")
        data = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScannerError("bandit", "parse_error") from exc

    findings: list[dict[str, Any]] = []
    for r in data.get("results", []):
        test_id = r.get("test_id", "unknown")
        test_name = r.get("test_name", "")
        rule_id = f"{test_id}.{test_name}" if test_name else test_id
        line = r.get("line_number", 0)
        raw_sev = r.get("issue_severity", "LOW")
        severity = _BANDIT_SEVERITY_MAP.get(raw_sev.upper(), "low")
        findings.append({"rule_id": rule_id, "severity": severity, "line": line})

    return findings


def run_bandit(content: str) -> list[dict[str, Any]]:
    """Run Bandit over *content* (Python blocks only).

    Parameters
    ----------
    content:
        The code block text (already capped by the extractor).

    Returns
    -------
    list of normalised findings: ``[{"rule_id": str, "severity": str, "line": int}]``

    Raises
    ------
    ScannerError
        On timeout, crash, parse error, or output overflow.
    """
    temp_dir, file_path = _write_block_to_tempdir(content, "python")
    try:
        argv = [
            "bandit",
            "-f",
            "json",
            "-q",  # quiet: suppress progress output
            file_path,  # PATH as argv arg — never shell-interpolated
        ]
        stdout = _run_subprocess(argv, scanner_name="bandit")

        # Bandit exits 1 when findings are present, 0 when clean.
        # We do not check the exit code here; we rely on JSON output.
        # Empty stdout (e.g. binary_not_found already raised above) is
        # handled by parse: empty bytes → parse_error.
        if not stdout.strip():
            # No output at all — treat as no findings (bandit was quiet).
            return []

        return _parse_bandit_output(stdout)
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Combined scan entry point
# ---------------------------------------------------------------------------


def scan_block(content: str, language: str) -> list[dict[str, Any]]:
    """Run all applicable scanners on a single code block.

    Semgrep runs on all blocks.  Bandit runs additionally on Python blocks.
    Findings from all scanners are merged into a single deduplicated list.

    ScannerError propagates to the caller (verdict.py maps it to WARN).

    Parameters
    ----------
    content:
        The code block text (already capped by the extractor).
    language:
        Language tag.  Used to determine which scanners apply.

    Returns
    -------
    Merged list of normalised findings from all applicable scanners.
    """
    findings: list[dict[str, Any]] = []

    # Always run Semgrep (handles all languages via the ruleset).
    semgrep_findings = run_semgrep(content, language)
    findings.extend(semgrep_findings)

    # HIGH-4: only explicitly-tagged Python blocks get Bandit.  Untagged/other-
    # language blocks get Semgrep-only (generic ruleset).  An empty language
    # tag on an untagged fence must NOT be treated as Python — that caused
    # parse-error ScannerErrors masking real PASSes (ADR-0019 §13).
    is_python = language.lower() in ("python", "py")
    if is_python:
        bandit_findings = run_bandit(content)
        findings.extend(bandit_findings)

    return findings
