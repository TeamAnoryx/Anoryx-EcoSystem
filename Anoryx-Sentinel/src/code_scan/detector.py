"""CodeScanDetector — 5th PostResponseHook (F-016, ADR-0019 §11).

Extracts fenced code blocks from an LLM response, scans them with Semgrep and
Bandit, and aggregates findings into a per-tenant verdict (PASS | WARN | BLOCK).
Emits one of four audit events per scan and maps the verdict to a DetectorResult.

Design constraints (from ADR-0019):
  - detector_slug = "code-scan"  (reserved in contracts/ids.md)
  - Default-OFF: absent policy → PASS, no event, no scan (Fork 4).
  - BLOCK applies only to non-streamed responses (Fork 1/R7).
    Streamed BLOCK-threshold → WARN + code_scan_warned with
    block_suppressed_by_streaming=True.
  - Any scanner error → WARN + code_scan_error (fail-safe, R4).
  - Audit event payload contains only metadata:
      verdict, language, finding_count, top_severity, scanner
    NEVER the code, NEVER a stack trace (R4 / CLAUDE.md honest-language).
  - action_taken = "blocked" for code_scan_blocked, "logged" for all others
    (matches ACTION_TAKEN_BY_EVENT_TYPE in events_audit_log.py).

Registration:
  Do NOT edit build_default_registry() here — the orchestration-hooks agent
  does that in STEP 5.  This class is directly importable and unit-testable.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from code_scan.config import CodeScanConfig, load_code_scan_config
from code_scan.extractor import extract_code_blocks
from code_scan.scanners import ScannerError, scan_block
from code_scan.verdict import Verdict, aggregate_verdict, top_severity_from_findings
from orchestration.hooks.base import DetectorResult, PostResponseHook

log = structlog.get_logger(__name__)

_SLUG = "code-scan"

# HIGH-1 fix: total wall-clock budget across ALL blocks/scanners in one inspect()
# call.  MAX_BLOCKS=20 × (semgrep+bandit) × SCANNER_TIMEOUT_SECONDS=30 ≈ 1200 s
# without this cap — an amplification DoS on the synchronous response path.
# 60 s is well under any typical worker/request timeout (120–300 s) while
# allowing real workloads (1–5 blocks) ample headroom.
MAX_TOTAL_SCAN_SECONDS: int = 60


class CodeScanDetector(PostResponseHook):
    """Post-response hook: scan LLM code output for likely vulnerabilities.

    Implements the full ADR-0019 inspect() contract:
      1. Load per-tenant config; if disabled → PASS cheaply, no event.
      2. Extract fenced code blocks (capped).
      3. Scan each block with Semgrep + Bandit (capped, isolated, timeout-bounded).
      4. Aggregate findings → PASS | WARN | BLOCK.
      5. Map verdict → DetectorResult + emit audit event.

    Honest framing: this detector "flags likely vulnerabilities" in AI-generated
    code blocks.  It does NOT guarantee the code is safe or bug-free.
    """

    @property
    def detector_slug(self) -> str:
        return _SLUG

    async def inspect(self, content: str, context: Any) -> DetectorResult:  # noqa: PLR0911
        """Inspect LLM response *content* for likely vulnerable code.

        Parameters
        ----------
        content:
            Full response text (non-streamed) or accumulated streaming text.
        context:
            HookContext — used for ``ctx.emit()`` and ``ctx.is_stream``.

        Returns
        -------
        DetectorResult with action "pass" or "block" (never "mask").
        """
        # ------------------------------------------------------------------
        # 1. Load config — default-OFF gate.
        # ------------------------------------------------------------------
        # CRIT-1 fix: do NOT rely on a session smuggled through the context.
        # Production HookContext objects never carry _db_session — only
        # _is_stream is set by _make_post_context.  Reading a session from
        # the context always returned None in production, making the detector
        # a permanent no-op for every tenant.
        #
        # Instead, extract only the tenant_id (which HookContext.tenant_context
        # always exposes) and let _load_config open its own RLS-scoped session
        # via get_tenant_session(tenant_id) — exactly how injection_detector.py
        # resolves its per-tenant config.
        tenant_id: str = ""
        try:
            tenant_id = context.tenant_context.tenant_id
        except Exception:
            pass

        config = await self._load_config(tenant_id)

        if not config.enabled:
            # Cheap no-op: no scan, no event.
            return DetectorResult(action="pass")

        # ------------------------------------------------------------------
        # 2. Extract code blocks.
        # ------------------------------------------------------------------
        extraction = extract_code_blocks(content)

        if not extraction.blocks and extraction.skipped_count == 0:
            # No code blocks found; nothing to scan.
            return DetectorResult(action="pass")

        # ------------------------------------------------------------------
        # 3. Scan blocks and aggregate findings.
        # ------------------------------------------------------------------
        is_stream: bool = bool(getattr(context, "_is_stream", False))  # MED-1: accept any truthy

        try:
            all_findings, scanner_name = self._scan_all_blocks(extraction)
        except ScannerError as exc:
            return await self._handle_scanner_error(context, exc)
        except Exception as exc:
            # Unexpected error in scanner layer → fail-safe WARN.
            synthetic = ScannerError("unknown", type(exc).__name__)
            return await self._handle_scanner_error(context, synthetic)

        # ------------------------------------------------------------------
        # 4. Aggregate verdict.
        # ------------------------------------------------------------------
        verdict = aggregate_verdict(
            all_findings,
            warn_threshold=config.warn_threshold,
            block_threshold=config.block_threshold,
        )

        # ------------------------------------------------------------------
        # 5. Map verdict → result + emit event.
        # ------------------------------------------------------------------
        top_sev = top_severity_from_findings(all_findings)
        finding_count = len(all_findings)

        # Determine a representative language (first block's language).
        language = extraction.blocks[0].language if extraction.blocks else ""

        if verdict == Verdict.PASS:
            # HIGH-3: when finding_count == 0, omit top_severity entirely
            # (contract enum does not include "none"; field is OPTIONAL on
            # code_scan_passed per api-architect amendment).
            event: dict = {
                "event_type": "code_scan_passed",
                "action_taken": "logged",
                "verdict": "pass",  # HIGH-2: wire value is lowercase
                "language": language,
                "finding_count": finding_count,
                "scanner": scanner_name,
            }
            if finding_count > 0:
                event["top_severity"] = top_sev
            # MED-1 fix: wrap success-path emit in best-effort try/except,
            # matching the error-path pattern (~line 256-259).  A future raising
            # emit must not convert a detection into a 500 response.
            try:
                await context.emit(event, detector_slug=_SLUG)
            except Exception:
                pass
            return DetectorResult(action="pass", event=event)

        if verdict == Verdict.WARN:
            event = {
                "event_type": "code_scan_warned",
                "action_taken": "logged",
                "verdict": "warn",  # HIGH-2: wire value is lowercase
                "language": language,
                "finding_count": finding_count,
                "top_severity": top_sev,  # WARN always has ≥1 finding
                "scanner": scanner_name,
            }
            if extraction.skipped_count > 0:
                event["skipped_blocks"] = extraction.skipped_count
            try:
                await context.emit(event, detector_slug=_SLUG)
            except Exception:
                pass
            return DetectorResult(action="pass", event=event)

        # verdict == Verdict.BLOCK
        if is_stream:
            # Streaming: honest BLOCK is physically impossible (bytes already
            # sent).  Emit WARN with block_suppressed_by_streaming=True.
            event = {
                "event_type": "code_scan_warned",
                "action_taken": "logged",
                "verdict": "block",  # HIGH-2: wire value is lowercase
                "language": language,
                "finding_count": finding_count,
                "top_severity": top_sev,  # BLOCK always has ≥1 finding
                "scanner": scanner_name,
                "block_suppressed_by_streaming": True,
            }
            try:
                await context.emit(event, detector_slug=_SLUG)
            except Exception:
                pass
            return DetectorResult(action="pass", event=event)

        # Non-streamed BLOCK.
        if config.block_action == "reject":
            event = {
                "event_type": "code_scan_blocked",
                "action_taken": "blocked",
                "verdict": "block",  # HIGH-2: wire value is lowercase
                "language": language,
                "finding_count": finding_count,
                "top_severity": top_sev,  # BLOCK always has ≥1 finding
                "scanner": scanner_name,
            }
            try:
                await context.emit(event, detector_slug=_SLUG)
            except Exception:
                pass
            return DetectorResult(action="block", event=event)
        else:
            # block_action == "audit" — tenant wants signal without rejection.
            event = {
                "event_type": "code_scan_warned",
                "action_taken": "logged",
                "verdict": "block",  # HIGH-2: wire value is lowercase
                "language": language,
                "finding_count": finding_count,
                "top_severity": top_sev,  # BLOCK always has ≥1 finding
                "scanner": scanner_name,
            }
            try:
                await context.emit(event, detector_slug=_SLUG)
            except Exception:
                pass
            return DetectorResult(action="pass", event=event)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_config(self, tenant_id: str) -> CodeScanConfig:
        """Load config; return disabled config on any error (fail-safe).

        CRIT-1 fix: no longer accepts a session parameter.  Delegates to
        load_code_scan_config() which opens its own RLS-scoped session via
        get_tenant_session(tenant_id).  An empty tenant_id → _DISABLED_CONFIG
        (default-OFF semantics preserved; no session opened without a valid
        tenant context — fail-closed guard in get_tenant_session).
        """
        if not tenant_id:
            from code_scan.config import _DISABLED_CONFIG  # noqa: PLC0415

            return _DISABLED_CONFIG
        try:
            return await load_code_scan_config(tenant_id)
        except Exception:
            from code_scan.config import _DISABLED_CONFIG  # noqa: PLC0415

            return _DISABLED_CONFIG

    def _scan_all_blocks(
        self,
        extraction: Any,
    ) -> tuple[list[dict], str]:
        """Scan all extracted blocks and merge findings within a total wall-clock budget.

        HIGH-1 fix: the 30 s per-subprocess timeout alone allows up to
        MAX_BLOCKS × 2 scanners × 30 s ≈ 1200 s total — an amplification DoS
        on the synchronous response path.  A monotonic deadline is enforced
        across the entire scan loop; any block that would start after the
        deadline is abandoned and the loop exits early with fail-safe WARN
        (raises ScannerError("budget_exceeded")).

        Returns (merged_findings, scanner_name_string).
        Raises ScannerError if any block scan fails or the total budget expires.
        """
        all_findings: list[dict] = []
        scanner_name = "semgrep+bandit"

        deadline = time.monotonic() + MAX_TOTAL_SCAN_SECONDS

        for block in extraction.blocks:
            if time.monotonic() >= deadline:
                # Total budget exceeded: stop scanning remaining blocks and
                # degrade to fail-safe WARN (never silently PASS unscanned blocks).
                log.warning(
                    "code_scan.total_budget_exceeded",
                    max_total_scan_seconds=MAX_TOTAL_SCAN_SECONDS,
                    blocks_remaining=len(extraction.blocks),
                )
                raise ScannerError("budget", "scan_budget_exceeded")
            block_findings = scan_block(block.content, block.language)
            all_findings.extend(block_findings)

        return all_findings, scanner_name

    async def _handle_scanner_error(self, context: Any, exc: ScannerError) -> DetectorResult:
        """Emit code_scan_error and return fail-safe PASS (WARN posture)."""
        event = {
            "event_type": "code_scan_error",
            "action_taken": "logged",
            "scanner": exc.scanner,
            "error_class": exc.error_class,
            # NEVER include the offending code or stack trace (ADR-0019 §6).
        }
        try:
            await context.emit(event, detector_slug=_SLUG)
        except Exception:
            pass  # emit failure must never mask the original scanner error
        log.warning(
            "code_scan.scanner_error",
            scanner=exc.scanner,
            error_class=exc.error_class,
            # No code content logged.
        )
        return DetectorResult(action="pass", event=event)
