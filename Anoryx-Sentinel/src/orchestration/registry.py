"""HookRegistry — ordered hook-chain executor (F-005, ADR-0007 §2, D1, D3, D4).

The registry holds two ordered lists:
  pre_request  — hooks run before the upstream proxy call (inbound inspection).
  post_response — hooks run after upstream returns (outbound inspection).

And one dedicated single-detector slot:
  _code_scan_detector — CodeScanDetector (F-016, ADR-0019 §3-§5, §8, §11).
      Excluded from the post_response windowed chain because it runs a
      Semgrep/Bandit subprocess that requires the COMPLETE response text and
      MUST NOT be invoked per-chunk.  Gateway-core calls run_code_scan()
      explicitly at two distinct call sites:
        • Non-stream  → run_code_scan(full_body, ctx) BEFORE JSONResponse is
          built; a "block" result raises HookBlockedError so the caller can
          return 403 policy_blocked (same error handling as run_post_response).
        • Stream      → run_code_scan(accumulated_full_text, ctx) AFTER the
          stream generator's finally block completes; emit-only (the detector
          itself returns action="pass" + block_suppressed_by_streaming when
          ctx._is_stream is True, so no HookBlockedError is raised).

Execution rules
---------------
1. Hooks run in the list order (fixed by D1; the registry enforces the ordering).
2. On a "block" result → SHORT-CIRCUIT: remaining hooks are skipped.
3. On a "mask" result  → the modified_payload is forwarded to the next hook and
   eventually replaces the outgoing content.
4. On an unexpected exception inside any hook → FAIL-SAFE BLOCK (D3): the
   exception is caught, wrapped in HookFailSafeError, and re-raised.  The
   request is NEVER passed upstream on inspection failure.
5. EVENTS_PER_DETECTOR_CAP is enforced by HookContext.emit() (D4).
   The action is always applied; only event volume is coalesced.

DI-injectable
-------------
HookRegistry is injected into the route handler rather than imported as a
module global, so tests can stub the registry with recording/raising/empty hooks.
"""

from __future__ import annotations

from typing import Any

import structlog

from orchestration.exceptions import HookBlockedError, HookFailSafeError
from orchestration.hooks.base import DetectorResult, PostResponseHook, PreRequestHook

log = structlog.get_logger(__name__)


class HookRegistry:
    """Ordered, DI-injectable hook-chain executor.

    Parameters
    ----------
    pre_request:
        Ordered list of PreRequestHook instances (ADR-0007 D1 order:
        SecretInbound → Injection → PII).
    post_response:
        Ordered list of PostResponseHook instances (D1 order: SecretOutbound).
    code_scan_detector:
        Optional CodeScanDetector instance (F-016, ADR-0019).  Stored in a
        dedicated slot — NOT appended to post_response — because it runs a
        subprocess over the COMPLETE response text and must never be called
        per-chunk in the streaming sliding-window loop.  Access via the
        ``code_scan_detector`` property; invoke via ``run_code_scan()``.
    """

    def __init__(
        self,
        pre_request: list[PreRequestHook] | None = None,
        post_response: list[PostResponseHook] | None = None,
        code_scan_detector: PostResponseHook | None = None,
    ) -> None:
        self._pre_request: list[PreRequestHook] = list(pre_request or [])
        self._post_response: list[PostResponseHook] = list(post_response or [])
        self._code_scan_detector: PostResponseHook | None = code_scan_detector

    # -------------------------------------------------------------------------
    # Code-scan accessor
    # -------------------------------------------------------------------------

    @property
    def code_scan_detector(self) -> PostResponseHook | None:
        """The registered CodeScanDetector, or None if not configured.

        Gateway-core uses this for introspection / conditional call-site logic.
        """
        return self._code_scan_detector

    # -------------------------------------------------------------------------
    # Pre-request chain
    # -------------------------------------------------------------------------

    async def run_pre_request(self, content: str, context: Any) -> str:
        """Run all PreRequestHooks in order.  Returns the (possibly mutated) content.

        Short-circuits on the first "block" result by raising HookBlockedError.
        Wraps unexpected hook exceptions in HookFailSafeError (D3).

        The returned string is the content after all masking hooks have run —
        this is what gets forwarded to the upstream model.
        """
        current_content = content

        for hook in self._pre_request:
            result = await self._run_hook(hook, current_content, context)

            if result.action == "block":
                log.info(
                    "orchestration.pre_request.blocked",
                    detector=hook.detector_slug,
                    request_id=getattr(context, "request_id", "unknown"),
                )
                # Emit the event (best-effort; emit() never raises).
                if result.event is not None:
                    await context.emit(result.event, detector_slug=hook.detector_slug)
                raise HookBlockedError(
                    error_code="policy_blocked",
                    event=result.event,
                )

            if result.action == "mask":
                log.info(
                    "orchestration.pre_request.masked",
                    detector=hook.detector_slug,
                    request_id=getattr(context, "request_id", "unknown"),
                )
                if result.event is not None:
                    await context.emit(result.event, detector_slug=hook.detector_slug)
                if result.modified_payload is not None:
                    current_content = result.modified_payload

            elif result.action == "pass" and result.event is not None:
                # "pass" with an event: emit the event (e.g. injection_detected
                # action_taken="logged" — detection recorded but request continues).
                await context.emit(result.event, detector_slug=hook.detector_slug)

        return current_content

    # -------------------------------------------------------------------------
    # Post-response chain
    # -------------------------------------------------------------------------

    async def run_post_response(self, content: str, context: Any) -> str:
        """Run all PostResponseHooks in order.  Returns the (possibly redacted) content.

        Short-circuits on the first "block" result by raising HookBlockedError.
        Wraps unexpected hook exceptions in HookFailSafeError (D3).
        """
        current_content = content

        for hook in self._post_response:
            result = await self._run_hook(hook, current_content, context)

            if result.action == "block":
                log.info(
                    "orchestration.post_response.blocked",
                    detector=hook.detector_slug,
                    request_id=getattr(context, "request_id", "unknown"),
                )
                if result.event is not None:
                    await context.emit(result.event, detector_slug=hook.detector_slug)
                raise HookBlockedError(
                    error_code="policy_blocked",
                    event=result.event,
                )

            if result.action == "mask":
                log.info(
                    "orchestration.post_response.masked",
                    detector=hook.detector_slug,
                    request_id=getattr(context, "request_id", "unknown"),
                )
                if result.event is not None:
                    if result.defer_emit:
                        # HIGH-B: caller must emit AFTER validating the redacted
                        # body is valid JSON.  Store for the handler to pick up.
                        context._deferred_event = (result.event, hook.detector_slug)
                    else:
                        await context.emit(result.event, detector_slug=hook.detector_slug)
                if result.modified_payload is not None:
                    current_content = result.modified_payload

            elif result.action == "pass" and result.event is not None:
                await context.emit(result.event, detector_slug=hook.detector_slug)

        return current_content

    # -------------------------------------------------------------------------
    # Code-scan phase (F-016 / ADR-0019 §3-§5, §8, §11)
    # -------------------------------------------------------------------------

    async def run_code_scan(self, content: str, context: Any) -> str:
        """Run the CodeScanDetector exactly once on the complete response text.

        This method MUST be called by gateway-core at two explicit call sites
        (never inside the per-chunk streaming loop):

        1. NON-STREAMED — called after ``run_post_response`` completes, before
           the JSONResponse is built.  ``context._is_stream`` must be False.
           If the detector returns action="block", this method raises
           ``HookBlockedError(error_code="policy_blocked")`` so the caller
           converts it to 403 policy_blocked — identical error handling to
           ``run_post_response``.

        2. STREAMED — called once after the stream generator's finally block,
           on the complete accumulated text.  ``context._is_stream`` must be
           True.  The CodeScanDetector itself detects the stream flag and
           returns action="pass" with ``block_suppressed_by_streaming=True``
           when the findings would otherwise warrant a block (ADR-0019 §4 /
           Fork 1 honesty).  No ``HookBlockedError`` is raised in this path.

        Returns the content string unchanged (code-scan never masks, only
        blocks or passes, so the caller does not need the return value —
        it is provided for API symmetry with ``run_post_response``).

        If ``_code_scan_detector`` is None (not configured), returns content
        immediately as a no-op.

        Unexpected exceptions are wrapped in ``HookFailSafeError`` (D3),
        preserving fail-safe semantics: an unexpected scanner failure never
        silently passes the response.
        """
        if self._code_scan_detector is None:
            return content

        result = await self._run_hook(self._code_scan_detector, content, context)

        if result.action == "block":
            log.info(
                "orchestration.code_scan.blocked",
                detector=self._code_scan_detector.detector_slug,
                request_id=getattr(context, "request_id", "unknown"),
            )
            # DO NOT re-emit here.  CodeScanDetector.inspect() already called
            # ctx.emit() for every verdict path (PASS / WARN / BLOCK) before
            # returning its DetectorResult — re-emitting would write a second
            # code_scan_blocked row to events_audit_log and corrupt the
            # append-only hash chain.  This matches the "pass" comment below.
            raise HookBlockedError(
                error_code="policy_blocked",
                event=result.event,
            )

        # action == "pass": event was already emitted inside inspect() by the
        # detector itself (CodeScanDetector calls ctx.emit() directly — see
        # detector.py).  No double-emit here.
        return content

    # -------------------------------------------------------------------------
    # Internal: safe single-hook executor (D3 fail-safe wrapper)
    # -------------------------------------------------------------------------

    async def _run_hook(self, hook: Any, content: str, context: Any) -> DetectorResult:
        """Execute a single hook, wrapping unexpected exceptions as HookFailSafeError.

        Per ADR-0007 D3: any unexpected exception inside a hook → FAIL-SAFE BLOCK.
        The executor catches the exception, logs it (no content — PII risk), and
        re-raises as HookFailSafeError.  The gateway handler converts this to
        500 internal_error and does NOT forward the request upstream.

        HookBlockedError and HookFailSafeError from nested calls are re-raised
        unwrapped so the caller's control flow is correct.
        """
        try:
            return await hook.inspect(content, context)
        except (HookBlockedError, HookFailSafeError):
            # Already a known terminal exception — propagate as-is.
            raise
        except Exception as exc:
            log.error(
                "orchestration.hook_unexpected_exception",
                detector=getattr(hook, "detector_slug", "unknown"),
                request_id=getattr(context, "request_id", "unknown"),
                exc_type=type(exc).__name__,
                # Never log exc value — may contain PII or secret material.
            )
            raise HookFailSafeError(exc) from exc


def build_default_registry(settings: Any | None = None) -> HookRegistry:
    """Build the default production HookRegistry from OrchestrationSettings.

    Hook order (ADR-0007 D1):
    PreRequest:  SecretInboundHook → InjectionHook → PIIHook
    PostResponse (windowed chain): SecretOutboundHook
    CodeScan (dedicated slot, NOT in windowed chain): CodeScanDetector

    CodeScanDetector is intentionally excluded from the post_response list.
    It runs a Semgrep/Bandit subprocess on the COMPLETE response text and
    must never fire per-chunk inside the 8 KiB streaming window.  Gateway-core
    calls registry.run_code_scan(full_text, ctx) explicitly at two dedicated
    call sites — once after run_post_response on non-streamed bodies (BLOCK-
    capable), and once after stream completion on accumulated text (emit-only).
    See HookRegistry.run_code_scan() docstring for the full contract.

    Imports are deferred so the registry is buildable without the optional
    heavy dependencies (Presidio/spacy/semgrep/bandit) being installed —
    disabled detectors are simply not included.
    """
    if settings is None:
        from orchestration.config import get_orchestration_settings

        settings = get_orchestration_settings()

    pre_hooks: list[PreRequestHook] = []
    post_hooks: list[PostResponseHook] = []
    code_scan: PostResponseHook | None = None

    if settings.secret_detection_enabled:
        from orchestration.detectors.secret_detector import (
            SecretInboundHook,
            SecretOutboundHook,
        )

        pre_hooks.append(SecretInboundHook(settings=settings))
        post_hooks.append(SecretOutboundHook(settings=settings))

    if settings.injection_detection_enabled:
        from orchestration.detectors.injection_detector import InjectionHook

        pre_hooks.append(InjectionHook(settings=settings))

    if settings.pii_detection_enabled:
        from orchestration.detectors.pii_detector import PIIHook

        pre_hooks.append(PIIHook(settings=settings))

    # F-016: CodeScanDetector registered in the dedicated code_scan slot.
    # Default-OFF (per-tenant opt-in via code_scan policy — ADR-0019 Fork 4);
    # the detector itself gates on tenant config, so we always register it
    # when the code_scan extra is installed.  A missing extra → ImportError
    # caught here → silently omitted (R9: no regression for deployments
    # without the code-scan optional-dependency extra).
    try:
        from code_scan.detector import CodeScanDetector  # noqa: PLC0415

        code_scan = CodeScanDetector()
    except ImportError:
        pass  # code-scan extra not installed — no-op, not an error

    return HookRegistry(
        pre_request=pre_hooks,
        post_response=post_hooks,
        code_scan_detector=code_scan,
    )
