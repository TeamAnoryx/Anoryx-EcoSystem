"""HookRegistry — ordered hook-chain executor (F-005, ADR-0007 §2, D1, D3, D4).

The registry holds two ordered lists:
  pre_request  — hooks run before the upstream proxy call (inbound inspection).
  post_response — hooks run after upstream returns (outbound inspection).

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
    """

    def __init__(
        self,
        pre_request: list[PreRequestHook] | None = None,
        post_response: list[PostResponseHook] | None = None,
    ) -> None:
        self._pre_request: list[PreRequestHook] = list(pre_request or [])
        self._post_response: list[PostResponseHook] = list(post_response or [])

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
    PostResponse: SecretOutboundHook

    Imports are deferred so the registry is buildable without the optional
    heavy dependencies (Presidio/spacy) being installed — disabled detectors
    are simply not included.
    """
    if settings is None:
        from orchestration.config import get_orchestration_settings

        settings = get_orchestration_settings()

    pre_hooks: list[PreRequestHook] = []
    post_hooks: list[PostResponseHook] = []

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

    return HookRegistry(pre_request=pre_hooks, post_response=post_hooks)
