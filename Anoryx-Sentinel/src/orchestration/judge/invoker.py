"""Judge invocation orchestration (F-007, ADR-0010 §2, §4).

`run_judge` is the single entry the injection detector calls AFTER its regex
pre-filter has decided the judge should run.  It owns the policy gate, the routed
provider call, structured-output parsing, cost/billing, and the three fail-safe
audit paths.  It NEVER raises into the detector: every outcome is a typed result,
and every path emits a hash-chained audit event (no silent path — closes the F-004
audit-bypass class).  No path returns "allow" — fallbacks return `JudgeFellBack`
and the detector uses the regex score (R9).

Routing (R5): the judge call goes THROUGH the F-006 provider adapter
(`provider_registry.get(provider).classify_structured(...)`), never a raw SDK.
Policy (D1, R: honor F-008): `evaluate_model_policies` runs at THIS call site on a
tenant session; a denied/unauthorized classifier model is terminal.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import structlog

from gateway.router.exceptions import ProviderError
from orchestration.judge.base import (
    EVENT_DEGRADED,
    EVENT_INVOCATION_FAILED,
    EVENT_JUDGE_BILLING,
    EVENT_UNCONFIGURED,
    JudgeParseError,
    JudgeVerdict,
)
from orchestration.judge.registry import JudgeRegistry

log = structlog.get_logger(__name__)

_DETECTOR_SLUG = "defense"


@dataclass(frozen=True)
class JudgeRan:
    """The judge produced a structured verdict (the detector decides how to use it)."""

    verdict: JudgeVerdict
    judge_model: str
    judge_provider: str


@dataclass(frozen=True)
class JudgeFellBack:
    """The judge did not produce a usable verdict; the detector uses regex only.

    reason ∈ {"unconfigured", "policy_denied", "degraded", "invocation_failed"}.
    """

    reason: str


def _elapsed_ms(started: float) -> int:
    """Milliseconds since a monotonic start, clamped to int."""
    return int((time.monotonic() - started) * 1000)


def _billing_event(
    *,
    preset: str,
    provider: str,
    model: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: int,
    outcome: str,
) -> dict[str, Any]:
    """Build a judge_billing_event payload (envelope stamped by HookContext.emit)."""
    from gateway.router.cost import estimate_from_tokens

    cost = estimate_from_tokens(provider, model, tokens_in, tokens_out)
    # Field names are column-aligned (events_audit_log): judge_provider →
    # selected_provider, prompt/completion tokens → tokens_in/tokens_out, outcome →
    # judge_outcome. These reuse existing audit columns (ADR-0010 §8).
    return {
        "event_type": EVENT_JUDGE_BILLING,
        "action_taken": "logged",
        "judge_preset": preset,
        "judge_model": model,
        "selected_provider": provider,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "cost_estimate_cents": round(float(cost), 6),
        "latency_ms": latency_ms,
        "judge_outcome": outcome,
    }


def _classifier_event(event_type: str, reason: str) -> dict[str, Any]:
    """Build a classifier_unconfigured / classifier_degraded / ..._invocation_failed payload.

    `reason` is column-aligned as `classifier_reason` (events_audit_log, ADR-0010 §8).
    """
    return {"event_type": event_type, "action_taken": "logged", "classifier_reason": reason}


async def _emit_billed_fallback(
    context: Any,
    *,
    classifier_event: str,
    reason: str,
    preset: str,
    provider: str,
    model: str,
    latency_ms: int,
    outcome: str,
) -> None:
    """Emit the classifier_* event AND a judge_billing_event for a billed fallback.

    Used for paths where a judge model was resolved (policy_denied / degraded /
    invocation_failed). Both events are hash-chained — no silent path.
    """
    await context.emit(_classifier_event(classifier_event, reason), detector_slug=_DETECTOR_SLUG)
    await context.emit(
        _billing_event(
            preset=preset,
            provider=provider,
            model=model,
            tokens_in=0,
            tokens_out=0,
            latency_ms=latency_ms,
            outcome=outcome,
        ),
        detector_slug=_DETECTOR_SLUG,
    )


async def _model_authorized(context: Any, judge_model: str) -> bool:
    """Return True if F-008 model policy permits the classifier model for this scope.

    Reads on a tenant session (RLS, R13).  A ModelDeny (or allow-list that excludes
    the classifier model) → False → the detector treats it as unconfigured (the
    tenant has not authorized their configured classifier).  Any infra error →
    False (fail-safe: do not invoke the judge on an unverifiable policy state).
    """
    from persistence.database import get_tenant_session
    from policy.enforcement import ModelDeny, evaluate_model_policies, scope_from_context

    scope = scope_from_context(context.tenant_context)
    try:
        async with get_tenant_session(context.tenant_context.tenant_id) as session:
            async with session.begin():
                decision = await evaluate_model_policies(session, scope, judge_model)
        return not isinstance(decision, ModelDeny)
    except Exception:
        log.error(
            "orchestration.judge.policy_eval_error", request_id=getattr(context, "request_id", "?")
        )
        return False


async def run_judge(
    *,
    scan_text: str,
    preset: str | None,
    context: Any,
    provider_registry: Any,
    judge_timeout_s: float,
    request_budget_s: float,
) -> JudgeRan | JudgeFellBack:
    """Invoke the configured judge through the F-006 provider layer; fail safe to regex."""
    adapter = JudgeRegistry.resolve(preset)
    if adapter is None:
        await context.emit(
            _classifier_event(EVENT_UNCONFIGURED, "no_preset"), detector_slug=_DETECTOR_SLUG
        )
        return JudgeFellBack("unconfigured")

    provider, model = adapter.provider, adapter.model

    # Policy gate at the judge call site (D1 / honor F-008).
    if not await _model_authorized(context, model):
        await _emit_billed_fallback(
            context,
            classifier_event=EVENT_UNCONFIGURED,
            reason="model_not_authorized",
            preset=preset,
            provider=provider,
            model=model,
            latency_ms=0,
            outcome="policy_denied",
        )
        return JudgeFellBack("policy_denied")

    provider_adapter = provider_registry.get(provider) if provider_registry is not None else None
    if provider_adapter is None:
        # Preset's provider has no configured credential → unconfigured (do NOT
        # substitute a different provider — D1).
        await context.emit(
            _classifier_event(EVENT_UNCONFIGURED, "provider_unavailable"),
            detector_slug=_DETECTOR_SLUG,
        )
        return JudgeFellBack("unconfigured")

    # Hot-path budget: cap the judge at judge_timeout_s, never exceeding the
    # request's remaining wall-clock (R: F-006 stream-cost anti-pattern).
    from gateway.router.context import RoutingContext

    budget = max(0.0, min(judge_timeout_s, request_budget_s))
    ctx = RoutingContext(
        request_id=getattr(context, "request_id", "judge"),
        resolved_provider=provider,
        resolved_model=model,
        remaining_budget=budget,
    )

    started = time.monotonic()
    try:
        verdict, tokens_in, tokens_out = await adapter.classify(
            scan_text, provider_adapter=provider_adapter, ctx=ctx
        )
    except JudgeParseError:
        await _emit_billed_fallback(
            context,
            classifier_event=EVENT_INVOCATION_FAILED,
            reason="invalid_structured_output",
            preset=preset,
            provider=provider,
            model=model,
            latency_ms=_elapsed_ms(started),
            outcome="failed",
        )
        return JudgeFellBack("invocation_failed")
    except ProviderError as exc:
        # kind="parse" → the provider returned no structured output → invocation_failed.
        # Any other kind (transport / auth / rate-limit) → degraded. Both → regex (R9).
        if exc.kind == "parse":
            await _emit_billed_fallback(
                context,
                classifier_event=EVENT_INVOCATION_FAILED,
                reason="invalid_structured_output",
                preset=preset,
                provider=provider,
                model=model,
                latency_ms=_elapsed_ms(started),
                outcome="failed",
            )
            return JudgeFellBack("invocation_failed")
        log.error(
            "orchestration.judge.degraded",
            request_id=getattr(context, "request_id", "?"),
            provider=provider,
            kind=exc.kind,
        )
        await _emit_billed_fallback(
            context,
            classifier_event=EVENT_DEGRADED,
            reason="judge_call_failed",
            preset=preset,
            provider=provider,
            model=model,
            latency_ms=_elapsed_ms(started),
            outcome="degraded",
        )
        return JudgeFellBack("degraded")
    except Exception as exc:
        # Any other failure (timeout, unexpected) → degraded → regex (R9). Never "allow".
        # NOTE: asyncio.CancelledError is a BaseException (not Exception), so it is
        # intentionally NOT caught here — request cancellation must propagate so the
        # task is cancelled cleanly rather than being masked as a degraded judge call.
        # error_type carries the class name only (no exception value → no content/PII).
        log.error(
            "orchestration.judge.degraded",
            request_id=getattr(context, "request_id", "?"),
            provider=provider,
            error_type=type(exc).__name__,
        )
        await _emit_billed_fallback(
            context,
            classifier_event=EVENT_DEGRADED,
            reason="judge_call_failed",
            preset=preset,
            provider=provider,
            model=model,
            latency_ms=_elapsed_ms(started),
            outcome="degraded",
        )
        return JudgeFellBack("degraded")

    await context.emit(
        _billing_event(
            preset=preset,
            provider=provider,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=_elapsed_ms(started),
            outcome="verdict",
        ),
        detector_slug=_DETECTOR_SLUG,
    )
    return JudgeRan(verdict=verdict, judge_model=model, judge_provider=provider)
