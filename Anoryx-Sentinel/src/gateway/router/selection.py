"""Router entry point + fallback loop (F-006, ADR-0008 §6 / §7).

route_non_stream / route_stream are invoked from the chat_completions.py L307
seam. They:
  1. Resolve the tenant routing policy (tenant session + RLS, §4) and intersect
     allowed providers with the providers that have credentials (fail-closed, §3).
  2. Walk fallback_order honoring the §6 matrix EXACTLY:
       - retry only on transient / rate_limited (retryable kinds),
       - 401/403 auth TERMINAL (never retried),
       - content_policy 4xx TERMINAL (never retried),
       - bad_request/parse TERMINAL for the attempt,
       - allow-list deny TERMINAL + audit + 403 policy_blocked,
       - cost breach TERMINAL + audit + 403 policy_blocked,
       - exhaustion -> 500 internal_error.
  3. Enforce ONE shared request_timeout_seconds budget across attempts and a
     router_max_fallbacks cap.
  4. Recompute the client-side cost estimate for the ACTUAL resolved
     (provider, model) on EVERY attempt (§7.3).
  5. Emit a routing_decision audit event on EVERY decision (§5.3).

Behavior is identical to today when the tenant resolves to OpenAI with no
fallback: a single OpenAI attempt, one `selected` routing_decision, then the
existing proxy path.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import AsyncIterator

import structlog

from gateway.config import GatewaySettings
from gateway.context import TenantContext
from gateway.exceptions import GatewayError
from gateway.middleware.audit import emit_routing_decision
from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest
from gateway.router.context import RoutingContext
from gateway.router.cost import estimate_pre_request
from gateway.router.exceptions import ProviderError, RoutingBlockedError
from gateway.router.registry import ProviderRegistry

log = structlog.get_logger(__name__)


@dataclass
class StreamRouteResult:
    """Mutable holder threaded into route_stream so the streaming handler can
    enforce the §7.4 stream-time cost ceiling (HIGH-1 remediation).

    route_stream sets these fields once a provider is COMMITTED (after the first
    translated byte, when the `selected` routing_decision is emitted). The chat
    route's _handle_stream chunk loop reads them to recompute a running cost
    estimate vs cost_ceiling_cents and fail-safe BLOCK on breach. All fields stay
    None until commit, so the handler simply skips the check pre-commit.
    """

    resolved_provider: str | None = None
    resolved_model: str | None = None
    cost_ceiling_cents: float | None = None


async def _resolve_policy(tenant_context: TenantContext):
    """Resolve the effective routing policy on a tenant session (RLS, §4)."""
    from persistence.database import get_tenant_session
    from persistence.repositories.tenant_routing_policy_repository import (
        TenantRoutingPolicyRepository,
    )

    async with get_tenant_session(tenant_context.tenant_id) as session:
        async with session.begin():
            repo = TenantRoutingPolicyRepository(session)
            return await repo.get_for_tenant(
                tenant_context.tenant_id,
                caller_tenant_id=tenant_context.tenant_id,
            )


def _effective_chain(
    policy,
    available: set[str],
    settings: GatewaySettings,
) -> list[str]:
    """Compute the ordered attempt chain.

    Intersect fallback_order with allowed_providers and the providers that
    actually have credentials (available). A provider listed by the tenant but
    without a configured key is silently excluded (fail-closed, §3 / §4.2).
    Capped at 1 + router_max_fallbacks total attempts (§6).
    """
    allowed = set(policy.allowed_providers)
    chain = [
        p
        for p in policy.fallback_order
        if p in allowed and p in available
    ]
    # Defensive: ensure we never exceed the configured attempt cap.
    max_attempts = 1 + settings.router_max_fallbacks
    return chain[:max_attempts]


def _reason_for_kind(kind: str) -> str:
    return {
        "transient": "fallback-transient",
        "rate_limited": "fallback-rate-limit",
        "auth": "provider-auth",
        "content_policy": "provider-content-policy",
        "bad_request": "provider-bad-request",
        "parse": "provider-parse",
    }.get(kind, "fallback-transient")


async def _check_allowlist_and_cost(
    *,
    provider: str,
    body: CreateChatCompletionRequest,
    policy,
    tenant_context: TenantContext,
    request_id: str,
    attempt_index: int,
) -> None:
    """Allow-list + pre-request cost checks for ONE candidate (§6 / §7.2).

    Raises RoutingBlockedError on a terminal block (after emitting the audit
    event). Allow-list deny is checked even though _effective_chain already
    filters — this is the explicit, audited TERMINAL the matrix requires for the
    case where the ONLY/last viable provider is the denied one.
    """
    if provider not in set(policy.allowed_providers):
        await emit_routing_decision(
            request_id=request_id,
            tenant_context=tenant_context,
            selected_provider=provider,
            routing_reason="tenant-allowlist",
            outcome="allowlist_denied",
            action_taken="blocked",
            attempt_index=attempt_index,
            requested_model=body.model,
        )
        raise RoutingBlockedError("allowlist", detail=provider)

    if policy.cost_ceiling_cents is not None:
        # Recompute for the ACTUAL resolved provider+model on this attempt (§7.3).
        estimate = estimate_pre_request(body, provider, body.model)
        if estimate > policy.cost_ceiling_cents:
            await emit_routing_decision(
                request_id=request_id,
                tenant_context=tenant_context,
                selected_provider=provider,
                routing_reason="cost-routing",
                outcome="cost_blocked",
                action_taken="blocked",
                attempt_index=attempt_index,
                requested_model=body.model,
            )
            raise RoutingBlockedError("cost", detail=f"{estimate:.4f}>{policy.cost_ceiling_cents}")


async def route_non_stream(
    *,
    validated_body: CreateChatCompletionRequest,
    request_id: str,
    tenant_context: TenantContext,
    registry: ProviderRegistry,
    settings: GatewaySettings,
) -> tuple[ChatCompletionResponse, int, int]:
    """Non-stream router. Returns a TRANSLATED OpenAI-shape response + tokens.

    Raises GatewayError on a terminal wire outcome:
      - policy_blocked (403) for allow-list deny / cost breach,
      - internal_error (500) for auth / content_policy / bad_request / parse /
        exhaustion.
    """
    policy = await _resolve_policy(tenant_context)
    available = registry.available_providers()
    chain = _effective_chain(policy, available, settings)

    if not chain:
        # No viable provider at all (e.g. tenant allows only unconfigured ones).
        await emit_routing_decision(
            request_id=request_id,
            tenant_context=tenant_context,
            selected_provider="openai",
            routing_reason="tenant-allowlist",
            outcome="allowlist_denied",
            action_taken="blocked",
            attempt_index=0,
            requested_model=validated_body.model,
        )
        raise GatewayError("policy_blocked")

    budget_start = time.monotonic()
    last_kind: str | None = None

    for attempt_index, provider in enumerate(chain):
        remaining = settings.request_timeout_seconds - (time.monotonic() - budget_start)
        if remaining <= 0:
            last_kind = "transient"
            break

        # Allow-list + cost (TERMINAL + audit; raises Gateway/RoutingBlocked).
        try:
            await _check_allowlist_and_cost(
                provider=provider,
                body=validated_body,
                policy=policy,
                tenant_context=tenant_context,
                request_id=request_id,
                attempt_index=attempt_index,
            )
        except RoutingBlockedError:
            raise GatewayError("policy_blocked") from None

        adapter = registry.get(provider)
        if adapter is None:  # pragma: no cover - chain already filtered
            continue

        ctx = RoutingContext(
            request_id=request_id,
            resolved_provider=provider,
            resolved_model=validated_body.model,
            remaining_budget=remaining,
            attempt_index=attempt_index,
        )

        try:
            completion, tokens_in, tokens_out = await adapter.complete(validated_body, ctx)
        except ProviderError as exc:
            last_kind = exc.kind
            if exc.is_retryable and attempt_index < len(chain) - 1:
                # Retryable + a next provider exists -> fall over (§6).
                await emit_routing_decision(
                    request_id=request_id,
                    tenant_context=tenant_context,
                    selected_provider=provider,
                    routing_reason=_reason_for_kind(exc.kind),
                    outcome="fallback_attempted",
                    action_taken="failed_over",
                    attempt_index=attempt_index,
                    requested_model=validated_body.model,
                )
                continue
            # TERMINAL (auth/content_policy/bad_request/parse, or last retryable).
            await emit_routing_decision(
                request_id=request_id,
                tenant_context=tenant_context,
                selected_provider=provider,
                routing_reason=_reason_for_kind(exc.kind),
                outcome="exhausted",
                action_taken="blocked",
                attempt_index=attempt_index,
                requested_model=validated_body.model,
            )
            log.error(
                "router_attempt_terminal",
                request_id=request_id,
                provider=provider,
                kind=exc.kind,
                status=exc.status,
                # NEVER log upstream body text (threat #10).
            )
            raise GatewayError("internal_error") from None

        # Success — emit selected, return TRANSLATED OpenAI-shape response.
        await emit_routing_decision(
            request_id=request_id,
            tenant_context=tenant_context,
            selected_provider=provider,
            routing_reason="tenant-allowlist" if policy.is_default else "cost-routing",
            outcome="selected",
            action_taken="routed",
            attempt_index=attempt_index,
            requested_model=validated_body.model,
        )
        return completion, tokens_in, tokens_out

    # Chain exhausted with no success.
    await emit_routing_decision(
        request_id=request_id,
        tenant_context=tenant_context,
        selected_provider=chain[-1],
        routing_reason=_reason_for_kind(last_kind or "transient"),
        outcome="exhausted",
        action_taken="blocked",
        attempt_index=len(chain) - 1,
        requested_model=validated_body.model,
    )
    raise GatewayError("internal_error")


async def route_stream(
    *,
    validated_body: CreateChatCompletionRequest,
    request_id: str,
    tenant_context: TenantContext,
    registry: ProviderRegistry,
    settings: GatewaySettings,
    result: StreamRouteResult | None = None,
) -> AsyncIterator[str]:
    """Stream router. Yields TRANSLATED OpenAI-shape SSE lines.

    HIGH-1: `result` is an optional mutable StreamRouteResult. When a provider is
    COMMITTED (after the first translated byte), route_stream records the resolved
    provider, resolved model, and the tenant cost_ceiling_cents on it so the
    streaming handler can enforce the §7.4 stream-time cost ceiling on the
    accumulating output tokens. The pre-request ceiling check below remains
    unchanged; this only EXPORTS the resolved facts for the running estimate.

    Streaming caveat (ADR-0006 / §6): fallback can only occur BEFORE the first
    byte. We perform all fallback/terminal decisions during connection
    establishment by buffering ONLY the first translated line from each adapter;
    once the first byte is committed, a mid-stream failure follows the inherited
    rule (the adapter emits one event: error frame and closes without [DONE]).

    On a terminal policy/exhaustion outcome before first byte, this generator
    yields a single OpenAI-shape error frame (policy_blocked / internal_error)
    and closes WITHOUT [DONE] — identical framing to _proxy_stream_generator.
    """
    from gateway.exceptions import ERROR_TABLE
    from gateway.routes.chat_completions import _build_sse_error_event

    def _error_frame(code: str) -> str:
        message, _ = ERROR_TABLE[code]
        return _build_sse_error_event(error_code=code, message=message, request_id=request_id)

    policy = await _resolve_policy(tenant_context)
    available = registry.available_providers()
    chain = _effective_chain(policy, available, settings)

    if not chain:
        await emit_routing_decision(
            request_id=request_id,
            tenant_context=tenant_context,
            selected_provider="openai",
            routing_reason="tenant-allowlist",
            outcome="allowlist_denied",
            action_taken="blocked",
            attempt_index=0,
            requested_model=validated_body.model,
        )
        yield _error_frame("policy_blocked")
        return

    budget_start = time.monotonic()
    last_kind: str | None = None

    for attempt_index, provider in enumerate(chain):
        remaining = settings.request_timeout_seconds - (time.monotonic() - budget_start)
        if remaining <= 0:
            last_kind = "transient"
            break

        try:
            await _check_allowlist_and_cost(
                provider=provider,
                body=validated_body,
                policy=policy,
                tenant_context=tenant_context,
                request_id=request_id,
                attempt_index=attempt_index,
            )
        except RoutingBlockedError:
            yield _error_frame("policy_blocked")
            return

        adapter = registry.get(provider)
        if adapter is None:  # pragma: no cover
            continue

        ctx = RoutingContext(
            request_id=request_id,
            resolved_provider=provider,
            resolved_model=validated_body.model,
            remaining_budget=remaining,
            attempt_index=attempt_index,
        )

        gen = adapter.stream(validated_body, ctx)
        try:
            # Pull the first translated line; pre-first-byte failure raises here.
            first_line = await gen.__anext__()
        except StopAsyncIteration:
            first_line = None
        except ProviderError as exc:
            last_kind = exc.kind
            if exc.is_retryable and attempt_index < len(chain) - 1:
                await emit_routing_decision(
                    request_id=request_id,
                    tenant_context=tenant_context,
                    selected_provider=provider,
                    routing_reason=_reason_for_kind(exc.kind),
                    outcome="fallback_attempted",
                    action_taken="failed_over",
                    attempt_index=attempt_index,
                    requested_model=validated_body.model,
                )
                continue
            await emit_routing_decision(
                request_id=request_id,
                tenant_context=tenant_context,
                selected_provider=provider,
                routing_reason=_reason_for_kind(exc.kind),
                outcome="exhausted",
                action_taken="blocked",
                attempt_index=attempt_index,
                requested_model=validated_body.model,
            )
            yield _error_frame("internal_error")
            return

        # First byte established — this provider is committed. Emit selected.
        # HIGH-1: export the committed (provider, model) + tenant ceiling so the
        # streaming handler can enforce the §7.4 running cost ceiling.
        if result is not None:
            result.resolved_provider = provider
            result.resolved_model = validated_body.model
            result.cost_ceiling_cents = policy.cost_ceiling_cents
        await emit_routing_decision(
            request_id=request_id,
            tenant_context=tenant_context,
            selected_provider=provider,
            routing_reason="tenant-allowlist" if policy.is_default else "cost-routing",
            outcome="selected",
            action_taken="routed",
            attempt_index=attempt_index,
            requested_model=validated_body.model,
        )
        if first_line is not None:
            yield first_line
        # Drain the rest of the (already-translated) stream. A mid-stream failure
        # inside the adapter surfaces as its own error frame; we do NOT retry.
        async for line in gen:
            yield line
        return

    # Exhausted before first byte.
    await emit_routing_decision(
        request_id=request_id,
        tenant_context=tenant_context,
        selected_provider=chain[-1],
        routing_reason=_reason_for_kind(last_kind or "transient"),
        outcome="exhausted",
        action_taken="blocked",
        attempt_index=len(chain) - 1,
        requested_model=validated_body.model,
    )
    yield _error_frame("internal_error")
