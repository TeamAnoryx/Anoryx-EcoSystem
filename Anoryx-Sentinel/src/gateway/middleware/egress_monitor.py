"""Shadow-AI egress monitor (F-007, ADR-0010 §5).

Sentinel's outbound provider calls go through httpx clients (the shared OpenAI
client and the dedicated Anthropic client) and aioboto3 (Bedrock). An ASGI
middleware sees only INBOUND requests, so the egress observer is an httpx
`request` event-hook registered on those clients.

On each outbound request the hook resolves the destination host → provider and,
if that provider is NOT in the current request's tenant allow-list, emits a
`shadow_ai_detected_outbound` event. It DETECTS + AUDITS only — it never blocks
the call (blocking is a future F-019 concern), and it NEVER raises into the
provider call (a monitor failure must not break user traffic).

Honest scope (ADR-0010 §12.1): this covers egress through Sentinel's OWN httpx
clients to the well-known provider hosts. It does NOT cover Bedrock/aioboto3
(deferred — docs/followups/bedrock-egress-monitoring.md), custom proxy base_urls
that do not match the host table, or traffic that bypasses Sentinel entirely
(network-layer, out of scope).
"""

from __future__ import annotations

import re

import httpx
import structlog

from gateway.context import EgressContext, TenantContext, current_egress_context

log = structlog.get_logger(__name__)

# Well-known provider hosts → provider name (ADR-0010 §5 host table).
_EXACT_HOST_PROVIDER: dict[str, str] = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
}
# Region-shaped Bedrock endpoints only (e.g. bedrock-runtime.us-east-1.amazonaws.com),
# so arbitrary "bedrock.<anything>.amazonaws.com" hosts are NOT false-positived.
# NB: Bedrock egress actually flows through aioboto3, not these httpx clients, so
# this classification is for completeness — the hook never observes Bedrock traffic
# (documented gap, ADR-0010 §12.1).
_BEDROCK_RE = re.compile(
    r"^bedrock(-runtime)?\.[a-z]{2}-[a-z]+-\d+\.amazonaws\.com$", re.IGNORECASE
)


def resolve_provider(host: str | None) -> str | None:
    """Map an outbound host to a provider name, or None if it is not a tracked host."""
    if not host:
        return None
    h = host.lower()
    if h in _EXACT_HOST_PROVIDER:
        return _EXACT_HOST_PROVIDER[h]
    if _BEDROCK_RE.search(h):
        return "bedrock"
    return None


async def egress_request_hook(request: httpx.Request) -> None:
    """httpx 'request' event-hook: flag egress to a disallowed provider.

    Reads the per-request EgressContext from the contextvar. If the outbound host
    resolves to a provider NOT in the tenant's allow-list, emits
    shadow_ai_detected_outbound. Swallows ALL errors — the monitor must never break
    the outbound provider call (defense-in-depth, not a blocking gate).
    """
    try:
        egress = current_egress_context.get()
        if egress is None:
            return
        provider = resolve_provider(request.url.host)
        if provider is None or provider in egress.allowed_providers:
            return  # untracked host, or an allowed provider → silent
        # request.url.host excludes the port; non-standard ports / custom proxy hosts
        # are not in the host table and resolve to None above (documented limitation,
        # ADR-0010 §12.1). httpx separates path from query, so no query string rides on
        # `path`; emit_shadow_ai_outbound_event sanitizes the endpoint regardless (D7).
        endpoint = f"{request.url.host}{request.url.path}"

        from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_outbound_event

        await emit_shadow_ai_outbound_event(egress=egress, provider=provider, endpoint=endpoint)
    except Exception:
        log.error("egress_monitor.hook_error")  # never propagate into the provider call


async def _resolve_allowed_providers(tenant_context: TenantContext) -> list[str]:
    """Read the tenant's allowed providers on a tenant session (RLS, R13)."""
    from persistence.database import get_tenant_session
    from persistence.repositories.tenant_routing_policy_repository import (
        TenantRoutingPolicyRepository,
    )

    async with get_tenant_session(tenant_context.tenant_id) as session:
        async with session.begin():
            policy = await TenantRoutingPolicyRepository(session).get_for_tenant(
                tenant_context.tenant_id, caller_tenant_id=tenant_context.tenant_id
            )
    return list(policy.allowed_providers)


async def bind_egress_context(tenant_context: TenantContext, request_id: str) -> None:
    """Bind the per-request EgressContext so the outbound hook can flag egress.

    Resolves the tenant's allowed providers once and stores the binding on the
    contextvar (task-local). Called by the chat-completions handler after the
    tenant context is resolved.
    """
    allowed = await _resolve_allowed_providers(tenant_context)
    current_egress_context.set(
        EgressContext(
            tenant_context=tenant_context,
            request_id=request_id,
            allowed_providers=tuple(allowed),
        )
    )
