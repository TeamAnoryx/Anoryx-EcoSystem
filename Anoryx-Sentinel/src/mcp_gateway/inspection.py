"""Uniform PII/injection/secret inspection of MCP-shaped payload content
(F-026, ADR-0032).

Proves the roadmap's "uniform inspection (PII/injection/secret)" requirement
by reusing the EXACT SAME detector chain /v1/chat/completions already runs
(orchestration.registry.build_default_registry — SecretInboundHook →
InjectionHook → PIIHook pre-request; SecretOutboundHook post-response), not a
reimplementation. Confirmed generic: HookRegistry.run_pre_request /
run_post_response take arbitrary `content: str` — nothing OpenAI-message-
shaped is baked into the hook contract itself (only the FACTORY
build_hook_context() is chat-message-shaped, so this module constructs
HookContext directly instead of going through that factory).

A block or mask decision here emits the SAME audit event types
(pii_blocked / injection_detected / secret_leaked) a chat-completions
request would emit — real, existing, contract-conformant events. No new
event type is introduced.

Honest scope: this inspects a PAYLOAD STRING you already have (e.g. captured
from an MCP tools/call request/response by some future proxy, or fed in for
testing/registration-time preview). It does not itself fetch anything from an
external MCP server — see docs/followups/f-026-mcp-proxy-endpoint.md.
"""

from __future__ import annotations

from gateway.context import TenantContext
from orchestration.context import HookContext
from orchestration.registry import HookRegistry, build_default_registry


async def inspect_mcp_payload(
    content: str,
    *,
    tenant_context: TenantContext,
    request_id: str,
    registry: HookRegistry | None = None,
) -> str:
    """Run MCP payload text through the F-005 pre-request inspection chain.

    Returns the (possibly PII/secret-masked) content on a pass/mask outcome.
    Raises orchestration.exceptions.HookBlockedError if a detector blocks, or
    HookFailSafeError on an unexpected detector exception (both raised by
    HookRegistry._run_hook itself, per ADR-0007 D3 fail-safe — this function
    does not re-catch or re-wrap them, only calls through). The caller must
    treat either as CLAUDE.md #5 "fail-safe: on ANY inspection or policy
    error -> BLOCK", never silently forward the original content.
    """
    hook_registry = registry or build_default_registry()
    ctx = HookContext(
        tenant_context=tenant_context,
        request_id=request_id,
        original_user_content=content,
        phase="pre_request",
    )
    return await hook_registry.run_pre_request(content, ctx)


async def inspect_mcp_response(
    content: str,
    *,
    tenant_context: TenantContext,
    request_id: str,
    registry: HookRegistry | None = None,
) -> str:
    """Run MCP tool-call RESPONSE text through the F-005 post-response chain
    (SecretOutboundHook — never echo a leaked credential back to the agent).
    See inspect_mcp_payload's docstring for the exception contract — identical."""
    hook_registry = registry or build_default_registry()
    ctx = HookContext(
        tenant_context=tenant_context,
        request_id=request_id,
        original_user_content=content,
        phase="post_response",
    )
    return await hook_registry.run_post_response(content, ctx)
