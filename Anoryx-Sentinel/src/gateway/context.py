"""Request-scoped tenant context for the gateway (F-004).

TenantContext holds the four server-resolved stable IDs from the virtual_api_keys row.
It is built fresh per request and stored in request.state — NEVER reused across
requests (ADR-0006 Decision 4, threat #10 session/state leakage).

The four IDs are ALWAYS the server-resolved values. Client-supplied headers are
cross-checked but never become the source of truth.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Immutable, request-scoped, server-resolved tenant context.

    Built by tenant_context middleware from the virtual_api_keys row returned
    by authentication. The four IDs are the authoritative source for all
    downstream processing: rate limiting, audit, usage events, upstream proxy.

    virtual_key_id: the key_id from the virtual_api_keys row (used as the
    rate-limit key — never used as a tenant identifier).
    """

    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    virtual_key_id: str
    # Model is not part of context; it comes from the request body.


@dataclass(frozen=True, slots=True)
class EgressContext:
    """Per-request egress-monitoring binding (F-007, ADR-0010 §5).

    Carries the tenant identity needed to attribute a shadow_ai_detected_outbound
    audit event PLUS the tenant's allowed providers — Affu's "current_allowed_providers"
    binding, extended with identity so the outbound httpx hook can emit a properly
    attributed, RLS-correct, hash-chained event. Bound by the chat-completions handler
    once the tenant context + routing policy are resolved.
    """

    tenant_context: TenantContext
    request_id: str
    allowed_providers: tuple[str, ...]


# Set by the chat-completions handler (request task) so the outbound httpx event
# hook can read the current tenant's allowed providers + identity. Task-local:
# a fresh request task sees the default (None); Starlette iterates the streaming
# response body in the same request task, so the binding covers both paths.
current_egress_context: ContextVar[EgressContext | None] = ContextVar(
    "current_egress_context", default=None
)
