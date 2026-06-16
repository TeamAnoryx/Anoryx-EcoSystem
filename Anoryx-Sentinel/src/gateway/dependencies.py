"""FastAPI dependency-injection helpers for the gateway (F-004).

Provides typed DI for:
- GatewaySettings singleton
- Tenant context extracted from request.state (set by middleware)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from gateway.config import GatewaySettings, get_settings
from gateway.context import TenantContext


def _get_gateway_settings() -> GatewaySettings:
    return get_settings()


SettingsDep = Annotated[GatewaySettings, Depends(_get_gateway_settings)]


def _get_tenant_context(request: Request) -> TenantContext:
    """Return the request-scoped TenantContext set by tenant_context middleware.

    Raises RuntimeError if the middleware did not run (should never happen in
    the fully-wired app — indicates a route bypassing the middleware stack).
    The four IDs are server-resolved from the virtual_api_keys row; never
    from client-supplied headers.
    """
    ctx: TenantContext | None = getattr(request.state, "tenant_context", None)
    if ctx is None:
        raise RuntimeError(
            "tenant_context not set on request.state — middleware may not be wired"
        )
    return ctx


TenantContextDep = Annotated[TenantContext, Depends(_get_tenant_context)]
