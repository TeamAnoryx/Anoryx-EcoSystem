"""Admin authentication primitive (mirrors ``Anoryx-Sentinel/src/admin/auth.py`` R2/R5/R8).

FAIL-CLOSED: the presented bearer must exact-match the configured
``DELTA_ADMIN_TOKEN`` under a constant-time compare, or the request is 401. No tenant
fallback, no partial match, no tenant data leaked in the response.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from .config import ADMIN_PRINCIPAL, AllocationAdminSettings

_UNAUTHORIZED = 401


async def require_admin(request: Request) -> str:
    """FastAPI dependency authorizing an admin (operator) request.

    Reads the resolved settings from ``request.app.state.allocation_admin_settings``
    (set fail-loud at app construction — see :mod:`.app`). Returns the principal slug
    on success and records ``request.state.admin_principal``; raises
    ``HTTPException(401)`` on any failure (missing header, wrong scheme, wrong token).
    """
    settings: AllocationAdminSettings = request.app.state.allocation_admin_settings

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    presented = auth_header[len("Bearer ") :]
    if not presented or not hmac.compare_digest(presented, settings.admin_token):
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    request.state.admin_principal = ADMIN_PRINCIPAL
    return ADMIN_PRINCIPAL
