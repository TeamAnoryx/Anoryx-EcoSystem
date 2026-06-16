"""Tenant context middleware (ADR-0006 pipeline step 3 + 5 combined).

Step 3 (header presence/format gate):
  Validates all four ID headers are present, well-formed, and ≤ 64 chars.
  Missing / malformed / overlong → 400 missing_required_header.
  This runs BEFORE auth (cheap gate that costs no DB round-trip).

Step 5 (ID cross-check + tenant context resolution):
  After auth has resolved the server-side IDs from the virtual_api_keys row,
  compare each header value against the corresponding resolved ID.
  Any mismatch → 403 id_context_mismatch.
  Build the request-scoped TenantContext from the RESOLVED values (not headers).
  Store it on request.state.tenant_context.

The four resolved IDs are NEVER sourced from headers. Headers are cross-check
ONLY (ADR-0006 Decision 4). The TenantContext stored on request.state carries
only server-resolved values — it is what reaches the audit trail.

TenantContext is built fresh each request and lives only in request.state.
It is NEVER shared across requests (threat #10 session/state leakage).

MED-3: Does NOT generate its own request_id. Reads the canonical
request.state.request_id set by TerminalAuditMiddleware (outermost layer).

NOTE: Returns JSONResponse directly on error (does not raise GatewayError
through the middleware stack — see auth.py module docstring for reason).
"""

from __future__ import annotations

import re
import uuid

import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from gateway.context import TenantContext
from gateway.exceptions import ERROR_TABLE, GatewayError

log = structlog.get_logger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_AGENT_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

_AUTH_EXEMPT_PATHS = frozenset({"/health", "/ready"})

_MAX_HEADER_LEN = 64


def _get_request_id(request: Request) -> str:
    """Return the canonical request_id from state, or generate a fallback."""
    rid = getattr(request.state, "request_id", None)
    if rid:
        return rid
    rid = "req-" + uuid.uuid4().hex[:32]
    request.state.request_id = rid
    return rid


def _error_json(error_code: str, request_id: str) -> JSONResponse:
    message, status = ERROR_TABLE[error_code]
    return JSONResponse(
        content={"error_code": error_code, "message": message, "request_id": request_id},
        status_code=status,
        headers={"X-Request-Id": request_id},
    )


def _validate_uuid_header(value: str | None) -> bool:
    """Return True if valid UUID header; False otherwise."""
    if not value:
        return False
    if len(value) > _MAX_HEADER_LEN:
        return False
    return bool(_UUID_RE.match(value))


def _validate_agent_header(value: str | None) -> bool:
    """Return True if valid agent-id slug; False otherwise."""
    if not value:
        return False
    if len(value) > _MAX_HEADER_LEN:
        return False
    return bool(_AGENT_SLUG_RE.match(value))


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Header-validation gate (step 3) — runs before auth on all /v1 paths.

    Validates format of all four ID headers. Returns 400 if any is missing,
    malformed, or overlong. Stores validated header values on request.state
    for the ID cross-check performed in resolve_tenant_context().

    The ID cross-check (step 5) is performed inside the route handler via
    resolve_tenant_context(), which runs after auth has set virtual_key_row.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        # MED-3: use the single canonical request_id from the outermost wrapper.
        request_id = _get_request_id(request)

        h_tenant = request.headers.get("x-anoryx-tenant-id")
        h_team = request.headers.get("x-anoryx-team-id")
        h_project = request.headers.get("x-anoryx-project-id")
        h_agent = request.headers.get("x-anoryx-agent-id")

        if not _validate_uuid_header(h_tenant):
            return _error_json("missing_required_header", request_id)
        if not _validate_uuid_header(h_team):
            return _error_json("missing_required_header", request_id)
        if not _validate_uuid_header(h_project):
            return _error_json("missing_required_header", request_id)
        if not _validate_agent_header(h_agent):
            return _error_json("missing_required_header", request_id)

        # Store validated header values for cross-check post-auth.
        request.state.header_tenant_id = h_tenant
        request.state.header_team_id = h_team
        request.state.header_project_id = h_project
        request.state.header_agent_id = h_agent

        return await call_next(request)


def resolve_tenant_context(request: Request) -> TenantContext:
    """Perform the ID cross-check (step 5) and build TenantContext.

    Called from route handlers after auth middleware has set virtual_key_row.
    Compares each header value against the server-resolved ID from the key row.
    Any mismatch → 403 id_context_mismatch (ADR-0006 Decision 4).

    The returned TenantContext carries ONLY the server-resolved values.
    It is stored on request.state.tenant_context for downstream use.
    """
    key_row = getattr(request.state, "virtual_key_row", None)
    if key_row is None:
        raise GatewayError("internal_error")

    resolved_tenant_id: str = key_row.tenant_id
    resolved_team_id: str = key_row.team_id
    resolved_project_id: str = key_row.project_id
    resolved_agent_id: str = key_row.agent_id

    h_tenant = getattr(request.state, "header_tenant_id", None)
    h_team = getattr(request.state, "header_team_id", None)
    h_project = getattr(request.state, "header_project_id", None)
    h_agent = getattr(request.state, "header_agent_id", None)

    # Cross-check: header must match server-resolved ID exactly (case-insensitive for UUIDs).
    if (h_tenant or "").lower() != resolved_tenant_id.lower():
        log.info("id_context_mismatch", field="tenant_id")
        raise GatewayError("id_context_mismatch")
    if (h_team or "").lower() != resolved_team_id.lower():
        log.info("id_context_mismatch", field="team_id")
        raise GatewayError("id_context_mismatch")
    if (h_project or "").lower() != resolved_project_id.lower():
        log.info("id_context_mismatch", field="project_id")
        raise GatewayError("id_context_mismatch")
    # agent_id is a slug — already lowercase by contract; compare exactly.
    if (h_agent or "") != resolved_agent_id:
        log.info("id_context_mismatch", field="agent_id")
        raise GatewayError("id_context_mismatch")

    ctx = TenantContext(
        tenant_id=resolved_tenant_id,
        team_id=resolved_team_id,
        project_id=resolved_project_id,
        agent_id=resolved_agent_id,
        virtual_key_id=key_row.key_id,
    )
    request.state.tenant_context = ctx
    return ctx
