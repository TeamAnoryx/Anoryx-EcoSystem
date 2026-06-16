"""Authentication middleware (ADR-0006 pipeline step 4).

Extracts the Bearer token from Authorization, resolves it via
VirtualApiKeyRepository.lookup_by_plaintext (constant-time HMAC fingerprint).

AUTH CHICKEN-EGG RESOLUTION (documented per ADR instruction):
  lookup_by_plaintext requires a DB session, but we don't know tenant_id
  until AFTER the lookup (the key row IS what gives us tenant_id). The
  fingerprint query is global (not tenant-filtered) because the fingerprint
  index is unique across all tenants.

  Resolution chosen: use get_privileged_session() for the fingerprint→row
  resolution step ONLY. Rationale: this is an auth resolution analogous to
  chain ops that need global visibility to locate the row before tenant GUC
  is known. The privileged session sees all rows (BYPASSRLS), which is
  exactly what a fingerprint lookup needs. After the row is returned we have
  the resolved tenant_id and all subsequent tenant-scoped reads use
  get_tenant_session(resolved_tenant_id).

  This is NOT widening RLS for tenant data reads. The fingerprint→row step
  is purely an authentication operation (find the key, not tenant data). RLS
  on virtual_api_keys rows is not bypassed for data reads; only the initial
  key-lookup auth step uses the privileged path.

  Reviewer note: if a cleaner approach arises (e.g. a dedicated read-only
  auth role that can see fingerprints globally without BYPASSRLS), that would
  be preferred. Document in ADR-0005 addendum when implemented.

Failure modes (all → 401 invalid_api_key, no timing distinction):
  - Authorization header absent or not "Bearer <token>" format
  - VirtualApiKeyAuthError from lookup_by_plaintext (not found / revoked /
    expired / inactive)

MED-3: Does NOT generate its own request_id. Reads the canonical
request.state.request_id set by TerminalAuditMiddleware (outermost layer).
The now-removed request.state.auth_request_id is no longer set.

NOTE: This middleware returns JSONResponse directly rather than raising
GatewayError, because BaseHTTPMiddleware does not reliably propagate
exceptions to FastAPI exception handlers across Starlette versions.
"""

from __future__ import annotations

import uuid

import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from gateway.exceptions import ERROR_TABLE
from persistence.database import get_privileged_session
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyAuthError,
    VirtualApiKeyRepository,
)

log = structlog.get_logger(__name__)

# Paths exempt from auth (operational probes only, outside /v1 surface).
_AUTH_EXEMPT_PATHS = frozenset({"/health", "/ready"})


def _get_request_id(request: Request) -> str:
    """Return the canonical request_id from state, or generate a fallback."""
    rid = getattr(request.state, "request_id", None)
    if rid:
        return rid
    rid = "req-" + uuid.uuid4().hex[:32]
    request.state.request_id = rid
    return rid


def _error_json(
    error_code: str, request_id: str, *, retry_after: int | None = None
) -> JSONResponse:
    message, status = ERROR_TABLE[error_code]
    headers: dict[str, str] = {"X-Request-Id": request_id}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        content={"error_code": error_code, "message": message, "request_id": request_id},
        status_code=status,
        headers=headers,
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """Bearer-token authentication. Resolves virtual key → four stable IDs.

    On success, stores the VirtualApiKey ORM row on request.state.virtual_key_row.
    The tenant_context middleware (step 5) reads this to build TenantContext.

    Returns JSONResponse directly on error (does not raise GatewayError through
    the middleware stack — see module docstring).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        # MED-3: use the single canonical request_id from the outermost wrapper.
        request_id = _get_request_id(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            log.info("auth_missing_bearer", path=request.url.path)
            return _error_json("invalid_api_key", request_id)

        plaintext_key = auth_header[len("Bearer ") :]
        if not plaintext_key:
            log.info("auth_empty_key", path=request.url.path)
            return _error_json("invalid_api_key", request_id)

        try:
            # AUTH CHICKEN-EGG RESOLUTION: use get_privileged_session() for the
            # fingerprint→row lookup ONLY (see module docstring for rationale).
            # This is the sole privileged-path read for authentication; all
            # subsequent tenant data reads use get_tenant_session(tenant_id).
            async with get_privileged_session() as session:
                async with session.begin():
                    repo = VirtualApiKeyRepository(session)
                    key_row = await repo.lookup_by_plaintext(plaintext_key)
        except VirtualApiKeyAuthError:
            # Uniform error — no timing distinction between "not found" and "wrong key"
            log.info("auth_failed", path=request.url.path)
            return _error_json("invalid_api_key", request_id)
        except Exception:
            log.exception("auth_unexpected_error", path=request.url.path)
            return _error_json("internal_error", request_id)

        # Store the resolved row — tenant_context middleware reads it next.
        # NEVER log the key_fingerprint or any secret material here.
        # MED-3: request.state.auth_request_id removed; single canonical ID is
        # already on request.state.request_id.
        request.state.virtual_key_row = key_row
        return await call_next(request)
