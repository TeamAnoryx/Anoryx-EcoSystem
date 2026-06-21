"""Unauthenticated OIDC SSO login routes (F-014 STEP 4, ADR-0017 §3/§5).

These two endpoints are the SSO login surface. They are **UNAUTHENTICATED** — the
IdP assertion IS the auth — so they MUST NOT sit behind require_admin. They live on
a SEPARATE router (`sso_login_router`, prefix /admin/sso) that is mounted next to
admin_router in gateway/main.py and is NOT a child of admin_router. Because every
path begins with `/admin`, it is already exempt from AuthMiddleware and
TenantContextMiddleware (both gate on `path == "/admin" or path.startswith
("/admin/")`), so no tenant headers / Bearer key are required or resolved here.

  POST /admin/sso/oidc/login    {tenant_id}      -> {authorization_url}
  POST /admin/sso/oidc/callback {state, code}    -> success identity payload | error

Security posture:
  * Per-IP rate limit (in-process sliding window) on both routes — these are
    unauthenticated and tenant-named, so they are a brute-force / enumeration
    surface. Exceeding the limit -> 429.
  * Tenant enumeration defence: a tenant with no active OIDC config returns the
    SAME uniform 404 "sso_unavailable" as a malformed/unknown tenant — the caller
    cannot distinguish "no config" from "bad tenant".
  * tenant_id is validated to a UUID shape before any lookup.
  * Assertion-validation failure on callback -> 401 with a generic error (no
    detail leak, R6); the SSO-unavailable case -> 404.

STEP-6 SCOPE (honest): on a SUCCESSFUL callback finalize_sso_login resolves
groups->role and, if the role is None, emits operator_sso_denied + raises ->
403 (fail-closed, vector 14, no provisioning). On role-resolution SUCCESS it
JIT-provisions the admin_user + role assignment, emits operator_sso_login (honest
attribution — actor_id = the admin_user.id, real tenant, vector 16), and returns
the provisioned principal {tenant_id, admin_user_id, role, idp_subject}. It DOES
NOT yet mint the operator-session cookie — that is STEP 7 (see the TODO at the
success path). No operator session is produced on ANY rejection path (R4).
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from admin.sso.login import SsoAccessDenied, finalize_sso_login
from admin.sso.oidc import (
    OidcAuthError,
    OidcConfigUnavailable,
    VerifiedOidcIdentity,
    begin_login,
    complete_login,
)
from admin.sso.session import SESSION_TTL_SECONDS, OperatorSessionError
from admin.sso.session import mint as mint_operator_session
from admin.util import parse_body, request_id

sso_login_router = APIRouter(prefix="/admin/sso", tags=["admin", "sso", "login"])

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Uniform response for "this tenant has no OIDC login available" — used for BOTH a
# bad/unknown tenant and a tenant with no active config (anti-enumeration).
_SSO_UNAVAILABLE_DETAIL = "sso_unavailable"
_GENERIC_AUTH_FAILURE = "sso_authentication_failed"

_OPERATOR_SSO_AGENT = "operator-sso"  # request-id correlation slug for denials

# --------------------------------------------------------------------------- #
# Minimal in-process per-IP rate limiter.
# The gateway's Redis rate limiter is tenant/virtual-key scoped and these routes
# are unauthenticated, so a small per-IP sliding-window guard is used instead
# (per the STEP-4 brief). Bounded per-IP; best-effort (single-process). Ops should
# additionally bound this surface at the network edge.
# --------------------------------------------------------------------------- #
_RATE_LIMIT_MAX = 10  # requests
_RATE_LIMIT_WINDOW_SECONDS = 60.0
_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = {}


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limiting (the connecting peer)."""
    client = request.client
    return client.host if client else "unknown"


def _rate_limit_ok(ip: str) -> bool:
    """Return True if `ip` is within the per-IP window; record the hit if so."""
    now = time.monotonic()
    cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        bucket = _rate_buckets.get(ip)
        if bucket is None:
            bucket = deque()
            _rate_buckets[ip] = bucket
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        # Evict a bucket that pruned to empty so a stale/rotating IP does not retain
        # an empty deque in _rate_buckets (bounds memory under many one-shot IPs;
        # F-014 code-review MED). A live hit below re-creates it.
        if not bucket:
            del _rate_buckets[ip]
        if len(bucket) >= _RATE_LIMIT_MAX:
            return False
        if ip not in _rate_buckets:
            _rate_buckets[ip] = bucket
        bucket.append(now)
        return True


def _enforce_rate_limit(request: Request) -> None:
    if not _rate_limit_ok(_client_ip(request)):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate_limited")


def reset_rate_limit_for_testing() -> None:
    """Clear the per-IP rate buckets (test hook)."""
    with _rate_lock:
        _rate_buckets.clear()


# --------------------------------------------------------------------------- #
# Request schemas (extra='forbid' — closed input).
# --------------------------------------------------------------------------- #
class OidcLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(max_length=64)


class OidcCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str = Field(max_length=64)
    code: str = Field(max_length=4096, repr=False)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@sso_login_router.post("/oidc/login")
async def oidc_login(request: Request) -> dict:
    """Begin an OIDC login. Returns {authorization_url}.

    UNAUTHENTICATED. Per-IP rate limited. A tenant with no active OIDC config
    returns a uniform 404 sso_unavailable (anti-enumeration). tenant_id must be a
    UUID shape.
    """
    _enforce_rate_limit(request)
    body = await parse_body(request, OidcLoginRequest)
    if not _UUID_RE.match(body.tenant_id):
        # Same uniform response as "no config" — never reveal which tenants exist.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL)

    try:
        authorization_url, _state = await begin_login(body.tenant_id)
    except OidcConfigUnavailable:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL
        ) from None
    except OidcAuthError:
        # Any other begin-time failure (e.g. discovery error) — generic, no detail.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL
        ) from None

    return {"authorization_url": authorization_url}


@sso_login_router.post("/oidc/callback")
async def oidc_callback(request: Request) -> dict:
    """Complete an OIDC login.

    UNAUTHENTICATED. Per-IP rate limited. Validates the assertion (state/PKCE/
    signature/claims/nonce) via complete_login; on assertion failure -> 401 generic.
    On success, finalize_sso_login resolves groups->role and:
      * role is None -> emits operator_sso_denied (blocked) exactly once, raises
        SsoAccessDenied -> 403 (fail-closed, vector 14), NO provisioning;
      * role resolved -> JIT-provisions the admin_user + role assignment, emits
        operator_sso_login (actor_id = the admin_user.id, real tenant — vector 16),
        and returns the provisioned principal {tenant_id, admin_user_id, role,
        idp_subject}. NO operator session is minted yet (STEP 7). No operator
        session is produced on any rejection path (R4).
    """
    _enforce_rate_limit(request)
    body = await parse_body(request, OidcCallbackRequest)

    # 1. Validate the assertion (fail-closed). Any OidcAuthError -> generic 401.
    try:
        identity: VerifiedOidcIdentity = await complete_login(body.state, body.code)
    except OidcAuthError:
        # Generic — never leak which check failed (R6). No session produced (R4).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_AUTH_FAILURE
        ) from None

    rid = request_id(request)

    # 2. Finalize: resolve role + JIT-provision + emit operator_sso_login (success),
    #    or emit operator_sso_denied + raise (fail-closed, vector 14). The denied
    #    event is audited inside finalize_sso_login (one place, emitted once).
    try:
        principal = await finalize_sso_login(identity, request_id=rid)
    except SsoAccessDenied:
        # No provisioning, no session (R4). The denial was already audited once.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="sso_no_role") from None

    # 3. Success (STEP 7): mint the tenant-pinned operator-session for this
    #    principal. The frontend (PART B) stores it in the httpOnly cookie spine
    #    and forwards it via the BFF; the admin API verifies + enforces tenant-pin
    #    + role on every call (ADR-0017 §3 D2). idp_subject is NOT returned (no PII
    #    to the browser, R6) — the token carries only the opaque admin_user_id.
    #
    # operator_session_token DELIVERY (BFF pattern — F-014 code-review HIGH reconcile):
    #   The IdP redirects the BROWSER to the FRONTEND callback route; that route
    #   fetches THIS endpoint SERVER-TO-SERVER (Next.js route handler -> Python
    #   admin API), receives this JSON, and immediately wraps the token into a
    #   signed httpOnly SESSION_SECRET cookie (ADR-0015/0017 §9 D8). The token is
    #   therefore consumed ENTIRELY server-side: the browser NEVER receives this
    #   response body and browser JavaScript NEVER reads the token. A cross-origin
    #   browser cannot read this response either — the /admin surface is
    #   server-to-server and is NOT in the gateway CORS allow-list (no
    #   Access-Control-Allow-Origin is emitted for /admin/sso/*; see
    #   gateway/main.py CORSMiddleware, which only allow-lists CORS_ALLOWED_ORIGINS
    #   and is exercised by test_sso_callback_no_permissive_cors). The token is the
    #   only auth material returned and it is short-lived + tenant-pinned (R6).
    try:
        token = mint_operator_session(principal)
    except OperatorSessionError:
        # SENTINEL_ADMIN_SESSION_SECRET unavailable -> fail-closed (R4): the login
        # validated but no session can be minted, so no operator session is issued.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="sso_session_unavailable"
        ) from None
    return {
        "operator_session_token": token,
        "token_type": "Bearer",
        "expires_in": SESSION_TTL_SECONDS,
        "role": principal.role,
        "tenant_id": principal.tenant_id,
    }
