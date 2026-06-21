"""Unauthenticated SAML SSO login routes (F-014 STEP 5, ADR-0017 §3/§6).

These two endpoints are the SAML SSO login surface. They are **UNAUTHENTICATED** —
the signed assertion IS the auth — so they MUST NOT sit behind require_admin. They
are registered on the SAME `sso_login_router` (prefix /admin/sso) that carries the
OIDC routes, mounted next to admin_router in gateway/main.py and NOT a child of it.
Because every path begins with `/admin`, it is already exempt from AuthMiddleware
and TenantContextMiddleware (both gate on `path == "/admin" or path.startswith
("/admin/")`), so no tenant headers / Bearer key are required or resolved here.

  POST /admin/sso/saml/login {tenant_id}                 -> {redirect_url, request_id}
  POST /admin/sso/saml/acs   {SAMLResponse, RelayState}  -> verified identity | error

Security posture (mirrors oidc_routes):
  * Per-IP rate limit (shared in-process sliding window with the OIDC routes) on
    both routes — these are unauthenticated and tenant-named, a brute-force /
    enumeration surface. Exceeding the limit -> 429.
  * Tenant enumeration defence: a tenant with no active SAML config returns the SAME
    uniform 404 "sso_unavailable" as a malformed/unknown tenant — the caller cannot
    distinguish "no config" from "bad tenant". A non-SAML-installed deploy also maps
    to sso_unavailable (the lazy-import failure surfaces as SamlConfigUnavailable).
  * tenant_id is validated to a UUID shape before any lookup.
  * ACS validation failure -> 401 with a GENERIC error (no detail leak, R6); the
    SSO-unavailable case -> 404.

STEP-6 SCOPE (honest, mirrors the OIDC ACS): on a SUCCESSFUL ACS validation
finalize_sso_login resolves groups->role and, if the role is None, emits
operator_sso_denied + raises -> 403 (fail-closed, vector 14, no provisioning). On
role-resolution SUCCESS it JIT-provisions the admin_user + role assignment, emits
operator_sso_login (honest attribution — actor_id = the admin_user.id, real tenant,
vector 16), and returns the provisioned principal {tenant_id, admin_user_id, role,
idp_subject}. It DOES NOT yet mint the operator-session — that is STEP 7 (see the
TODO at the success path). No operator session is produced on ANY rejection path (R4).

R6: this module NEVER logs the SAMLResponse, the assertion, or any PII attribute.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from admin.sso.login import SsoAccessDenied, finalize_sso_login
from admin.sso.oidc_routes import (
    _GENERIC_AUTH_FAILURE,
    _SSO_UNAVAILABLE_DETAIL,
    _UUID_RE,
    _enforce_rate_limit,
    sso_login_router,
)
from admin.sso.saml import (
    SamlAuthError,
    SamlConfigUnavailable,
    VerifiedSamlIdentity,
    begin_login,
    complete_login,
)
from admin.sso.session import SESSION_TTL_SECONDS, OperatorSessionError
from admin.sso.session import mint as mint_operator_session
from admin.util import parse_body, request_id


# --------------------------------------------------------------------------- #
# Request schemas (extra='forbid' — closed input).
# --------------------------------------------------------------------------- #
class SamlLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(max_length=64)


class SamlAcsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The IdP's base64 SAMLResponse. repr=False so it never lands in a __repr__/log.
    SAMLResponse: str = Field(max_length=1_000_000, repr=False)
    # RelayState carries the SP-initiated AuthnRequest id (InResponseTo binding).
    RelayState: str = Field(max_length=64)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@sso_login_router.post("/saml/login")
async def saml_login(request: Request) -> dict:
    """Begin an SP-initiated SAML login. Returns {redirect_url, request_id}.

    UNAUTHENTICATED. Per-IP rate limited. A tenant with no active SAML config (or a
    deploy without python3-saml installed) returns a uniform 404 sso_unavailable
    (anti-enumeration). tenant_id must be a UUID shape. The caller redirects the
    browser to redirect_url and echoes request_id back as RelayState on the ACS.
    """
    _enforce_rate_limit(request)
    body = await parse_body(request, SamlLoginRequest)
    if not _UUID_RE.match(body.tenant_id):
        # Same uniform response as "no config" — never reveal which tenants exist.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL)

    try:
        redirect_url, request_id = await begin_login(body.tenant_id)
    except SamlConfigUnavailable:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL
        ) from None
    except SamlAuthError:
        # Any other begin-time failure — generic, no detail (anti-enumeration).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_SSO_UNAVAILABLE_DETAIL
        ) from None

    return {"redirect_url": redirect_url, "request_id": request_id}


@sso_login_router.post("/saml/acs")
async def saml_acs(request: Request) -> dict:
    """Assertion Consumer Service — validate the IdP's SAMLResponse.

    UNAUTHENTICATED. Per-IP rate limited. Validates the assertion (signature / XSW /
    conditions / NotBefore-NotOnOrAfter / InResponseTo) via complete_login, BOUND to
    the RelayState request_id (single-use). On assertion failure -> 401 generic (no
    detail leak, R6). On success, finalize_sso_login resolves groups->role and:
      * role is None -> emits operator_sso_denied (blocked) exactly once, raises
        SsoAccessDenied -> 403 (fail-closed, vector 14), NO provisioning;
      * role resolved -> JIT-provisions the admin_user + role assignment, emits
        operator_sso_login (actor_id = the admin_user.id, real tenant — vector 16),
        and returns the provisioned principal {tenant_id, admin_user_id, role,
        idp_subject}. NO operator session is minted yet (STEP 7). No operator
        session is produced on any rejection path (R4).
    """
    _enforce_rate_limit(request)
    body = await parse_body(request, SamlAcsRequest)

    # 1. Validate the assertion (fail-closed). Any SamlAuthError -> generic 401.
    try:
        identity: VerifiedSamlIdentity = await complete_login(body.SAMLResponse, body.RelayState)
    except SamlAuthError:
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

    # 3. Success (STEP 7): mint the tenant-pinned operator-session (mirrors the OIDC
    #    ACS). The frontend (PART B) stores it in the httpOnly cookie spine and
    #    forwards it via the BFF; the admin API verifies + enforces tenant-pin +
    #    role per call (ADR-0017 §3 D2). idp_subject is NOT returned (no PII, R6).
    #
    # operator_session_token DELIVERY (BFF pattern — F-014 code-review HIGH reconcile):
    #   The IdP POSTs the SAMLResponse to the BROWSER, which posts it to the FRONTEND
    #   ACS route; that route calls THIS endpoint SERVER-TO-SERVER and wraps the
    #   returned token into a signed httpOnly SESSION_SECRET cookie (ADR-0015/0017
    #   §9 D8). The token is consumed ENTIRELY server-side — the browser never
    #   receives this response body and browser JavaScript never reads the token. A
    #   cross-origin browser cannot read it either: /admin/sso/* is server-to-server
    #   and is NOT in the gateway CORS allow-list (no Access-Control-Allow-Origin is
    #   emitted for it; see gateway/main.py CORSMiddleware + the
    #   test_sso_callback_no_permissive_cors assertion). Short-lived + tenant-pinned (R6).
    try:
        token = mint_operator_session(principal)
    except OperatorSessionError:
        # SENTINEL_ADMIN_SESSION_SECRET unavailable -> fail-closed (R4).
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
