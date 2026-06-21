"""OIDC authorization-code + PKCE middleware (F-014 STEP 4, ADR-0017 §5 D4).

Signature and claim validation are delegated to **authlib** (R3 — no hand-rolled
JWT or signature verification). This module orchestrates the SP-initiated
authorization-code flow with PKCE and enforces every fail-closed check (R4):

  begin_login(tenant_id):
    * load the tenant's ACTIVE oidc idp_config (404 / OidcConfigUnavailable if none
      — fail-closed, never fall through to access);
    * OIDC discovery on the issuer (.well-known/openid-configuration) to resolve
      authorization_endpoint / token_endpoint / jwks_uri;
    * generate high-entropy state (CSRF), nonce (replay), and a PKCE
      code_verifier + S256 code_challenge;
    * persist the single-use transaction (state PK, nonce + code_verifier
      server-side, short TTL) via the privileged session;
    * build the authorization_url (response_type=code, client_id, redirect_uri,
      scope incl. 'openid', state, nonce, code_challenge, code_challenge_method=S256).

  complete_login(state, code):
    * consume(state) — reject if missing / expired / already consumed
      (vectors 9, 10 — single-use);
    * exchange the code at the token_endpoint WITH the stored code_verifier
      (PKCE — vector 13; the verifier is ALWAYS sent, even if the IdP would not
      strictly require it);
    * verify the ID-token signature against the IdP JWKS via authlib (vector 11);
    * validate iss == idp_config.issuer, aud == client_id, exp/iat within a small
      skew (vector 12), and nonce == the stored nonce (vector 10);
    * return VerifiedOidcIdentity(idp_subject=sub, groups=<configured claim>,
      tenant_id=<idp_config OWNER — never the token>, idp_config_id).

R1 tenant binding: the tenant is ALWAYS the owner of the matched idp_config,
recorded at begin_login and carried through the transaction — NEVER read from the
token (vector 2).

R6: this module NEVER logs the ID token, access token, authorization code,
client_secret, code_verifier, nonce, or any claim. There is no logger here by
design; errors carry only an opaque reason code.

Network injection (testability): the three outbound calls — discovery, JWKS fetch,
token exchange — are module-level functions (`discover_oidc`, `fetch_jwks`,
`exchange_code`) that tests monkeypatch to run fully offline. No live IdP.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
from authlib.common.security import generate_token
from authlib.jose import JsonWebToken
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from persistence.database import get_privileged_session
from persistence.repositories.idp_config_repository import (
    IdpConfigNotFoundError,
    IdpConfigRepository,
)
from persistence.repositories.oidc_login_transaction_repository import (
    OidcLoginTransactionRepository,
)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_PROTOCOL = "oidc"
_STATE_NONCE_BYTES = 32  # generate_token(32) -> 64 hex chars
_PKCE_VERIFIER_BYTES = 48  # -> 96 hex chars (43..128 allowed by RFC 7636)
_TRANSACTION_TTL_SECONDS = 300  # 5 min — short-lived pre-auth handle
# Tolerance for IdP-to-SP clock drift, NOT a grace window for expired tokens.
# 30s is enough to absorb realistic NTP-synced clock skew between the IdP and the
# gateway; it is deliberately small so an already-expired ID token is rejected
# promptly (vector 12). Applied symmetrically to exp (backward) and iat (future).
_CLOCK_SKEW_SECONDS = 30
# v1 LIMITATION (F-014 code-review LOW): the OIDC groups claim is hardcoded to
# "groups". Per-IdP groups-claim configurability is DEFERRED (§13.3). A tenant whose
# IdP emits group memberships under a different claim name (e.g. "roles",
# "memberOf") resolves to an EMPTY groups list here and is therefore fail-closed
# DENIED at group->role resolution (D6) — never silently granted access.
_DEFAULT_GROUPS_CLAIM = "groups"
_DISCOVERY_PATH = "/.well-known/openid-configuration"
_HTTP_TIMEOUT_SECONDS = 10.0
# RS256/RS384/RS512/ES256/ES384/ES512 — the algorithms we accept for the ID token.
# 'none' is NOT in this list, so an unsigned/alg=none token is rejected by authlib.
_ALLOWED_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


# --------------------------------------------------------------------------- #
# Errors — every failure path raises OidcAuthError (fail-closed, R4). Distinct
# reason codes for the threat-model vectors; the message NEVER carries a token,
# code, secret, or claim (R6).
# --------------------------------------------------------------------------- #
class OidcAuthError(Exception):
    """Base for any OIDC validation failure. Carries an opaque `reason` code only."""

    reason = "oidc_error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.reason)


class OidcConfigUnavailable(OidcAuthError):
    """The tenant has no active OIDC idp_config (fail-closed; surfaced as 404)."""

    reason = "sso_unavailable"


class OidcStateInvalid(OidcAuthError):
    """state is unknown, expired, or already consumed (vectors 9, 10)."""

    reason = "state_invalid"


class OidcReplay(OidcAuthError):
    """nonce mismatch — replayed / forged ID token (vector 10)."""

    reason = "replay"


class OidcSignatureInvalid(OidcAuthError):
    """ID-token signature does not verify against the IdP JWKS (vector 11)."""

    reason = "signature_invalid"


class OidcClaimsInvalid(OidcAuthError):
    """iss / aud / exp / iat invalid (vector 12)."""

    reason = "claims_invalid"


class OidcPkceInvalid(OidcAuthError):
    """Token exchange failed PKCE verification (vector 13)."""

    reason = "pkce_invalid"


# --------------------------------------------------------------------------- #
# Verified identity (returned ONLY on full success).
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VerifiedOidcIdentity:
    """The result of a fully-validated OIDC login. NEVER partially populated.

    tenant_id is the idp_config OWNER (R1) — never a token-supplied value.
    idp_subject is the IdP `sub`. groups is the list from the configured groups
    claim (empty list if absent). No raw token / claim payload is exposed.
    """

    idp_subject: str
    groups: list[str]
    tenant_id: str
    idp_config_id: str


# --------------------------------------------------------------------------- #
# Injectable network hooks (monkeypatched in tests — no live IdP).
# Each raises OidcAuthError-family on failure; none ever logs a secret.
# --------------------------------------------------------------------------- #
def discover_oidc(issuer: str) -> dict:
    """Fetch the OIDC discovery document for `issuer`. Injectable for tests.

    Returns the parsed .well-known/openid-configuration JSON. Raises
    OidcConfigUnavailable on any network/parse failure (fail-closed).
    """
    url = issuer.rstrip("/") + _DISCOVERY_PATH
    try:
        resp = httpx.get(url, timeout=_HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001 — fail-closed on any discovery error
        raise OidcConfigUnavailable("oidc discovery failed") from exc


def fetch_jwks(jwks_uri: str) -> dict:
    """Fetch the IdP JWKS document. Injectable for tests.

    Raises OidcSignatureInvalid on any network/parse failure — without keys we
    cannot verify the signature, so we fail closed.
    """
    try:
        resp = httpx.get(jwks_uri, timeout=_HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        raise OidcSignatureInvalid("jwks fetch failed") from exc


def exchange_code(
    *,
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str | None,
    code_verifier: str,
) -> dict:
    """Exchange an authorization code for tokens at the token endpoint.

    PKCE (vector 13): `code_verifier` is ALWAYS included in the form body, so an
    IdP that requires it (and one that does not) both receive it; a token endpoint
    that rejects a wrong/absent verifier surfaces here. Injectable for tests.

    Returns the parsed token response (expected to contain `id_token`). Raises
    OidcPkceInvalid on an HTTP error from the token endpoint (PKCE/exchange
    failure), OidcClaimsInvalid when no id_token is present. NEVER logs the code,
    verifier, secret, or returned tokens (R6).
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        # PKCE verifier — always sent (R3/vector 13).
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    try:
        resp = httpx.post(token_endpoint, data=data, timeout=_HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001 — token-exchange failure (incl. PKCE)
        raise OidcPkceInvalid("token exchange failed") from exc
    if not isinstance(payload, dict) or "id_token" not in payload:
        raise OidcClaimsInvalid("token response missing id_token")
    return payload


# --------------------------------------------------------------------------- #
# begin_login
# --------------------------------------------------------------------------- #
def _build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Assemble the authorization redirect URL with PKCE + state + nonce."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return str(httpx.URL(authorization_endpoint, params=params))


def _normalize_scope(scopes: str | None) -> str:
    """Return a scope string that always contains 'openid'."""
    parts = (scopes or "").split()
    if "openid" not in parts:
        parts = ["openid", *parts]
    return " ".join(parts)


async def begin_login(tenant_id: str) -> tuple[str, str]:
    """Start an OIDC login for `tenant_id`. Returns (authorization_url, state).

    Loads the tenant's ACTIVE oidc idp_config (raises OidcConfigUnavailable if
    none — fail-closed). Runs OIDC discovery, generates state/nonce/PKCE, persists
    the single-use transaction (privileged session), and builds the authorization
    URL. The tenant binding (idp_config owner) is captured in the transaction here
    — never later from a token (R1, vector 2).
    """
    # 1. Load the tenant's active OIDC config on a tenant session (RLS-scoped;
    #    caller == the named tenant). 404 if absent -> fail-closed.
    from persistence.database import get_tenant_session

    async with get_tenant_session(tenant_id) as ts:
        repo = IdpConfigRepository(ts)
        try:
            cfg = await repo.get_active(
                tenant_id=tenant_id, protocol=_PROTOCOL, caller_tenant_id=tenant_id
            )
        except IdpConfigNotFoundError as exc:
            raise OidcConfigUnavailable("no active oidc config for tenant") from exc
        # Pull the fields we need off the ORM row while the session is open.
        idp_config_id = cfg.id
        issuer = cfg.issuer
        client_id = cfg.client_id
        scopes = cfg.scopes
        redirect_uri = cfg.sp_acs_url  # configured ACS / redirect_uri
        config_owner_tenant = cfg.tenant_id  # the R1 binding (== tenant_id under RLS)

    if not issuer or not client_id or not redirect_uri:
        # A config row exists but is incomplete — treat as unavailable (fail-closed).
        raise OidcConfigUnavailable("oidc config incomplete")

    # 2. Discovery (injectable). Resolve the authorization endpoint.
    disco = discover_oidc(issuer)
    authorization_endpoint = disco.get("authorization_endpoint")
    if not authorization_endpoint:
        raise OidcConfigUnavailable("discovery missing authorization_endpoint")

    # 3. Generate state / nonce / PKCE.
    state = generate_token(_STATE_NONCE_BYTES)
    nonce = generate_token(_STATE_NONCE_BYTES)
    code_verifier = generate_token(_PKCE_VERIFIER_BYTES)
    code_challenge = create_s256_code_challenge(code_verifier)

    # 4. Persist the single-use transaction on the privileged (global) session.
    async with get_privileged_session() as ps:
        async with ps.begin():
            tx_repo = OidcLoginTransactionRepository(ps)
            # Opportunistic cleanup of expired handles (best-effort).
            await tx_repo.delete_expired()
            await tx_repo.create(
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                tenant_id=config_owner_tenant,
                idp_config_id=idp_config_id,
                ttl_seconds=_TRANSACTION_TTL_SECONDS,
            )

    # 5. Build the authorization redirect.
    authorization_url = _build_authorization_url(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=_normalize_scope(scopes),
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
    )
    return authorization_url, state


# --------------------------------------------------------------------------- #
# complete_login
# --------------------------------------------------------------------------- #
def _verify_id_token(
    *,
    id_token: str,
    jwks: dict,
    issuer: str,
    client_id: str,
    expected_nonce: str,
    groups_claim: str,
) -> tuple[str, list[str]]:
    """Verify signature + claims of an ID token. Returns (sub, groups).

    Signature is verified by authlib against the JWKS (vector 11; alg=none is not
    in _ALLOWED_ID_TOKEN_ALGS so it is rejected). iss/aud/exp/iat are validated
    with a small skew (vector 12); nonce must equal the stored value (vector 10).
    Raises the matching OidcAuthError subclass on any failure (fail-closed, R4).
    """
    jwt = JsonWebToken(_ALLOWED_ID_TOKEN_ALGS)
    try:
        claims = jwt.decode(id_token, jwks)
    except Exception as exc:  # noqa: BLE001 — any decode/signature failure
        raise OidcSignatureInvalid("id token signature invalid") from exc

    # --- iss ---
    if claims.get("iss") != issuer:
        raise OidcClaimsInvalid("iss mismatch")

    # --- aud (string or list) ---
    aud = claims.get("aud")
    aud_ok = aud == client_id or (isinstance(aud, (list, tuple)) and client_id in aud)
    if not aud_ok:
        raise OidcClaimsInvalid("aud mismatch")

    # --- exp / iat with skew ---
    now = int(time.time())
    exp = claims.get("exp")
    if exp is None or now > int(exp) + _CLOCK_SKEW_SECONDS:
        raise OidcClaimsInvalid("token expired")
    iat = claims.get("iat")
    if iat is not None and int(iat) - _CLOCK_SKEW_SECONDS > now:
        raise OidcClaimsInvalid("iat in the future")

    # --- nonce (single-use replay) ---
    if claims.get("nonce") != expected_nonce:
        raise OidcReplay("nonce mismatch")

    sub = claims.get("sub")
    if not sub:
        raise OidcClaimsInvalid("missing sub")

    raw_groups = claims.get(groups_claim, [])
    if isinstance(raw_groups, str):
        groups = [raw_groups]
    elif isinstance(raw_groups, (list, tuple)):
        groups = [str(g) for g in raw_groups]
    else:
        groups = []

    return str(sub), groups


async def complete_login(state: str, code: str) -> VerifiedOidcIdentity:
    """Complete an OIDC login. Returns VerifiedOidcIdentity or raises OidcAuthError.

    Consumes the single-use transaction (rejecting missing/expired/replayed state),
    exchanges the code with the stored PKCE verifier, verifies the ID token
    signature + claims + nonce, and binds the identity to the idp_config OWNER
    (R1) — never to a token value. NEVER returns a partial identity (R4).
    """
    # 1. Consume the single-use transaction (privileged/global session).
    async with get_privileged_session() as ps:
        async with ps.begin():
            tx_repo = OidcLoginTransactionRepository(ps)
            tx = await tx_repo.consume(state=state)
            if tx is None:
                # Unknown, expired, or already-consumed state (vectors 9, 10).
                raise OidcStateInvalid("state unknown/expired/consumed")
            # Snapshot the transaction fields before the session closes.
            tx_tenant_id = tx.tenant_id
            tx_idp_config_id = tx.idp_config_id
            tx_nonce = tx.nonce
            tx_code_verifier = tx.code_verifier

    # 2. Re-load the idp_config for this tenant (RLS-scoped) to get issuer,
    #    client_id, redirect_uri, scopes, and the (decrypted) client_secret. The
    #    tenant is the transaction's tenant (the config owner) — R1.
    from persistence.database import get_tenant_session

    async with get_tenant_session(tx_tenant_id) as ts:
        repo = IdpConfigRepository(ts)
        try:
            cfg = await repo.get_active(
                tenant_id=tx_tenant_id, protocol=_PROTOCOL, caller_tenant_id=tx_tenant_id
            )
        except IdpConfigNotFoundError as exc:
            raise OidcConfigUnavailable("oidc config disappeared mid-flow") from exc
        issuer = cfg.issuer or ""
        client_id = cfg.client_id or ""
        redirect_uri = cfg.sp_acs_url or ""
        groups_claim = _DEFAULT_GROUPS_CLAIM
        # Decrypt the client_secret at the use-site only (kept out of logs, R6).
        client_secret_bytes = await repo.get_decrypted_secret(
            tenant_id=tx_tenant_id,
            protocol=_PROTOCOL,
            field="client_secret",
            caller_tenant_id=tx_tenant_id,
        )
    client_secret = client_secret_bytes.decode("utf-8") if client_secret_bytes else None

    # 3. Discovery -> token_endpoint + jwks_uri (injectable).
    disco = discover_oidc(issuer)
    token_endpoint = disco.get("token_endpoint")
    jwks_uri = disco.get("jwks_uri")
    if not token_endpoint or not jwks_uri:
        raise OidcConfigUnavailable("discovery missing token/jwks endpoint")

    # 4. Exchange the code WITH the PKCE verifier (vector 13).
    token_response = exchange_code(
        token_endpoint=token_endpoint,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        code_verifier=tx_code_verifier,
    )
    id_token = token_response["id_token"]

    # 5. Fetch JWKS + verify signature/claims/nonce (vectors 10, 11, 12).
    jwks = fetch_jwks(jwks_uri)
    idp_subject, groups = _verify_id_token(
        id_token=id_token,
        jwks=jwks,
        issuer=issuer,
        client_id=client_id,
        expected_nonce=tx_nonce,
        groups_claim=groups_claim,
    )

    # 6. Bind to the idp_config OWNER (R1) — never to any token value.
    return VerifiedOidcIdentity(
        idp_subject=idp_subject,
        groups=groups,
        tenant_id=tx_tenant_id,
        idp_config_id=tx_idp_config_id,
    )
