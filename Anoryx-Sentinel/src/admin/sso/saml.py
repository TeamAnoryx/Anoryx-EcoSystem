"""SAML SSO middleware (F-014 STEP 5, ADR-0017 §6 D5).

SP-initiated only (Fork 4), signed assertion REQUIRED, unsigned REJECTED. XML
signature validation is delegated to **python3-saml** (R3 — we do NOT hand-roll XML
or signature parsing); our job is strict configuration + validating every
condition, fail-closed (R4).

  begin_login(tenant_id) -> (redirect_url, request_id):
    * load the tenant's ACTIVE saml idp_config (404 / SamlConfigUnavailable if none
      — fail-closed, never fall through to access);
    * build a python3-saml settings dict (strict=True, wantAssertionsSigned=True,
      rejectUnsolicitedResponsesWithInResponseTo=True);
    * issue an AuthnRequest via OneLogin_Saml2_Auth.login() and capture its
      generated request id (get_last_request_id());
    * persist a single-use saml_login_transaction (request_id PK, tenant + config,
      short TTL) on the privileged session;
    * return the IdP redirect target + the request_id.

  complete_login(saml_response_b64, request_data) -> VerifiedSamlIdentity:
    * consume(request_id) FIRST on the privileged store — an unknown/absent/replayed
      InResponseTo (IdP-initiated injection or replay) consumes nothing -> reject
      (vector 7);
    * process_response(request_id=<the consumed id>) — python3-saml verifies the
      XML signature against idp_x509_cert, enforces exactly-one-signed-assertion
      (XSW, vector 4), rejects unsigned assertions (wantAssertionsSigned, vector 5),
      and validates Issuer / Audience / Recipient / Destination / NotBefore /
      NotOnOrAfter / InResponseTo (vectors 2, 6, 7, 8) under strict=True;
    * then we ADDITIONALLY assert: is_authenticated() True, get_errors() empty, the
      response carried InResponseTo == the consumed request_id, and a NameID is
      present (defence-in-depth on top of the library checks);
    * return VerifiedSamlIdentity(idp_subject=NameID, groups=<configured attribute>,
      tenant_id=<idp_config OWNER — NEVER the assertion>, idp_config_id).

R1 tenant binding: the tenant is ALWAYS the owner of the matched idp_config,
recorded at begin_login in the transaction — NEVER read from the assertion (vector
2).

R6: this module NEVER logs the SAMLResponse, the assertion, the SP private key, or
any PII attribute. There is no logger here by design; errors carry only an opaque
reason code (no assertion/PII content).

LAZY IMPORT (slim-image safe): onelogin.saml2 is imported INSIDE the functions
(guarded with a clear "pip install anoryx-sentinel[saml]" hint), never at module
top-level — so src/admin imports without python3-saml installed on the slim image /
a non-SAML deploy (mirrors the F-010 optional-extras discipline).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.idp_config_repository import (
    IdpConfigNotFoundError,
    IdpConfigRepository,
)
from persistence.repositories.saml_login_transaction_repository import (
    SamlLoginTransactionRepository,
)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_PROTOCOL = "saml"
_TRANSACTION_TTL_SECONDS = 300  # 5 min — short-lived pre-auth handle
# v1 LIMITATION (F-014 code-review LOW): the SAML groups attribute is hardcoded to
# "groups". Per-IdP groups-attribute configurability is DEFERRED (§13.3). A tenant
# whose IdP emits group memberships under a different attribute name (e.g.
# "memberOf", "Role") resolves to an EMPTY groups list here and is therefore
# fail-closed DENIED at group->role resolution (D6) — never silently granted access.
_DEFAULT_GROUPS_ATTRIBUTE = "groups"  # SAML attribute carrying group memberships
_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
_INSTALL_HINT = (
    "python3-saml is not installed. SAML SSO requires the optional extra: "
    "pip install anoryx-sentinel[saml]"
)


# --------------------------------------------------------------------------- #
# Errors — every failure path raises SamlAuthError (fail-closed, R4). Distinct
# reason codes for the threat-model vectors; the message NEVER carries the
# SAMLResponse, assertion, key, or any PII (R6).
# --------------------------------------------------------------------------- #
class SamlAuthError(Exception):
    """Base for any SAML validation failure. Carries an opaque `reason` code only."""

    reason = "saml_error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.reason)


class SamlConfigUnavailable(SamlAuthError):
    """The tenant has no active SAML idp_config (fail-closed; surfaced as 404)."""

    reason = "sso_unavailable"


class SamlUnsigned(SamlAuthError):
    """The assertion is not signed (wantAssertionsSigned; vector 5)."""

    reason = "unsigned"


class SamlSignatureInvalid(SamlAuthError):
    """Signature does not verify, or signature-wrapping (XSW) detected (vector 4)."""

    reason = "signature_invalid"


class SamlConditionsInvalid(SamlAuthError):
    """Issuer / Audience / Recipient / Destination invalid (vectors 2, 8)."""

    reason = "conditions_invalid"


class SamlTimeInvalid(SamlAuthError):
    """NotBefore / NotOnOrAfter out of window (vector 6)."""

    reason = "time_invalid"


class SamlReplay(SamlAuthError):
    """InResponseTo unknown / absent / replayed — single-use violated (vector 7)."""

    reason = "replay"


# --------------------------------------------------------------------------- #
# Verified identity (returned ONLY on full success).
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VerifiedSamlIdentity:
    """The result of a fully-validated SAML login. NEVER partially populated.

    tenant_id is the idp_config OWNER (R1) — never an assertion-supplied value.
    idp_subject is the SAML NameID. groups is the list from the configured group
    attribute (empty list if absent). No raw assertion / attribute payload other
    than the NameID + groups is exposed.
    """

    idp_subject: str
    groups: list[str]
    tenant_id: str
    idp_config_id: str


# --------------------------------------------------------------------------- #
# Lazy onelogin.saml2 import (slim-image safe).
# --------------------------------------------------------------------------- #
def _import_onelogin():
    """Import onelogin.saml2 lazily; raise SamlConfigUnavailable with a hint if absent.

    Keeps the module top-level free of python3-saml so src/admin imports on the slim
    image / a non-SAML deploy. The failure is surfaced as a config-unavailable error
    (the route maps it to the uniform sso_unavailable response — no enumeration
    signal that SAML is merely uninstalled).
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only on slim image
        raise SamlConfigUnavailable(_INSTALL_HINT) from exc
    return OneLogin_Saml2_Auth


# --------------------------------------------------------------------------- #
# Settings builder
# --------------------------------------------------------------------------- #
def build_settings(idp_config) -> dict:
    """Build the python3-saml settings dict from an idp_config row (ADR-0017 §6).

    STRICT configuration (R3/R4):
      * strict=True — enforce every condition (Recipient/Destination/timestamps/
        Audience/InResponseTo). Without strict, python3-saml would not reject many
        of the vectors.
      * security.wantAssertionsSigned=True — an UNSIGNED assertion is rejected
        (vector 5). signatureAlgorithm/digestAlgorithm pinned to SHA-256;
        rejectDeprecatedAlgorithm=True bans SHA-1.
      * security.rejectUnsolicitedResponsesWithInResponseTo=True — a response that
        carries an InResponseTo for which we issued no AuthnRequest is rejected;
        combined with the single-use store this is the SP-initiated-only guard
        (vector 7). wantMessagesSigned is configurable (default False — assertions
        MUST be signed; message-level signing is optional).
      * sp.entityId = the configured audience; sp.assertionConsumerService.url =
        sp_acs_url (the Recipient/Destination the IdP must target, vector 8).
      * idp.entityId = idp_entity_id (Issuer must match, vector 2);
        idp.singleSignOnService.url = idp_sso_url; idp.x509cert = idp_x509_cert
        (the public signing cert — validated, not a secret).

    The SP private key is decrypted and added ONLY when SP request-signing is in use
    (wantMessagesSigned / a stored sp_private_key); it is NEVER logged (R6). This
    builder does not decrypt by default — callers that need SP signing pass it in
    via build_settings_with_sp_key().

    REQUIRED-FIELD GUARD (F-014 code-review MED, fail-closed R4): idp_entity_id,
    idp_sso_url and sp_acs_url are mandatory — without them python3-saml would build
    a strict settings dict containing empty strings and fail later with an opaque
    error. Instead, raise SamlConfigUnavailable up front so an incomplete config is
    surfaced as the uniform sso_unavailable response (no enumeration signal, R6) and
    no half-built settings dict is ever returned.
    """
    _REQUIRED_FIELDS = ("idp_entity_id", "idp_sso_url", "sp_acs_url")
    missing = [f for f in _REQUIRED_FIELDS if not (getattr(idp_config, f, None) or "").strip()]
    if missing:
        # The reason carries only field NAMES (no secret/PII, R6).
        raise SamlConfigUnavailable(
            "saml idp_config is missing required field(s): " + ", ".join(missing)
        )
    sp_entity_id = idp_config.audience or idp_config.sp_acs_url or ""
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": idp_config.sp_acs_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": _NAMEID_FORMAT,
        },
        "idp": {
            "entityId": idp_config.idp_entity_id or "",
            "singleSignOnService": {
                "url": idp_config.idp_sso_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp_config.idp_x509_cert or "",
        },
        "security": {
            # Assertions MUST be signed; unsigned -> rejected (vector 5).
            "wantAssertionsSigned": True,
            # Message-level signing is optional in v1 (assertion signing is the
            # required control). Flip to True if the IdP signs the <Response>.
            "wantMessagesSigned": False,
            # SP-initiated-only guard (vector 7): reject a response whose
            # InResponseTo we never issued.
            "rejectUnsolicitedResponsesWithInResponseTo": True,
            # Require a NameID (the idp_subject) be present.
            "wantNameId": True,
            # Ban SHA-1 signatures/digests.
            "rejectDeprecatedAlgorithm": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            # We do not sign our own AuthnRequest in v1 (SP request-signing off).
            "authnRequestsSigned": False,
        },
    }


def _request_data_for_acs(*, acs_url: str, saml_response_b64: str | None = None) -> dict:
    """Build the python3-saml `request` dict that locates our ACS (Destination check).

    The `https`/`http_host`/`script_name` fields tell python3-saml the URL the
    request arrived at, which it compares against the assertion's Recipient /
    Destination under strict=True (vector 8). We derive them from the CONFIGURED
    sp_acs_url (our own trusted value), not from any attacker-controlled header.
    """
    parsed = urlparse(acs_url)
    default_port = "443" if parsed.scheme == "https" else "80"
    data: dict = {
        "https": "on" if parsed.scheme == "https" else "off",
        "http_host": parsed.netloc,
        "script_name": parsed.path or "/",
        "server_port": str(parsed.port) if parsed.port else default_port,
        "get_data": {},
        "post_data": {},
    }
    if saml_response_b64 is not None:
        data["post_data"] = {"SAMLResponse": saml_response_b64}
    return data


# --------------------------------------------------------------------------- #
# begin_login (SP-initiated)
# --------------------------------------------------------------------------- #
async def begin_login(tenant_id: str) -> tuple[str, str]:
    """Start an SP-initiated SAML login for `tenant_id`. Returns (redirect_url, request_id).

    Loads the tenant's ACTIVE saml idp_config (raises SamlConfigUnavailable if none
    — fail-closed). Builds strict settings, issues an AuthnRequest, captures its
    generated request id, and persists the single-use transaction (privileged
    session). The tenant binding (idp_config owner) is captured in the transaction
    here — never later from the assertion (R1, vector 2).
    """
    OneLogin_Saml2_Auth = _import_onelogin()

    # 1. Load the tenant's active SAML config on a tenant session (RLS-scoped;
    #    caller == the named tenant). 404 if absent -> fail-closed.
    async with get_tenant_session(tenant_id) as ts:
        repo = IdpConfigRepository(ts)
        try:
            cfg = await repo.get_active(
                tenant_id=tenant_id, protocol=_PROTOCOL, caller_tenant_id=tenant_id
            )
        except IdpConfigNotFoundError as exc:
            raise SamlConfigUnavailable("no active saml config for tenant") from exc
        idp_config_id = cfg.id
        config_owner_tenant = cfg.tenant_id  # the R1 binding (== tenant_id under RLS)
        acs_url = cfg.sp_acs_url
        idp_sso_url = cfg.idp_sso_url
        settings_dict = build_settings(cfg)

    if not acs_url or not idp_sso_url or not settings_dict["idp"]["entityId"]:
        # A config row exists but is incomplete — treat as unavailable (fail-closed).
        raise SamlConfigUnavailable("saml config incomplete")

    # 2. Build the Auth object on a request rooted at OUR configured ACS, issue the
    #    AuthnRequest, and capture the generated request id.
    req = _request_data_for_acs(acs_url=acs_url)
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
    redirect_url = auth.login()  # builds + returns the IdP redirect with the AuthnRequest
    request_id = auth.get_last_request_id()
    if not request_id:
        # Should never happen with a valid AuthnRequest; fail-closed.
        raise SamlConfigUnavailable("authn request id unavailable")

    # 3. Persist the single-use transaction on the privileged (global) session.
    async with get_privileged_session() as ps:
        async with ps.begin():
            tx_repo = SamlLoginTransactionRepository(ps)
            await tx_repo.delete_expired()  # opportunistic cleanup (best-effort)
            await tx_repo.create(
                request_id=request_id,
                tenant_id=config_owner_tenant,
                idp_config_id=idp_config_id,
                ttl_seconds=_TRANSACTION_TTL_SECONDS,
            )

    return redirect_url, request_id


# --------------------------------------------------------------------------- #
# complete_login (the ACS validation — the marquee security path)
# --------------------------------------------------------------------------- #
def _classify_errors(errors: list[str], last_reason: str | None) -> SamlAuthError:
    """Map python3-saml's failure to a typed SamlAuthError (no raw reason in the message).

    python3-saml returns a COARSE error code (almost always 'invalid_response') in
    get_errors(); the discriminating detail lives only in get_last_error_reason()
    (`last_reason`). We READ `last_reason` to pick the vector-specific reason CODE
    but NEVER propagate its text into the raised exception's message — every
    SamlAuthError carries only a fixed opaque string (R6). `last_reason` can mention
    our own config values (issuer/audience/ACS) but never a secret or PII; we still
    do not echo it, to keep error surfaces uniform and leak-free.

    The ordering matters: signature/XSW first (it short-circuits before condition
    checks in the library), then unsigned, then InResponseTo, then time, then the
    issuer/audience/recipient/destination conditions.
    """
    haystack = (" ".join(errors) + " " + (last_reason or "")).lower()
    if "wrapping" in haystack or "signature" in haystack or "node signature" in haystack:
        return SamlSignatureInvalid("signature invalid or wrapped")
    if "not signed" in haystack or "require it" in haystack or "unsigned" in haystack:
        return SamlUnsigned("assertion not signed")
    if "inresponseto" in haystack or "in_response_to" in haystack or "unsolicited" in haystack:
        return SamlReplay("inresponseto mismatch")
    if (
        "timestamp" in haystack
        or "expired" in haystack
        or "not yet valid" in haystack
        or "too early" in haystack
    ):
        return SamlTimeInvalid("notbefore/notonorafter out of window")
    if (
        "audience" in haystack
        or "issuer" in haystack
        or "recipient" in haystack
        or "destination" in haystack
        or "subjectconfirmation" in haystack
        or "received at" in haystack
    ):
        return SamlConditionsInvalid("issuer/audience/recipient/destination invalid")
    # Default: anything unclassified is a generic invalid response — fail-closed.
    return SamlSignatureInvalid("saml response invalid")


async def complete_login(saml_response_b64: str, request_id: str) -> VerifiedSamlIdentity:
    """Complete an SP-initiated SAML login. Returns VerifiedSamlIdentity or raises.

    `request_id` is the AuthnRequest id the browser flow round-tripped (the value the
    ACS route holds). We consume it FIRST (single-use store) — so an unknown / absent
    / replayed InResponseTo (IdP-initiated injection or a replayed response) is
    rejected before any XML is processed (vector 7). We then run python3-saml's
    strict validation bound to that exact request_id, and additionally assert the
    library found the response authenticated, error-free, InResponseTo-matched, and
    NameID-bearing. NEVER returns a partial identity (R4).
    """
    OneLogin_Saml2_Auth = _import_onelogin()

    # 1. Consume the single-use transaction FIRST (privileged/global session). An
    #    unknown / expired / already-consumed request_id (replay or IdP-initiated
    #    injection) consumes nothing -> reject (vector 7) before touching the XML.
    async with get_privileged_session() as ps:
        async with ps.begin():
            tx_repo = SamlLoginTransactionRepository(ps)
            tx = await tx_repo.consume(request_id=request_id)
            if tx is None:
                raise SamlReplay("request_id unknown/expired/consumed")
            tx_tenant_id = tx.tenant_id
            tx_idp_config_id = tx.idp_config_id

    # 2. Re-load the idp_config for the bound tenant (RLS-scoped) to rebuild strict
    #    settings (cert, audience, ACS). The tenant is the transaction's tenant (the
    #    config owner) — R1, never the assertion.
    async with get_tenant_session(tx_tenant_id) as ts:
        repo = IdpConfigRepository(ts)
        try:
            cfg = await repo.get_active(
                tenant_id=tx_tenant_id, protocol=_PROTOCOL, caller_tenant_id=tx_tenant_id
            )
        except IdpConfigNotFoundError as exc:
            raise SamlConfigUnavailable("saml config disappeared mid-flow") from exc
        acs_url = cfg.sp_acs_url or ""
        groups_attribute = _DEFAULT_GROUPS_ATTRIBUTE
        settings_dict = build_settings(cfg)

    # 3. Build the Auth object rooted at OUR configured ACS (the Destination/Recipient
    #    python3-saml compares against under strict=True, vector 8) and process the
    #    response BOUND to the consumed request_id (InResponseTo enforcement, vector 7).
    req = _request_data_for_acs(acs_url=acs_url, saml_response_b64=saml_response_b64)
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)

    try:
        # process_response runs the FULL strict validation: XML signature verify
        # against idp_x509_cert (vector 4), exactly-one-signed-assertion / XSW
        # (validate_num_assertions + process_signed_elements), wantAssertionsSigned
        # (vector 5), Issuer/Audience/Recipient/Destination (vectors 2, 8),
        # NotBefore/NotOnOrAfter (vector 6), and InResponseTo == request_id (vector 7).
        # R3: we do NOT parse or validate the XML ourselves.
        auth.process_response(request_id=request_id)
    except Exception as exc:  # noqa: BLE001 — any library error -> fail-closed, typed
        # The exception text can echo assertion fragments; do NOT propagate it (R6).
        raise SamlSignatureInvalid("saml response processing failed") from exc

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        # Read the library's last-error reason ONLY to choose a typed reason code;
        # its text is never propagated into the raised message (R6). get_errors()
        # alone is too coarse (always 'invalid_response') to distinguish vectors.
        last_reason = auth.get_last_error_reason()
        raise _classify_errors(errors, last_reason)

    # 4. Defence-in-depth on top of the library checks (fail-closed, R4):
    #    (a) the response's InResponseTo MUST equal the consumed request_id. With
    #        strict + rejectUnsolicitedResponsesWithInResponseTo this is already
    #        enforced; we re-assert it so a library-config regression cannot silently
    #        accept a wrapped/foreign InResponseTo (vector 7).
    in_response_to = auth.get_last_response_in_response_to()
    if in_response_to != request_id:
        raise SamlReplay("inresponseto != consumed request_id")

    #    (b) a NameID (the idp_subject) MUST be present.
    name_id = auth.get_nameid()
    if not name_id:
        raise SamlConditionsInvalid("missing nameid")

    # 5. Extract groups from the configured attribute (NEVER logged). A missing
    #    attribute yields [] (the caller's group->role resolution then denies,
    #    fail-closed). Coerce to a list[str].
    attributes = auth.get_attributes() or {}
    raw_groups = attributes.get(groups_attribute, [])
    if isinstance(raw_groups, str):
        groups = [raw_groups]
    elif isinstance(raw_groups, (list, tuple)):
        groups = [str(g) for g in raw_groups]
    else:
        groups = []

    # 6. Bind to the idp_config OWNER (R1) — never to any assertion value.
    return VerifiedSamlIdentity(
        idp_subject=str(name_id),
        groups=groups,
        tenant_id=tx_tenant_id,
        idp_config_id=tx_idp_config_id,
    )
