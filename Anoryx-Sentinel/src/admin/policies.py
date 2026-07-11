"""Admin policy-intake HTTP route (X-003, ADR-0042) — closes the wire loop for F-008.

POST /admin/policies/intake is a THIN ingress wrapper over the EXISTING,
fail-closed `intake_policy()` pipeline (`src/policy/intake.py`, ADR-0009 §3). It
adds an authenticated HTTP entry point for the SAME function `sentinel-cli policy
push` already calls in-process; it adds NO new business logic and bypasses NONE
of intake_policy()'s checks (schema -> signature -> scope-resolve-and-reject ->
replay/rollback -> persist+audit, atomic, fail-closed, audited on every path).

SCOPE / AUTH DECISION (read before touching this file — the security auditor
will scrutinize this):

  Every OTHER per-tenant admin route ({tenant_id} in the path) additionally
  depends on `validate_tenant_id_path` + `enforce_admin_scope`, which pin an
  SSO-operator principal to ITS OWN path tenant (R1, ADR-0017 §3 D2). This route
  has NO {tenant_id} path parameter: the authoritative tenant/scope for a policy
  record is resolved INSIDE intake_policy() from the VERIFIED signature, not from
  any path or body value. There is therefore no path tenant to pin an operator to,
  and adding `enforce_admin_scope` here would be a type error, not a security
  improvement — it has nothing to compare the signature-resolved tenant against
  except the record BODY's tenant_id, which is explicitly a cross-check-only,
  non-authoritative value intake_policy() itself never trusts.

  This route IS, however, inherently cross-tenant in the same sense the global
  tenant-registry routes are: a single call can legitimately persist a policy for
  ANY tenant, decided entirely by whichever signing key produced the record's
  signature. `admin.scope` already encodes the codebase's existing invariant for
  that shape of route: "no SSO-authenticated request is ever cross-tenant"
  (`reject_sso_global`, ADR-0017 §3 D2.5, reused verbatim here — not
  reimplemented, R8). So the most conservative correct choice — reusing existing,
  already-tested authorization primitives rather than inventing a new one — is:

    require_admin (parent admin_router, inherited)  -> authenticates: break-glass
      SENTINEL_ADMIN_TOKEN OR an SSO-operator-session, exactly as O-004 (which
      sends the break-glass bearer) already expects.
    reject_sso_global (this router)                 -> authorizes: break-glass
      only. An SSO-operator-session is 403'd before intake_policy() ever runs.

  WHY reject SSO here even though intake_policy() cannot itself be tricked into
  widening scope (the verified signature is authoritative; an SSO operator
  without the Delta/Orchestrator signing key cannot forge a record for a tenant
  they don't already have a validly-signed record for): an SSO-operator session
  is tenant-pinned everywhere else in this API, so a caller holding one is
  reasonably expected — by every other route in this file's own package — to be
  restricted to their own tenant. Allowing that SAME credential to relay a
  cross-tenant-signed record here, with no pin and no path tenant to check it
  against, would be a silent, route-specific exception to that expectation.
  Reusing `reject_sso_global` closes that gap by construction: it never depends
  on this route reasoning correctly about the record body (which is untrusted
  input) — it rejects the SSO principal before the body is even read. Only the
  break-glass principal (the one credential O-004 is documented to send,
  ADR-0042 §2/§4) can reach this route, exactly mirroring the global
  tenant-registry precedent for "inherently cross-tenant, no per-request tenant
  to pin against".

RESPONSE MAPPING (ADR-0042 §2.1 / contracts/openapi.yaml `adminIntakePolicy`):
  IntakeResult.Accepted             -> 200 AdminPolicyIntakeAccepted
  IntakeResult.RejectedSchema       -> 422 policy_intake_schema_rejected
  IntakeResult.RejectedSignature    -> 403 policy_intake_signature_rejected
  IntakeResult.RejectedScopeMismatch-> 409 policy_intake_scope_mismatch
  IntakeResult.RejectedReplay       -> 409 policy_intake_replay_rejected

Each rejection is returned as the standard `Error` envelope
({error_code, message, request_id} — contracts/openapi.yaml `Error` schema) built
directly here (NOT via HTTPException(detail=...): unlike the short opaque slugs
the rest of /admin/* raises via HTTPException — which FastAPI serializes as
{"detail": ...}, not the Error envelope — this endpoint's contract entry
explicitly pins four new stable error_code/message pairs onto the shared `Error`
schema, so the response body is built to match that schema exactly, the same way
gateway/middleware/*.py's `_error_json` helpers already do for the data plane).
`message` is a fixed constant selected solely by error_code — never derived from
the record, so it can never leak record content (CLAUDE.md #6).

RAW BYTES: the body is handed to intake_policy() EXACTLY as received
(request.state.raw_body, set once by RequestValidationMiddleware — which is NOT
skipped for /admin/*, only AuthMiddleware/TenantContextMiddleware are). This
route never parses/re-serializes/mutates the body before passing it on: doing so
could change bytes the signature or content-hash claim covers, turning a validly
signed record into one intake_policy() would (correctly) reject as tampered.

NEVER LOGGED HERE: record content, signature bytes, disputed IDs, or the rejected
version numbers. intake_policy() already audits every path (accept + every
rejection) and, for scope/replay rejections, logs the disputed detail at
warning/debug keyed by request_id internally — this route adds no logging of its
own beyond what request_id() computes for the response.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from admin.scope import reject_sso_global
from admin.util import request_id
from policy.intake import intake_policy
from policy.results import (
    Accepted,
    RejectedReplay,
    RejectedSchema,
    RejectedScopeMismatch,
    RejectedSignature,
)

# reject_sso_global: break-glass (SENTINEL_ADMIN_TOKEN) only — see module
# docstring "SCOPE / AUTH DECISION" above. require_admin itself is inherited
# from the parent admin_router (mounted in admin/router.py), so it is NOT
# repeated here.
policies_router = APIRouter(tags=["admin"], dependencies=[Depends(reject_sso_global)])

# Fixed, constant messages — selected SOLELY by error_code (contracts/openapi.yaml
# `Error.message` enum). Never interpolated with request/record content.
_MSG_SCHEMA_REJECTED = "The signed policy record failed schema validation."
_MSG_SIGNATURE_REJECTED = "The signed policy record signature could not be verified."
_MSG_SCOPE_MISMATCH = "The signed policy scope does not match the record body."
_MSG_REPLAY_REJECTED = "The policy version is not newer than the stored version (replay/rollback)."
_MSG_INTERNAL_ERROR = "An internal error occurred. The request was not processed."


class AdminPolicyIntakeAccepted(BaseModel):
    """Body for a successful intake (IntakeResult.Accepted).

    Field-for-field from policy.results.Accepted, per
    contracts/openapi.yaml#/components/schemas/AdminPolicyIntakeAccepted.
    Metadata only — never signature bytes, key material, or the enforcement body.
    """

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="accepted")
    policy_id: str
    policy_version: int
    policy_type: str


class _ErrorEnvelope(BaseModel):
    """The standard `Error` envelope (contracts/openapi.yaml#/components/schemas/Error)."""

    model_config = ConfigDict(extra="forbid")

    error_code: str
    message: str
    request_id: str


def _error_response(status_code: int, error_code: str, message: str, rid: str) -> JSONResponse:
    body = _ErrorEnvelope(error_code=error_code, message=message, request_id=rid)
    return JSONResponse(
        content=body.model_dump(),
        status_code=status_code,
        headers={"X-Request-Id": rid},
    )


@policies_router.post("/policies/intake")
async def admin_intake_policy(request: Request) -> JSONResponse:
    """Thin ingress wrapper: forward the raw body to intake_policy() unchanged.

    No session kwarg is passed — intake_policy() opens its own privileged
    session + transaction so persist and audit commit atomically (ADR-0009 §3).
    Fail-safe: intake_policy() itself is fail-closed on every checked dimension;
    an exception escaping it here is NOT caught — it propagates to the app's
    generic exception handler (gateway/main.py), which returns a 500
    `internal_error` Error envelope rather than silently passing the record
    through (CLAUDE.md #5 — on ANY inspection/policy error, BLOCK, never pass).
    """
    rid = request_id(request)

    # Read the EXACT bytes RequestValidationMiddleware already captured (module
    # docstring "RAW BYTES") — never re-parse/re-serialize before this call, or a
    # signature/content-hash-covered byte could change under the pipeline's feet.
    raw_body = getattr(request.state, "raw_body", None)
    if raw_body is None:
        raw_body = await request.body()  # fallback: no middleware in front (e.g. a bare test app)

    result = await intake_policy(raw_body)

    if isinstance(result, Accepted):
        body = AdminPolicyIntakeAccepted(
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            policy_type=result.policy_type,
        )
        return JSONResponse(
            content=body.model_dump(), status_code=200, headers={"X-Request-Id": rid}
        )
    if isinstance(result, RejectedSchema):
        return _error_response(422, "policy_intake_schema_rejected", _MSG_SCHEMA_REJECTED, rid)
    if isinstance(result, RejectedSignature):
        return _error_response(
            403, "policy_intake_signature_rejected", _MSG_SIGNATURE_REJECTED, rid
        )
    if isinstance(result, RejectedScopeMismatch):
        return _error_response(409, "policy_intake_scope_mismatch", _MSG_SCOPE_MISMATCH, rid)
    if isinstance(result, RejectedReplay):
        return _error_response(409, "policy_intake_replay_rejected", _MSG_REPLAY_REJECTED, rid)

    # IntakeResult is a closed union (policy/results.py) — this is unreachable by
    # construction. Fail-safe anyway rather than let an unmapped variant fall
    # through unblocked (CLAUDE.md #5): BLOCK with a generic internal error.
    return _error_response(500, "internal_error", _MSG_INTERNAL_ERROR, rid)  # pragma: no cover
