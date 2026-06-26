"""AccessTokenClaims — the decoded ES256 access-token payload.

Mirrors R-001's LOCKED ``components.schemas.AccessTokenClaims`` byte-for-byte: the same closed
property set (``additionalProperties:false``), the same required claims, the same bounds. The
contract's claim set is the law and is the AUTHORITATIVE, server-resolved identity:

  required: iss, sub, tenant_id, scope, token_use, iat, exp, jti
  optional: roles (open string array, ≤64), idp_subject (RESERVED O-010 seam, null in R-001)

NO ``aud`` claim (R-003 surfaced point S1, resolved "conform"): the locked schema is closed and
omits ``aud``, so this model omits it too. For a single self-issued audience, ``iss`` (const) +
``token_use`` ("access") bind issuer + purpose; verification checks those, not an audience.

Because the model is closed (``extra="forbid"``), parsing a decoded token back into it is a
defense-in-depth check: a token carrying any unexpected claim (e.g. a smuggled ``aud`` or a
mismatched ``token_use``) is rejected at parse, on top of the signature/issuer checks.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from ..identifiers import TenantId, UserId

ISSUER = "https://rendly.anoryx.io"
TOKEN_USE_ACCESS = "access"

# jti charset-bounded against log injection (contract: ^[A-Za-z0-9._-]{1,64}$).
Jti = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,64}$", max_length=64)]
ScopeStr = Annotated[str, StringConstraints(max_length=512)]
Role = Annotated[str, StringConstraints(max_length=64)]
IdpSubject = Annotated[str, StringConstraints(max_length=256)]

# Timestamp ceiling mirrors the contract (JSON-Schema 2^53-1 safe-integer maximum).
_TS_MAX = 9007199254740991
Timestamp = Annotated[int, Field(ge=0, le=_TS_MAX)]


class AccessTokenClaims(BaseModel):
    """The decoded JWT access-token payload. Closed + immutable; matches the LOCKED schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    iss: Literal["https://rendly.anoryx.io"]
    sub: UserId
    tenant_id: TenantId
    scope: ScopeStr
    token_use: Literal["access"]
    iat: Timestamp
    exp: Timestamp
    jti: Jti
    roles: Annotated[list[Role], Field(max_length=64)] | None = None
    idp_subject: IdpSubject | None = None

    def scope_set(self) -> frozenset[str]:
        """The granted scopes as a set (space-delimited per the contract)."""
        return frozenset(self.scope.split())
