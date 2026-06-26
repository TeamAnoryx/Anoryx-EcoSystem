"""Wire request/response DTOs for the auth endpoints (mirror the LOCKED contract shapes).

These are the on-the-wire bodies for ``/auth/token`` and ``/auth/revoke``, reproduced from
``contracts/openapi.yaml`` byte-for-byte: same closed objects (``extra="forbid"`` ==
``additionalProperties:false``), same field bounds, same required sets. The closedness is also a
security control: because no auth body carries a ``tenant_id``/``user_id`` field at all, a client
cannot assert identity, and a smuggled extra key is REJECTED (400 ``invalid_request``) rather than
silently ignored — the claim-injection defense is structural.

The ``GET /users/me`` response reuses the R-002 domain :class:`rendly.user.User` directly (it is
already the exact closed wire ``User`` shape), so identity is never re-modelled here.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class TokenRequest(BaseModel):
    """OAuth2 token request: ``password`` or ``refresh_token`` grant (closed)."""

    model_config = ConfigDict(extra="forbid")

    grant_type: Literal["password", "refresh_token"]
    username: Annotated[str, StringConstraints(max_length=320)] | None = None
    password: Annotated[str, StringConstraints(max_length=1024)] | None = None
    refresh_token: Annotated[str, StringConstraints(max_length=4096)] | None = None
    scope: Annotated[str, StringConstraints(max_length=512)] | None = None


class TokenResponse(BaseModel):
    """OAuth2 token response (closed). ``access_token`` is a Rendly-issued ES256 JWT."""

    model_config = ConfigDict(extra="forbid")

    access_token: Annotated[str, StringConstraints(max_length=8192)]
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: Annotated[int, Field(ge=1, le=86400)]
    refresh_token: Annotated[str, StringConstraints(max_length=4096)] | None = None
    scope: Annotated[str, StringConstraints(max_length=512)]


class RevokeRequest(BaseModel):
    """RFC 7009-style refresh-token revoke request (closed)."""

    model_config = ConfigDict(extra="forbid")

    token: Annotated[str, StringConstraints(max_length=4096)]
