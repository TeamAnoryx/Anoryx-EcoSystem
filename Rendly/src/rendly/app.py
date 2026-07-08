"""Rendly auth service — FastAPI app factory (R-003).

Mounts exactly the LOCKED auth surface plus the one protected identity-proof route:

  * ``POST /v1/auth/token``   — password + refresh_token grants (TokenResponse / fixed Error).
  * ``POST /v1/auth/revoke``  — RFC 7009 refresh revoke; 204; idempotent.
  * ``GET  /v1/users/me``     — protected demonstration route (scope ``profile:read``). Proves the
    verify dependency authorizes a request end-to-end; returns the caller's own ``User``.
    HONESTY BOUNDARY: in R-003 this is fixture-backed (the ``UserStore`` seam) — R-004 swaps in the
    DB with no contract change. Identity is read from the verified token, never from request input.

Every non-2xx response is the LOCKED, fixed-message ``Error`` envelope with a correlating
``X-Request-Id``; a closed-schema body-validation failure becomes 400 ``invalid_request`` (not
FastAPI's default 422), and any unexpected error fails closed to 500 ``internal_error`` — traffic
is never passed through on internal failure. Paths are served under ``/v1`` to match the contract
server URL.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth.claims import AccessTokenClaims
from .auth.dependencies import require_scope
from .auth.errors import AuthError, ErrorCode, error_body, new_request_id
from .auth.keys import KeyMaterial
from .auth.refresh import RefreshTokenStore
from .auth.schemas import RevokeRequest, TokenRequest, TokenResponse
from .auth.service import AuthConfig, Clock, TokenService
from .auth.store import UserStore
from .user import User

# Fail-safe body cap: the auth bodies are tiny; reject anything larger BEFORE parsing.
MAX_BODY_BYTES = 65536
# Methods that carry a request body and are therefore subject to the size cap.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or new_request_id()


def create_app(
    *,
    user_store: UserStore,
    refresh_store: RefreshTokenStore,
    key: KeyMaterial,
    config: AuthConfig | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    """Build the Rendly auth FastAPI app over the given stores + ES256 key material."""
    app = FastAPI(title="Rendly Auth", version="1.0.0")
    app.state.key_material = key
    service = TokenService(
        user_store=user_store,
        refresh_store=refresh_store,
        key=key,
        config=config,
        clock=clock,
    )

    @app.exception_handler(AuthError)
    async def _auth_error(request: Request, exc: AuthError) -> JSONResponse:
        rid = _request_id(request)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(exc.code, rid),
            headers={"X-Request-Id": rid},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # A closed-schema violation (extra/unknown key, bad bound, missing field) -> 400, never 422.
        rid = _request_id(request)
        return JSONResponse(
            status_code=400,
            content=error_body(ErrorCode.INVALID_REQUEST, rid),
            headers={"X-Request-Id": rid},
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Fail-closed: never pass traffic through on an internal error; never leak the cause.
        rid = _request_id(request)
        return JSONResponse(
            status_code=500,
            content=error_body(ErrorCode.INTERNAL_ERROR, rid),
            headers={"X-Request-Id": rid},
        )

    @app.middleware("http")
    async def _request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = new_request_id()
        if request.method in _BODY_METHODS:
            # Fail-safe sizing: a body-bearing request MUST declare a parseable Content-Length
            # within the cap. Missing (e.g. chunked Transfer-Encoding) or unparseable fails CLOSED
            # (413), so an oversized body is never buffered into memory before validation.
            content_length = request.headers.get("content-length")
            too_large = True
            if content_length is not None:
                try:
                    too_large = int(content_length) > MAX_BODY_BYTES
                except ValueError:
                    too_large = True
            if too_large:
                rid = request.state.request_id
                return JSONResponse(
                    status_code=413,
                    content=error_body(ErrorCode.REQUEST_TOO_LARGE, rid),
                    headers={"X-Request-Id": rid},
                )
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        # No DB/dependency check (R-010, ADR-0010 Fork G) — mirrors the Orchestrator's
        # single /health probe. A DB-gated /readyz split is a named deferral, not silently
        # worked around.
        return {"status": "ok"}

    router = APIRouter(prefix="/v1")

    @router.post("/auth/token", response_model=TokenResponse)
    def issue_token(body: TokenRequest) -> TokenResponse:
        if body.grant_type == "password":
            return service.issue_password_grant(
                username=body.username, password=body.password, requested_scope=body.scope
            )
        return service.issue_refresh_grant(refresh_token=body.refresh_token)

    @router.post("/auth/revoke", status_code=204)
    def revoke_token(body: RevokeRequest) -> Response:
        service.revoke(body.token)
        return Response(status_code=204)

    @router.get("/users/me", response_model=User)
    def get_my_profile(
        principal: AccessTokenClaims = Depends(require_scope("profile:read")),
    ) -> User:
        user = user_store.get_user(principal.sub, principal.tenant_id)
        if user is None:
            # The token verified but its principal no longer resolves — treat as invalid.
            raise AuthError(ErrorCode.INVALID_TOKEN)
        return user

    app.include_router(router)
    return app
