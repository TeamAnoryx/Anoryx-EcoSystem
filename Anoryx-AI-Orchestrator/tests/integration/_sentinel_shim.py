"""TEST-ONLY Sentinel policy-intake shim (O-004 distribution e2e, ADR-0004 Fork F / F1).

This is a minimal Starlette stand-in for the not-yet-built Sentinel HTTP policy-intake
route. Production Sentinel exposes NO such HTTP route (ADR-0004 honesty boundary: the
documented admin-intake path is a contract, not a shipped endpoint). The shim exists ONLY
so the Orchestrator's outbound distribution engine can make a GENUINE network call to a
real socket and have Sentinel's REAL intake verify + persist the policy.

It does NOT re-implement any verification. The single route:
  1. Requires `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>` and constant-time compares to
     the env token (mirrors Sentinel's real require_admin) → 401 on missing/mismatch.
  2. Reads the RAW request body bytes (the byte-identical signed record the Orchestrator
     forwarded UNCHANGED) and calls Sentinel's REAL `intake_policy(raw_body)`. With
     `session=None`, intake opens its OWN privileged Sentinel session and commits the
     verify → scope-resolve → replay-check → persist + audit pipeline atomically.
  3. Maps the typed IntakeResult to HTTP: Accepted → 200; every rejection → a PERMANENT 4xx
     (RejectedSchema → 422, RejectedReplay → 409, signature/scope rejection → 403). A
     permanent 4xx tells the engine the policy was rejected — do not retry (no amplification).

No secret material, no policy field value, and no signature bytes are ever logged here.
"""

from __future__ import annotations

import hmac
import os

from policy.intake import intake_policy
from policy.results import (
    Accepted,
    RejectedReplay,
    RejectedSchema,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_ADMIN_TOKEN_ENV = "SENTINEL_ADMIN_TOKEN"  # noqa: S105 - env var name, not a secret
_BEARER_PREFIX = "Bearer "


def _http_status_for(result: object) -> int:
    """Map a typed IntakeResult onto the HTTP status the engine interprets.

    Accepted → 200 (success). RejectedSchema → 422, RejectedReplay → 409, and any other
    rejection (RejectedSignature / RejectedScopeMismatch) → 403. Every rejection is a
    PERMANENT 4xx so the engine records `failed` without a retry storm (a rejected
    signature can never become valid by retrying).
    """
    if isinstance(result, Accepted):
        return 200
    if isinstance(result, RejectedSchema):
        return 422
    if isinstance(result, RejectedReplay):
        return 409
    return 403  # RejectedSignature | RejectedScopeMismatch — permanent reject


async def _intake_route(request: Request) -> JSONResponse:
    # Coarse bearer peer-auth (mirrors Sentinel's real require_admin): fail-closed when the
    # token is absent / not a "Bearer " header / mismatched. Constant-time compare.
    expected = os.environ.get(_ADMIN_TOKEN_ENV, "")
    header = request.headers.get("authorization", "")
    presented = header[len(_BEARER_PREFIX) :] if header.startswith(_BEARER_PREFIX) else ""
    if not expected or not presented or not hmac.compare_digest(presented, expected):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    # Delegate ENTIRELY to Sentinel's real intake. The raw bytes are exactly what the
    # Orchestrator forwarded, so the ES256 signature is verified UNCHANGED.
    raw_body = await request.body()
    result = await intake_policy(raw_body)
    return JSONResponse({"result": type(result).__name__}, status_code=_http_status_for(result))


def create_shim_app(intake_path: str = "/admin/policies/intake") -> Starlette:
    """Build the single-route TEST Sentinel intake shim ASGI app."""
    return Starlette(routes=[Route(intake_path, _intake_route, methods=["POST"])])
