"""TEST Sentinel app for the O-004 distribution e2e (X-003, ADR-0042 — real route).

This app serves Sentinel's REAL production policy-intake route. As of X-003
(ADR-0042) Sentinel ships `POST /admin/policies/intake` on the real `admin_router`
(`Anoryx-Sentinel/src/admin/policies.py`, mounted in `src/admin/router.py`) — a thin,
fail-closed ingress wrapper over the SAME `intake_policy()` pipeline `sentinel-cli
policy push` already calls in-process. The earlier "Production Sentinel exposes NO
such HTTP route" note is OBSOLETE: this shim used to hand-roll a Starlette route +
a hand-rolled bearer check as a stand-in for the not-yet-built endpoint; it now
mounts the ACTUAL router so the e2e exercises the real route and the real
`require_admin` / `reject_sso_global` auth.

INTAKE (`/admin/policies/intake`) — the REAL route, nothing re-implemented here:
  * We build a real FastAPI app and `include_router(admin_router)`. The admin router's
    router-level `require_admin` dependency authenticates the break-glass
    `SENTINEL_ADMIN_TOKEN` bearer (constant-time compare) — the exact bearer O-004
    sends — and the policies router's `reject_sso_global` allows that break-glass
    principal through while 403'ing any SSO operator-session. A missing / wrong
    bearer is a REAL 401 from `require_admin` (not a hand-rolled check).
  * The route reads `request.state.raw_body` if a middleware set it and otherwise
    falls back to `await request.body()` — it was designed for exactly this "bare
    test app with no gateway middleware" case — so the byte-identical signed record
    the Orchestrator forwarded reaches `intake_policy()` UNCHANGED and the ES256
    signature is verified against the same bytes.
  * The route maps the typed IntakeResult to HTTP + the standard `Error` envelope
    itself (200 Accepted; 422 schema; 403 signature `policy_intake_signature_rejected`;
    409 scope / replay). The engine keys off the status code (a permanent 4xx → no
    retry storm), so this is transparent to the existing allow/deny/forged tests.

The OTHER routes below are UNCHANGED test stand-ins (Sentinel's real gateway/readiness
surface is out of scope for the Orchestrator's own suite — each has its own boundary
note): a `/healthz` probe (O-005) and the `_make_chat_route` relay-target stand-in
(O-009). Only the policy-intake path is the real route.

No secret material, no policy field value, and no signature bytes are logged here.
"""

from __future__ import annotations

import hmac

from admin.router import admin_router
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

_BEARER_PREFIX = "Bearer "


async def _health_route(request: Request) -> JSONResponse:
    """TEST Sentinel health probe (O-005). The documented-contract stand-in for a readiness
    route Sentinel does not yet ship (ADR-0005 honesty boundary E1) — a reachability signal,
    NOT a verified-enforcing signal. No auth (a health probe carries no secret)."""
    return JSONResponse({"status": "ok"}, status_code=200)


def _make_chat_route(chat_token: str):
    """Build the O-009 relay-target stand-in route, closed over its expected tenant key.

    UNLIKE the intake route (which mounts Sentinel's REAL `/admin/policies/intake`), this does
    NOT delegate to any real Sentinel code — Sentinel's real `/v1/chat/completions`
    (F-001/F-004/F-006, already SHIPPED) requires a live provider adapter + DB-backed
    virtual-key resolution that is out of scope to stand up in the Orchestrator's own test suite
    (ADR-0009 honesty boundary: this e2e proves the RELAY mechanism — registry-gated,
    SSRF-checked, single-attempt, audited dispatch — not Sentinel's own gateway behavior, which
    has its own dedicated Sentinel-side test suite). It checks a Bearer tenant key (mirroring
    Sentinel's real virtual-API-key auth: right key -> 200 with a canned OpenAI-compatible body,
    wrong/missing key -> 401) purely so the e2e can prove the relay forwards the caller-supplied
    X-Sentinel-Authorization value UNCHANGED and returns Sentinel's real status/body transparently.
    """

    async def _chat_route(request: Request) -> JSONResponse:
        header = request.headers.get("authorization", "")
        presented = header[len(_BEARER_PREFIX) :] if header.startswith(_BEARER_PREFIX) else ""
        if not presented or not hmac.compare_digest(presented, chat_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        return JSONResponse(
            {
                "id": "chatcmpl-shim-test",
                "object": "chat.completion",
                "model": body.get("model", "unknown"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "shim response"},
                        "finish_reason": "stop",
                    }
                ],
            },
            status_code=200,
        )

    return _chat_route


def create_shim_app(
    intake_path: str = "/admin/policies/intake",
    health_path: str = "/healthz",
    *,
    chat_path: str = "/v1/chat/completions",
    chat_token: str = "shim-tenant-sentinel-key",  # noqa: S107 - test-only fake
) -> FastAPI:
    """Build the TEST Sentinel ASGI app: the REAL admin policy-intake route + test stand-ins.

    The policy-intake path is served by Sentinel's REAL `admin_router` (X-003 / ADR-0042) so the
    e2e drives the actual production route + `require_admin`/`reject_sso_global` auth — the caller
    must set SENTINEL_ADMIN_TOKEN so `require_admin` accepts O-004's break-glass bearer. `/healthz`
    (O-005) and the O-009 relay-target chat stand-in are re-added as test-only routes.

    `intake_path` is retained for call-site compatibility; the real route's path is fixed at
    `/admin/policies/intake` by `admin_router` (prefix `/admin`) + `policies_router`
    (`/policies/intake`). Both call sites pass exactly that value, so it always matches.
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    # The REAL Sentinel admin router — includes the real POST /admin/policies/intake, gated by
    # the real require_admin (break-glass SENTINEL_ADMIN_TOKEN) + reject_sso_global. Nothing
    # about intake auth or mapping is re-implemented in this test file anymore.
    app.include_router(admin_router)
    # Test-only stand-ins for the OTHER suites (unchanged behavior).
    app.add_api_route(health_path, _health_route, methods=["GET"])
    app.add_api_route(chat_path, _make_chat_route(chat_token), methods=["POST"])
    return app
