"""Chat app assembly (R-005) — the WebSocket + chat REST surface over the R-004 DB-backed app.

``create_chat_app`` builds the merged R-003/R-004 auth app (``create_db_app`` — the sync
identity stack, untouched) and ADDS the R-005 chat layer onto it: the ``GET /v1/realtime``
WebSocket route, the chat REST router, and the per-app runtime context (the single-instance
connection registry + the inspection seam). No change to the auth app factory — the chat layer is
purely additive, so R-003/R-004 keep their exact behavior and exception handlers (AuthError ->
the LOCKED Error envelope; closed-schema 400; fail-closed 500) apply to the chat REST routes too.

The inspector defaults to the fail-closed NO-OP (``NoOpMessageInspector``). R-008 passes a real
:class:`MessageInspector` here with NO other change — the send pipeline already calls it
synchronously before persist + fan-out.
"""

from __future__ import annotations

from fastapi import FastAPI

from ..auth.keys import KeyMaterial
from ..auth.service import AuthConfig, Clock
from ..persistence.identity_app import create_db_app
from .inspector import MessageInspector, NoOpMessageInspector
from .pipeline import RuntimeContext
from .registry import ConnectionRegistry
from .rest import router as chat_rest_router
from .ws import realtime_endpoint


def create_chat_app(
    *,
    key: KeyMaterial,
    config: AuthConfig | None = None,
    clock: Clock | None = None,
    inspector: MessageInspector | None = None,
) -> FastAPI:
    """Build the Rendly chat app: the DB-backed auth app + the WebSocket/chat REST layer.

    ``key`` is the ES256 verify/sign material. The async chat engine reads ``DATABASE_URL`` /
    ``APP_DATABASE_URL`` lazily on first use — no URL is passed through or logged here. The
    ``inspector`` defaults to the fail-closed no-op seam (R-008 swaps in real inspection).
    """
    app = create_db_app(key=key, config=config, clock=clock)
    app.state.realtime_ctx = RuntimeContext(
        registry=ConnectionRegistry(),
        inspector=inspector or NoOpMessageInspector(),
    )
    app.add_api_websocket_route("/v1/realtime", realtime_endpoint)
    app.include_router(chat_rest_router)
    return app
