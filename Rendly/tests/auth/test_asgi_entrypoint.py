"""``rendly.asgi.create_app_from_env`` — the uvicorn --factory entrypoint (R-010, ADR-0010).

Constructing the chat app requires no live Postgres (every DB-backed collaborator resolves
its engine lazily on first use — see ``persistence/identity_app.py``), so this runs in the
no-DB CI lane like the rest of tests/auth.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from rendly.asgi import create_app_from_env
from rendly.auth.keys import KeyConfigError


def test_create_app_from_env_builds_the_full_chat_app(monkeypatch, private_pem: str):
    monkeypatch.setenv("RENDLY_JWT_PRIVATE_KEY_PEM", private_pem)
    app = create_app_from_env()
    client = TestClient(app)

    assert client.get("/health").status_code == 200

    # The R-003 auth surface is mounted (a bad grant is a well-formed 400, not a 404 —
    # proving the router is actually included, not just present in the app object).
    resp = client.post("/v1/auth/token", json={"grant_type": "password"})
    assert resp.status_code != 404

    # The R-005..R-009 realtime layer is mounted too (added directly via
    # add_api_websocket_route, so it appears as a top-level route rather than wrapped in an
    # _IncludedRouter like the auth/chat REST routers above).
    from fastapi.routing import APIWebSocketRoute

    assert any(
        isinstance(route, APIWebSocketRoute) and route.path == "/v1/realtime"
        for route in app.routes
    )


def test_create_app_from_env_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("RENDLY_JWT_PRIVATE_KEY_PEM", raising=False)
    with pytest.raises(KeyConfigError):
        create_app_from_env()
