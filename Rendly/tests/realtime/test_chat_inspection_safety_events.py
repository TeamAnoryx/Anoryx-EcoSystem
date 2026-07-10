"""X-004 integration test: the REAL R-008 pipeline wired to the REAL ``safety_event_emitter``.

Mirrors ``test_chat_inspection_sentinel.py``'s style (real Postgres, real in-process ASGI
WebSocket, the real ``SentinelMessageInspector`` — not a test fake) and adds ONE more real
component: a lightweight local HTTP sink standing in for the Anoryx-AI-Orchestrator's
``POST /v1/safety/events`` (a genuine socket + a genuine ``httpx`` round-trip out of
``safety_event_emitter.py`` — nothing about the Rendly-side emission logic is stubbed). This is
NOT the "two real apps" e2e (that is a later, separate task that drives Rendly's real pipeline
AND the Orchestrator's real ingestion endpoint together) — this proves Rendly's own emission is
real and correctly shaped, using a sink instead of the real Orchestrator specifically because the
Orchestrator's runtime is being built concurrently and is not available to this task in isolation.

Because ``emit_block_events_best_effort`` is fire-and-forget (ADR-0026: it must never delay the
``chat.ack``), the notification can still be in flight after the WebSocket ack/audit-row
assertions complete — tests poll the sink with a bounded timeout rather than a fixed sleep.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from sqlalchemy import text

from chatdata import recv_until
from rendly.realtime.safety_event_emitter import (
    ORCHESTRATOR_SAFETY_TOKEN_ENV,
    ORCHESTRATOR_SAFETY_URL_ENV,
)
from rendly.realtime.sentinel_inspector import SentinelMessageInspector

_REALTIME = "/v1/realtime"
_FULL_SCOPE = "channels:write channels:admin chat:read chat:write"
_TOKEN = "test-rendly-safety-source-token"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_channel(client, *, owner_token, name="c") -> str:
    resp = client.post(
        "/v1/channels", json={"name": name, "type": "private"}, headers=_auth(owner_token)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["channel_id"]


def _audit_rows(tenant_id: str) -> list:
    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as session:
        return (
            session.execute(
                text(
                    "SELECT audit_id, channel_id, status FROM rendly.inspection_audit_log "
                    "WHERE tenant_id=:t"
                ),
                {"t": tenant_id},
            )
            .mappings()
            .all()
        )


def _send(ws, *, client_msg_id: str, channel_id: str, content: str) -> None:
    ws.send_json(
        {
            "msg_type": "chat.send",
            "client_msg_id": client_msg_id,
            "channel_id": channel_id,
            "content": content,
            "content_type": "text",
        }
    )


@dataclass
class _CapturedRequest:
    path: str
    headers: dict
    body: dict | None


class _CapturingHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming convention
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        self.server.requests.append(  # type: ignore[attr-defined]
            _CapturedRequest(
                path=self.path,
                headers=dict(self.headers.items()),
                body=json.loads(raw) if raw else None,
            )
        )
        payload = json.dumps({"status": "accepted", "disposition": "accepted"}).encode()
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:  # silence default stderr access log
        pass


@contextmanager
def _safety_events_sink() -> Iterator[http.server.ThreadingHTTPServer]:
    """A real local HTTP server standing in for the Orchestrator's ``/v1/safety/events``."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _wait_for_requests(
    server: http.server.ThreadingHTTPServer, *, count: int, timeout: float = 3.0
) -> list[_CapturedRequest]:
    """Bounded poll (fire-and-forget delivery — no guaranteed ordering vs. the test thread)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        requests = list(server.requests)  # type: ignore[attr-defined]
        if len(requests) >= count:
            return requests
        time.sleep(0.05)
    return list(server.requests)  # type: ignore[attr-defined]


@pytest.fixture
def safety_sink(monkeypatch: pytest.MonkeyPatch) -> Iterator[http.server.ThreadingHTTPServer]:
    """Configure the emitter at a real local sink for the duration of one test."""
    with _safety_events_sink() as server:
        host, port = server.server_address
        monkeypatch.setenv(ORCHESTRATOR_SAFETY_URL_ENV, f"http://{host}:{port}")
        monkeypatch.setenv(ORCHESTRATOR_SAFETY_TOKEN_ENV, _TOKEN)
        yield server


def test_pii_block_emits_one_safety_event_with_correct_shape(
    make_client, seed_user, mint_token, new_uuid, safety_sink
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=SentinelMessageInspector())
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    channel_id = _make_channel(client, owner_token=owner_tok)

    with client.websocket_connect(_REALTIME, headers=_auth(owner_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        _send(
            ws, client_msg_id="c-pii", channel_id=channel_id, content="email me at bob@example.com"
        )
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "blocked"  # the local block/ack decision, unaffected by X-004

    # The local trail (ADR-0008, unchanged) is already durable by the time the ack was sent.
    audits = _audit_rows(tenant)
    assert len(audits) == 1
    audit_id = audits[0]["audit_id"]

    requests = _wait_for_requests(safety_sink, count=1)
    assert len(requests) == 1
    request = requests[0]
    assert request.path == "/v1/safety/events"
    assert request.headers["Authorization"] == f"Bearer {_TOKEN}"
    body = request.body
    assert body["tenant_id"] == tenant
    assert body["category"] == "pii"
    assert body["outcome"] == "block"
    assert body["target"] == channel_id  # opaque channel id, never message content
    assert "bob@example.com" not in json.dumps(body)  # metadata only — never the offending content
    assert body["idempotency_key"] == f"rendly-inspection-{audit_id}-pii"
    assert "occurred_at" in body
    # never sent by Rendly — the Orchestrator server-resolves source_product from the bearer.
    assert "source_product" not in body


def test_multi_category_block_emits_one_event_per_category(
    make_client, seed_user, mint_token, new_uuid, safety_sink
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=SentinelMessageInspector())
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    channel_id = _make_channel(client, owner_token=owner_tok)

    # Trips BOTH pii (email) and secret (AWS-key-shaped token) in one message.
    content = "contact bob@example.com — key: " + "AKIA" + "IOSFODNN7EXAMPLE"

    with client.websocket_connect(_REALTIME, headers=_auth(owner_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        _send(ws, client_msg_id="c-multi", channel_id=channel_id, content=content)
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "blocked"

    requests = _wait_for_requests(safety_sink, count=2)
    assert len(requests) == 2
    categories = {r.body["category"] for r in requests}
    assert categories == {"pii", "secret"}
    keys = {r.body["idempotency_key"] for r in requests}
    assert len(keys) == 2  # one distinct idempotency key per category


def test_clean_message_emits_no_safety_event(
    make_client, seed_user, mint_token, new_uuid, safety_sink
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=SentinelMessageInspector())
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    channel_id = _make_channel(client, owner_token=owner_tok)

    with client.websocket_connect(_REALTIME, headers=_auth(owner_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        _send(ws, client_msg_id="c-clean", channel_id=channel_id, content="see you at lunch today")
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "accepted"

    # A short bounded wait proves absence (not just "hasn't arrived yet") without a fixed sleep
    # masquerading as a real check — same bounded-poll helper, just asserting it stays at 0.
    requests = _wait_for_requests(safety_sink, count=1, timeout=0.5)
    assert requests == []


def test_pii_block_without_orchestrator_configured_still_blocks_and_audits_normally(
    make_client, seed_user, mint_token, new_uuid, monkeypatch: pytest.MonkeyPatch
):
    """The default (no Orchestrator env vars set) deployment posture: X-004 is a pure no-op and
    R-008's own block/audit behavior is completely unaffected (no crash, no delay, no change)."""
    monkeypatch.delenv(ORCHESTRATOR_SAFETY_URL_ENV, raising=False)
    monkeypatch.delenv(ORCHESTRATOR_SAFETY_TOKEN_ENV, raising=False)

    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=SentinelMessageInspector())
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    channel_id = _make_channel(client, owner_token=owner_tok)

    with client.websocket_connect(_REALTIME, headers=_auth(owner_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        _send(
            ws, client_msg_id="c-pii2", channel_id=channel_id, content="email me at bob@example.com"
        )
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "blocked"

    audits = _audit_rows(tenant)
    assert len(audits) == 1
    assert audits[0]["status"] == "blocked"
