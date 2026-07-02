"""Importable helpers + test inspectors for the chat suite.

Kept out of conftest.py so the test modules can import these by name (pytest puts this directory
on sys.path); conftest holds only the auto-injected fixtures. These inspectors exercise the
fail-closed seam: a blocking / unavailable / raising inspector must stop the send before persist
+ fan-out.
"""

from __future__ import annotations

from datetime import datetime, timezone

from rendly.realtime.inspector import InspectionOutcome, MessageInspector

# Frame types that may interleave ahead of the one a test is waiting for (presence/typing/welcome).
_TRANSIENT = {"session.welcome", "presence.update", "typing.update"}


def recv_until(ws: object, msg_type: str, *, max_frames: int = 12) -> dict:
    """Receive frames until one of type ``msg_type`` arrives (skipping transient broadcasts)."""
    for _ in range(max_frames):
        frame = ws.receive_json()
        if frame.get("msg_type") == msg_type:
            return frame
        if frame.get("msg_type") in _TRANSIENT:
            continue
        # A non-transient, non-target frame is an unexpected result for this wait.
        raise AssertionError(f"expected {msg_type}, got {frame.get('msg_type')}: {frame}")
    raise AssertionError(f"did not receive a {msg_type} frame within {max_frames} frames")


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def make_channel(client: object, owner_token: str, *, members=(), name: str = "c") -> str:
    """POST a channel as the owner and add (user_id, role) members; return the channel id."""
    resp = client.post(
        "/v1/channels", json={"name": name, "type": "private"}, headers=auth(owner_token)
    )
    assert resp.status_code == 201, resp.text
    channel_id = resp.json()["channel_id"]
    for user_id, role in members:
        r = client.put(
            f"/v1/channels/{channel_id}/members/{user_id}",
            json={"role": role},
            headers=auth(owner_token),
        )
        assert r.status_code == 200, r.text
    return channel_id


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AllBlockInspector(MessageInspector):
    """Blocks every message (R-008 stand-in for the block path)."""

    async def inspect(self, **_: object) -> InspectionOutcome:
        return InspectionOutcome(status="blocked", evaluated_at=_now())


class MarkerBlockInspector(MessageInspector):
    """Blocks only content containing ``marker``; passes everything else.

    Lets a single test prove BOTH halves of fail-closed: the marked message is blocked (not
    persisted, not delivered) while a following clean message passes (persisted + delivered),
    so the clean message arriving first at the receiver proves the blocked one never went out.
    """

    def __init__(self, marker: str) -> None:
        self._marker = marker

    async def inspect(self, *, content: str, **_: object) -> InspectionOutcome:
        status = "blocked" if self._marker in content else "pass"
        return InspectionOutcome(status=status, evaluated_at=_now())


class UnavailableInspector(MessageInspector):
    """Returns seam_unavailable — the seam could not complete (fail-closed BLOCK)."""

    async def inspect(self, **_: object) -> InspectionOutcome:
        return InspectionOutcome(status="seam_unavailable", evaluated_at=_now())


class RaisingInspector(MessageInspector):
    """Raises — an inspector that errors must be converted to a fail-closed BLOCK, never a pass."""

    async def inspect(self, **_: object) -> InspectionOutcome:
        raise RuntimeError("inspection backend exploded")
