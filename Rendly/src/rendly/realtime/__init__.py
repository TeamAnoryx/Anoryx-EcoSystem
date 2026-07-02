"""Rendly real-time chat runtime (R-005).

The WebSocket chat layer that implements R-001's LOCKED chat message catalog over the single
``GET /v1/realtime`` upgrade endpoint, plus the minimal chat REST surface (history + channel /
member management). Built on the R-004 RLS persistence (``rendly`` schema, ``rendly_app``
NOBYPASSRLS) via a NEW async session layer (ADR-0004 Fork D forward boundary; ADR-0005 Fork A).

HONESTY BOUNDARIES (verbatim — see ADR-0005):
  * CHAT ONLY, not signaling. R-005 implements the 8 chat-family frames + session.welcome +
    error. The 1-on-1 huddle/signaling frames (huddle.*, signal.*) are R-007; the frame
    dispatcher is built so R-007 ADDS those handlers without rearchitecting, but NONE are
    implemented here.
  * SEAM ONLY, not inspection. The send path calls a ``MessageInspector`` seam synchronously
    BEFORE persist + fan-out; R-005 ships only the fail-closed NO-OP. Real PII/injection/secret
    detection is R-008.
  * ARCHIVAL FIELDS ONLY, not immutability. Messages carry the R-009 hash-chain-ready fields
    (record_id, seq, created_at); the hash columns persist NULL and no chain is computed here.
  * SINGLE-INSTANCE, not multi. The connection registry is in-process; cross-instance fan-out
    (Redis/LISTEN-NOTIFY) is a documented seam, not built.

This package is intentionally light at import time (no eager runtime imports) so the pure
domain type :mod:`rendly.realtime.message` can be imported by the persistence layer without a
cycle. Import the app assembler explicitly via :mod:`rendly.realtime.app`.
"""

from __future__ import annotations
