"""Agent mailbox relay + shared state store (O-012, ADR-0012).

Two independent, intra-tenant, Postgres-backed primitives:

  A. an agent-to-agent MESSAGE RELAY — durable, ordered, poll-based (NOT push, NOT
     sub-millisecond);
  B. a shared KEY-VALUE STATE STORE with optimistic concurrency (compare-and-swap via a
     version number — NOT distributed consensus, NOT "flawless" cross-product sync).

Named `messaging`, not `automation`/`relay` — this is a new capability area, distinct from
O-011's automation-rules engine and O-009's inter-app relay. See docs/adr/0012-agent-
messaging-and-state.md for the honesty boundaries this module deliberately stays inside.
"""

from __future__ import annotations
