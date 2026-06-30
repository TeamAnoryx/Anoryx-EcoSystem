# ADR-0005 — Rendly Real-Time Chat (R-005)

Status: Accepted
Date: 2026-07-01
Builds on: ADR-0004 (persistence, RLS, the async forward boundary), ADR-0002 (domain), R-001 (the
locked wire contract), R-003 (ES256 auth).

## Context

R-005 implements the real-time chat half of R-001's locked WebSocket catalog over the single
`GET /v1/realtime` upgrade endpoint, plus the minimal chat REST surface (history + channel/member
management). It is the largest Rendly task so far and closes four deferrals at once: Channel +
Membership persistence (deferred at R-004), the async session pattern (R-004 shipped sync), Message
persistence, and the Sentinel inspection seam. It is also Rendly's **second migration** — rule 9
(head-pin bumps + chain reversibility) goes live.

The build order was mandatory and followed: schema + RLS + persistence proven on real Postgres
FIRST, then the WebSocket runtime on top, then the inspection seam.

## Decisions (one per resolved fork)

### Fork A — async session topology: **A1 (async chat layer only)**
A NEW async engine (`postgresql+asyncpg`) + `async get_tenant_session` lives ALONGSIDE the merged
sync engine (`src/rendly/persistence/async_database.py`). R-003/R-004's REST auth keeps the sync
psycopg engine untouched; only the new WebSocket/chat code (and the chat REST routes) use the async
engine. This is exactly the forward boundary ADR-0004 Fork D drew ("R-005 adds its OWN async session
layer alongside this one; the RLS/role/GUC design is driver-agnostic and ports directly"). Least
blast radius — merged auth is not touched. Identity at WS-connect comes OFF the JWT (no DB), so the
hot path needs no sync↔async bridge.

Banked-rule carry-over, now on fresh async code: `async get_tenant_session` AUTOBEGINS (sets the
txn-local GUC before yield) and is NEVER wrapped in `async with session.begin()` (rule 6 — the
double-begin fail-open that shipped F-007 inert and caused the F-009/F-018 fail-opens). The async
engine singleton resets at test SETUP, not only teardown (rule 7). Two engines are now managed.

Rejected: A2 (migrate everything to async — touches merged code, widens blast radius); A3 (sync +
threadpool on the realtime hot path — wrong shape for a WS service).

### Fork B — connection topology: **single-instance in-memory registry + documented seam**
`ConnectionRegistry` keys live sockets by `(tenant_id, channel_id)`. A connection only registers
under its OWN tenant's channels (its membership set is loaded under its own tenant session, so RLS
already scoped it), which makes a fan-out for `(tenantB, channel)` structurally unable to reach a
tenant-A socket — the live-delivery half of tenant isolation. **Stated limitation: single process.**
Cross-instance fan-out (Redis pub/sub or Postgres LISTEN/NOTIFY) is a documented seam, NOT built;
R-010 is single-cluster, so premature pub/sub is unwarranted complexity. A connection's deliverable
channel set is a SNAPSHOT at connect (a member ADDED mid-session receives after reconnect); send
authorization always re-checks LIVE DB membership. A member REMOVED mid-session is evicted from the
live registry immediately (the `DELETE` member REST path calls
`ConnectionRegistry.remove_user_from_channel`), so a revoked member stops receiving at once rather
than at reconnect (post-review hardening); and the send-path membership re-check runs in the SAME
transaction as the persist, so a membership revoked during inspection cannot let one last message
through.

### Fork C — ordering/delivery: **per-channel seq + client ack, no exactly-once**
Each message gets a monotonic per-channel `seq` assigned under a `SELECT ... FOR UPDATE` row lock on
the channel (mirrors `refresh_store`'s rotation lock) — strictly monotonic, gap-free, serialized per
channel. Delivery is best-effort fan-out to live sockets; missed messages are recovered via the
`GET history` keyset endpoint (ordered by `seq`). No exactly-once, no gap-detection, no offline
replay beyond history fetch — stated boundary.

### Fork D — inspection seam: **CONFIRMED — synchronous, pre-persist, pre-fan-out, fail-closed**
The send pipeline (`realtime/pipeline.py`) runs the `MessageInspector` seam IN-LINE BEFORE persist
and BEFORE fan-out. A `pass` proceeds (persist → ack `accepted` → fan out `chat.message`). A
`blocked` verdict, a `seam_unavailable` verdict, OR an inspector that RAISES all yield a `chat.ack`
with `status:"blocked"` (the locked FORK-D reject: `error_code` `message_blocked` for a block,
`inspection_unavailable` for an unavailable/raising seam) and the message is NEVER persisted and
NEVER delivered. An inspector that errors is converted to a fail-closed BLOCK — never a silent pass
(Sentinel non-negotiable #5). R-005 ships only the no-op pass-through; R-008 swaps in real detection
by providing a different `MessageInspector` with no pipeline change.

### Fork E — presence: **ephemeral, connection-derived, not persisted**
Live presence lives in the registry only: `online` at connect, `offline` at disconnect, `away`/
`busy` via `presence.set`; the server broadcasts `presence.update` to connections that share a
channel. **Stated: non-durable** — lost on disconnect / restart; no heartbeat/TTL. The persisted
`users.presence` column is NOT the live-presence source of truth and is not written live by R-005.

### REST surface — Minimal-REST
`POST /v1/channels` (`channels:write`, creator becomes `owner`), `PUT`/`DELETE
/v1/channels/{id}/members/{user_id}` (`channels:admin`), `GET /v1/channels/{id}/messages`
(`chat:read`, member-only). Identity is read SOLELY off the token; a resource in another tenant — or
a channel the caller is not a member of — resolves as a tenant-scoped 404 (no existence oracle). The
channel list/get/patch/archive + member-list endpoints, and the Delta-team auto-mapping, are NOT
built here.

## The DB-layer proof of the cross-tenant membership invariant
Migration 0002 gives `memberships` two same-tenant composite FKs — `(tenant_id, channel_id) →
channels` and `(tenant_id, user_id) → users`. Both carry `tenant_id`, so a membership row's tenant
must equal BOTH the channel's and the user's tenant; a cross-tenant pair is structurally
unconstructible at the DB. This re-proves R-002's `bind_membership` invariant at the storage layer
(the app `ValueError` is the first gate, the composite FK + RLS are the next two).

## Honesty boundaries (verbatim — non-removable)
- **Chat only, NOT signaling.** R-005 implements the 8 chat-family frames + `session.welcome` +
  `error`. The 1-on-1 huddle/signaling frames (`huddle.*`, `signal.*`) are R-007; the frame
  dispatcher is built so R-007 ADDS those handlers without rearchitecting, but NONE are implemented
  here (a `huddle.*`/`signal.*` frame received in R-005 is answered `huddle_unavailable`).
- **Seam only, NOT inspection.** Only the fail-closed no-op `MessageInspector` is built; real PII /
  injection / secret detection is R-008.
- **Archival fields only, NOT immutability.** Messages carry the R-009 hash-chain-ready fields
  (`record_id`, `seq`, `created_at`); the hash columns persist NULL and no chain is computed. Messages
  are append-only by GRANT (rendly_app has SELECT,INSERT — no UPDATE/DELETE); cryptographic
  immutability (the chain) is R-009.
- **Single-instance, NOT multi.** The connection registry is in-process; cross-instance fan-out is a
  documented seam.
- **Delta-mapping columns nullable, NOT mapped.** `source`/`external_ref` persist nullable; the
  Delta-team auto-mapping logic is R-006.

## Consequences
- R-006 maps channels to Delta teams by populating `source`/`external_ref` — columns already
  persisted nullable.
- R-007 adds the huddle/signaling handlers to the same WS dispatcher + the ICE endpoint — no
  contract change.
- R-008 replaces `NoOpMessageInspector` with a real inspector — the fail-closed wiring is already in
  the send path.
- R-009 archives the persisted messages and computes the hash chain over `seq` — the archival fields
  are already populated and the hash columns reserved.
- R-010 deploy hardening (carried from the R-004 audit): do not run request-path lookups as a DB
  superuser; the async privileged engine inherits the same note.
