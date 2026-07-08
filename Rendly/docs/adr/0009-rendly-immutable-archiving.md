# ADR-0009 — Rendly Immutable Archiving: Message + Huddle Hash Chains (R-009)

Status: Accepted
Date: 2026-07-07
Builds on: ADR-0001 D3 (the DEFINE-ONLY ``ArchivalMeta`` wire shape, locked ahead of this task),
ADR-0007 Fork A ("R-009... can start persisting at the exact `ended`/`declined` transition point
this task already computes"), ADR-0008's closing note ("this is ALSO, deliberately, NOT the R-009
hash chain... R-009 still owns turning `messages` into a hash-chained archive"), the roadmap's
own instruction to reuse "the Sentinel F-003 audit pattern."

## Context

R-001 reserved two archival fields on every durable record (`prev_record_hash`/`content_hash`,
`contracts/messages.schema.json` `ArchivalMeta`) and R-005/R-007/R-008 left them DEFINE-ONLY —
always `null` on `messages`, and huddle sessions were never persisted at all (ADR-0007 Fork A:
ephemeral, in-memory only). R-009 closes both gaps: it turns `messages.prev_record_hash`/
`content_hash` into a real chain, and it gives a huddle's terminal `ended` state a durable,
equally-chained session record. The roadmap frames this as "regulatory compliance + internal
security audits (Sentinel F-003 audit pattern applied to comms)."

`ArchivalMeta.seq`'s own doc string already commits to the SCOPE: "Monotonic per-channel
(messages) / per-tenant (huddles) ordering sequence." So — unlike Sentinel's F-003, which runs
ONE global chain across every tenant in a single `events_audit_log` table — Rendly needed TWO
independent, scoped chain families from the start. That drove every fork below.

## Decisions (one per resolved fork)

### Fork A — chain scope + lock: **A1 (reuse the existing per-scope row lock as the tip holder; no privileged/BYPASSRLS session)**

Messages already serialize concurrent sends per channel via a `SELECT ... FOR UPDATE` lock on
the `channels` row (migration 0002 FORK C, for `next_seq`). R-009 reuses that SAME lock and adds
one column, `channels.last_row_hash` (migration 0004), read/written in the SAME transaction as
`next_seq` — no extra query, no extra lock, and the seq assignment + chain link are always
computed together. Huddles have no analogous existing lock target (a huddle isn't channel-scoped
— ADR-0007 Fork B), so R-009 adds a small companion table, `huddle_chain_state` (one row per
tenant, lazily upserted via `INSERT ... ON CONFLICT DO NOTHING` on a tenant's first archived
huddle), that plays the exact role `channels` plays for messages: lock it, read `next_seq`/
`last_row_hash`, insert the archival row, advance both.

Both chains stay entirely within Rendly's existing tenant-RLS session (`rendly_app`,
NOBYPASSRLS, `persistence/async_database.get_tenant_session`) — unlike Sentinel, which needs a
privileged/BYPASSRLS session + a `pg_advisory_xact_lock` because its chain is GLOBAL across
tenants. A per-(tenant,channel) / per-tenant row lock is sufficient here because each chain's
"global order" is scoped to begin with; there is no cross-tenant ordering claim to protect.

Rejected: B (a `pg_advisory_xact_lock`, Sentinel's own mechanism, keyed by a hash of
`tenant_id`/`channel_id`) — works, but adds a second locking primitive to reason about for no
benefit over a row lock Rendly already has (messages) or can cheaply add (huddles) within the
existing tenant-RLS session; Sentinel needed the advisory lock specifically because ITS chain
spans a privileged session with no natural per-scope row to lock.

### Fork B — hashing algorithm: **B1 (verbatim Sentinel F-003 algorithm: SHA-256 over sort-keys canonical JSON, an explicit per-record-kind field list, genesis-or-tip `prev_record_hash`)**

`persistence/hash_chain.py` mirrors `Anoryx-Sentinel/src/persistence/hash_chain.py` field for
field: `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)` then
`hashlib.sha256(...).hexdigest()`; a fixed, explicit `..._CANONICAL_FIELDS` tuple per record
kind (a field present in the tuple but absent from the input dict folds in as `null` rather than
being silently dropped — the same omission-attack guard Sentinel documents); `prev_record_hash`
always last in each tuple. Two record kinds needed two field lists
(`MESSAGE_CANONICAL_FIELDS`/`HUDDLE_CANONICAL_FIELDS`) and two genesis constants
(`MESSAGE_GENESIS_HASH`/`HUDDLE_GENESIS_HASH`, each `sha256("rendly:<domain>:genesis:v1")` —
domain-separated and reproducible, never hand-hardcoded), since messages and huddles hash
disjoint field sets over independently-scoped chains.

Rejected: reusing ONE shared genesis constant for both kinds — harmless in practice (the
per-record fields differ enough that a collision is not a real risk), but domain separation is
free and removes any argument that a message row and a huddle row could ever hash-collide at
the genesis boundary.

### Fork C — Message/HuddleArchive shape: **C1 (optional hash fields on `Message`; a new thin `HuddleArchive` value object, not fields on the mutable `Huddle`)**

`Message` (`realtime/message.py`) gains `prev_record_hash`/`content_hash` as OPTIONAL fields
(default `None`) — the same backward-compat posture `detectors` already established for
pre-R-008 rows: a `Message` rebuilt from a row inserted BEFORE this migration has no chain to
link into and stays `None` forever; every row inserted since carries real values. `Huddle`
(`realtime/huddle.py`) stays exactly as ADR-0007 left it (mutable, LIVE-state-only, no archival
fields) — a new frozen `HuddleArchive` dataclass carries the persisted record
(`huddle_id`/`created_at`/`seq`/`prev_record_hash`/`content_hash`) that
`persistence/huddle_repo.archive_ended_huddle` returns and `realtime/frames.py`'s
`build_huddle_update(archive=...)` renders into the wire `archival` object. This keeps the
LIVE/ARCHIVAL split ADR-0007 already drew (ephemeral manager state vs. the durable record)
instead of retrofitting DB-shaped fields onto the in-memory `Huddle`.

**Superseded from ADR-0007 Fork C:** the huddle archival `seq` was, pre-R-009, an
in-process-only `HuddleManager` counter (`itertools.count` per tenant, reset on restart,
disclosed as a stated single-instance limitation). R-009 replaces it with a DB-assigned `seq`
from `huddle_chain_state.next_seq`, computed atomically with the hash chain under the same
lock — the ephemeral counter is now dead code and removed (`HuddleManager.next_seq`/`_seq`). The
wire-visible `archival.seq` value changes source (durable, not in-memory) but not shape (still a
plain non-negative int); no existing test pinned an exact prior value (only `isinstance(...,
int)`), so this is a strict correctness improvement with no observable-contract break.

### Fork D — huddle archive write timing + failure mode: **D1 (synchronous DB write before the `ended` broadcast; best-effort — a write failure degrades to no `archival` field, never blocks the broadcast)**

Both transition points that end a huddle (`handle_huddle_hangup` in `realtime/pipeline.py`, and
the disconnect cleanup in `realtime/ws.py`) now `await` `archive_ended_huddle_best_effort`
BEFORE building the `huddle.update ended` frame, so the wire's `archival.seq`/hash fields and
the persisted row are always the SAME values (no separate in-memory vs. DB-derived seq to drift
apart, closing the gap Fork C's superseded design had). The call is wrapped to catch any
exception and return `None` on failure — mirrors `_record_inspection_audit`'s established
posture exactly: the huddle has ALREADY ended from both peers' perspective (signaling/media
already stopped) by the time this runs, so a DB outage here must not turn an ended call into a
stuck/undelivered state. `build_huddle_update` already treats `archive=None` as "omit
`archival`" (unchanged from the pre-R-009 declined-call case), so this degrades gracefully to
exactly the R-007 behavior a huddle had before this task, on the specific `ended` broadcast a
failed archive write affects — never a fabricated/partial `archival` object.

**HONESTY BOUNDARY (verbatim, non-removable):** the `ended` huddle.update broadcast is not
gated on a successful archive write — a DB outage at the exact moment of hangup silently loses
that one session record's archival trail (the two peers still see `state: "ended"` normally,
just without `archival`). This mirrors the SAME accepted trade-off ADR-0008 made for
`inspection_audit_log` writes, for the same reason: the primary user-facing action (the call
ending / the send being blocked) must never be held hostage to a secondary audit trail's
durability.

**Discovered during testing — the disconnect-triggered path needs `anyio.CancelScope(shield=True)`:**
`realtime/ws.py`'s disconnect cleanup runs inside the WebSocket connection's OWN teardown, which
Starlette/anyio has already begun cancelling by the time a dropped socket reaches that code (the
non-stubbed e2e test suite reproduced this as a genuine, deterministic hang, not a flake). The
in-process, non-suspending `registry`-based sends elsewhere in that same cleanup never hit a real
suspension point and so were never affected — but the archive write's brand-new DB connection
IS real socket I/O that suspends the coroutine, and an unshielded suspension inside an already-
cancelled scope gets re-cancelled there. Left unshielded, this doesn't just skip the archive: the
`CancelledError` propagates out and aborts the cleanup *before* the peer is ever notified the
huddle ended — silently losing the ENTIRE notification, a strictly worse outcome than "ended, no
archival" and one D1 above did not intend. `realtime/ws.py` wraps the archive call AND the
subsequent peer `send` (both are needed — an unshielded send after a shielded archive reproduces
the same hang one step later) in one `with anyio.CancelScope(shield=True):` block. The
hangup-triggered call site (`handle_huddle_hangup`) runs in an uncancelled context and needed no
such change. `anyio` was already an installed transitive dependency (via `starlette`); this task
makes it an explicit direct one (`pyproject.toml`) since `realtime/ws.py` now imports it.

### Fork E — scope: messages + huddles only, `inspection_audit_log` NOT chained here

ADR-0008 explicitly left the door open ("R-009... MAY choose to extend [`inspection_audit_log`]
with the hash chain"). This task does NOT: the roadmap's R-009 description is "comms + video
logs" (messages + huddles), `inspection_audit_log` already has its own disclosed, accepted
posture as "a plain append-only log, NOT a hash-chained tamper-evident audit trail" (ADR-0008),
and chaining it would need a THIRD scope decision (per-tenant, like huddles — it has no
channel-lock-equivalent either) with no concrete requirement driving it yet. Extending it is a
clean, mechanically-identical follow-up (reuse `hash_chain.py`, add a fourth
`..._CANONICAL_FIELDS` tuple, a `last_row_hash` analog) whenever a real need appears — deferred,
not forgotten, not silently implied as done.

**HONESTY BOUNDARY (verbatim, non-removable):** "immutable archiving" in this task covers
`messages` and `huddles` only. `inspection_audit_log` remains a plain, non-chained append-only
log after this PR.

## Chain coverage boundary

Any `messages` row inserted BEFORE this migration has `prev_record_hash`/`content_hash` NULL
forever — there was no chain yet for it to link into. A chain walk/verifier over a channel's
message history must start from the first row carrying a real hash, not assume the channel's
first-ever message is the chain's genesis link. `huddles` carries no such gap (the table itself
is new in this migration — every row it will ever hold has real, non-null hash columns, enforced
by a NOT NULL + hex-format CHECK constraint at the DB layer).

## Consequences

- Every `messages` row inserted from this migration forward is part of a real, verifiable,
  per-channel SHA-256 hash chain; `huddles` gains its first-ever durable session record, chained
  per tenant, exactly as ADR-0007 anticipated.
- No REST/admin read surface or a `validate_chain`-style verifier is built here (mirrors
  ADR-0008's own precedent of shipping the data layer before the read/verify surface) — a
  follow-up task owns walking/verifying the chain and any admin-facing tamper report.
- `inspection_audit_log` remains explicitly un-chained (Fork E) — a disclosed scope boundary,
  not an oversight.
- `realtime/ws.py`'s disconnect-triggered huddle-end path now depends directly on `anyio`
  (Fork D addendum) — the one place in Rendly's realtime layer that shields cleanup work from
  an already-cancelled connection scope, discovered by the non-stubbed e2e suite reproducing a
  genuine hang, not inferred from code review alone.
- `HuddleManager.next_seq`/`_seq` (the ADR-0007 in-process archival counter) is removed —
  superseded by the DB-assigned, chain-consistent `seq` this task introduces (Fork C).
