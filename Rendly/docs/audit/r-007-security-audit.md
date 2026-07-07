# R-007 Security Audit — Rendly 1-on-1 Huddle Signaling + Self-Hosted ICE/TURN

Verdict: **CLEAN** (no High/Critical). Independent red-team security-auditor (Opus), static
tracing on the R-007 diff. R-007 is a new client->server input surface (WebRTC signaling over the
live WS + a TURN-credential-minting REST endpoint), so session hijack, cross-tenant relay, an
existence oracle on the invite path, and TURN-credential forgery were the headline attack surfaces.

Scope reviewed: `src/rendly/realtime/{huddle.py, ice.py, pipeline.py, frames.py, ws.py, rest.py,
registry.py, app.py}`, `src/rendly/realtime/inspector.py` (the reused seam), `src/rendly/
persistence/chat_repo.py` (`load_user`/`load_channel`/`is_member` RLS scoping), ADR-0007, and the
R-007 tests. Contract shape (`contracts/messages.schema.json` `$defs` + `contracts/openapi.yaml`
`/huddles/ice-servers`) was treated as LOCKED (R-001) — only the server-side implementation against
it was judged.

Tooling note: the required Semgrep registry configs (`p/python`, `p/security-audit`, `p/secrets`)
could not be fetched — `semgrep.dev:443` is denied by this session's egress policy (proxy returns
`403` to CONNECT; confirmed via `$HTTPS_PROXY/__agentproxy/status`). Per the proxy README, an org
policy denial is reported, not routed around. This pass is therefore full manual static tracing of
every changed call path; the Semgrep step should be re-run in a CI environment with registry access
before merge as a defense-in-depth check (no High/Critical is expected — the diff is
allow/deny/relay control flow with no obvious injection/sink pattern for the ERROR rulesets).

## Invariants actively attacked and NOT broken
- **Session hijack / stranger signal injection:** `handle_signal_send` and `handle_huddle_hangup`
  each gate on `huddle is not None and huddle.tenant_id == conn.tenant_id and
  huddle.is_participant(conn.user_id)` before any relay/transition; `signal.send` additionally
  requires `huddle.state in ACTIVE_STATES`. The relay target is always `huddle.other(conn.user_id)`
  (the fixed peer fixed at creation), never a client-supplied address. `huddle_id` is a server-minted
  UUIDv4 (`new_huddle_id`), unguessable. A non-participant, wrong-tenant, or unknown `huddle_id` all
  resolve to an identical `huddle_unavailable` — no way to inject into or enumerate someone else's
  call.
- **Cross-tenant isolation:** identity (`tenant_id`/`user_id`) is token-derived on every frame
  (`Connection` off the verified JWT); no `huddle.*`/`signal.*` frame body carries identity
  (`extra="forbid"` pydantic models). `HuddleRegistry` indexes are keyed by `(tenant_id, user_id)`
  and each huddle stores its `tenant_id`; every lookup re-checks it. Peer resolution
  (`chat_repo.load_user`) runs under `get_tenant_session` so RLS returns `None` for an out-of-tenant
  peer — indistinguishable from a nonexistent one. `ConnectionRegistry.user_connections` is keyed by
  `(tenant_id, user_id)`, so a relay can only ever reach same-tenant sockets.
- **Invite existence oracle (cross-tenant):** an out-of-tenant / nonexistent / offline peer all
  return the same `huddle_unavailable`; cross-tenant probing yields nothing (RLS `None` on the fast
  path, before any registry/busy work). The `huddle:initiate` scope is checked BEFORE any DB/registry
  access, so an unscoped token learns nothing about peer/channel existence.
- **Fail-closed inspection seam (`signal.send`):** mirrors the R-005 `handle_chat_send` pattern
  exactly — `try/except` around `inspector.inspect` converts a raise to `inspection_unavailable`;
  `status == "blocked"` -> `message_blocked`; `status != "pass"` (`seam_unavailable`) ->
  `inspection_unavailable`. All three stop the relay before any signal reaches the peer; only an
  explicit `pass` relays. No silent pass path exists.
- **One-active-session-per-user race:** the caller-busy check (`active_huddle_id_for`) and
  `HuddleRegistry.create` are separated by NO `await` (the intervening `user_connections` and
  peer-busy lookups are synchronous). On single-threaded asyncio, `create()` completes atomically
  before the coroutine next yields, so two concurrent invites (multi-tab / interleaved at the earlier
  DB await) cannot both create — the second observes the first's session and rejects. `create()`
  marks BOTH participants busy atomically; `_retire`/`transition` clear both indexes.
- **TURN credential minting (`ice.py`):** standard coturn REST time-limited scheme —
  `username = "<expiry>:<user_id>"`, `credential = base64(HMAC-SHA1(secret, username))`. `user_id` is
  token-derived (`principal.sub`), not client input. The secret comes only from `RENDLY_TURN_SECRET`
  and is never logged (no logging in the module at all). Forgery requires the shared secret;
  replay past `expiry` is rejected by the TURN server (expiry embedded in the signed username). An
  unset/empty secret degrades to STUN-only — `turn_secret = os.environ.get(...) or None` plus the
  `config.turn_urls and config.turn_secret` guard means a credential is NEVER fabricated without a
  secret. TTL is clamped to `[1, 86400]`.
- **No double-`begin` (Rule-6):** the only DB access on the new path (`handle_huddle_invite`) uses
  `async with get_tenant_session(tenant_id)` with no `session.begin()` wrap; reads only, no commit.
- **Insecure deserialization:** all inbound frames are closed (`extra="forbid"`), charset-/length-
  bounded pydantic models; the `Signal` oneOf is a smart union over `Literal` `kind` consts — no
  arbitrary object construction, no polymorphic gadget surface.
- **Disconnect handling (`ws.py`):** `end_active_for_user` transitions the user's active huddle to
  `ended` and notifies the peer before the connection is discarded; no NEW phantom-busy gap beyond
  the documented single-instance limitation (Fork F).

## Low findings — accepted, non-gating
1. **Same-tenant presence/busy oracle + unsolicited ring on `handle_huddle_invite`
   (pipeline.py:339-369).** When `channel_id` is omitted (the ADR-0007 Fork B "direct calling"
   mode), any holder of `huddle:initiate` can invite any same-tenant `peer_user_id` and distinguish
   four outcomes: invalid/cross-tenant/offline -> `huddle_unavailable`; online-and-free -> a real
   `ringing` `huddle.update` (which also RINGS the victim and marks them busy); online-and-busy -> a
   `busy` `huddle.update`. This discloses a known same-tenant user's online + in-call state without a
   shared channel, and lets an attacker force a ring. **Accepted:** cross-tenant is fully protected
   (RLS `None` -> `huddle_unavailable`, identical to nonexistent), `user_id`s are UUIDv4 so blind
   enumeration is infeasible (the attacker must already possess a valid same-tenant `user_id` and the
   `huddle:initiate` scope), and presence disclosure to a same-tenant caller is the documented,
   intended semantics of a direct-calling feature (a phone busy signal). No isolation boundary is
   crossed. Optional hardening if the presence disclosure is undesired: require the optional
   `channel_id` gate for all invites (narrows to shared-channel peers), or collapse `busy` into the
   generic unavailable response when caller and peer share no channel.
2. **No rate limiting on any real-time frame — the ring path makes it more visible
   (pipeline.py, whole dispatch).** The contract reserves `rate_limit_exceeded`, but no handler
   (chat.send included) enforces a limit anywhere in `src/`. On the huddle path an attacker can
   rapid-fire `invite -> hangup -> invite` to spam a same-tenant victim with rings (each cycle is
   cheap; the one-session invariant only caps CONCURRENT calls, not RATE). **Accepted / pre-existing:**
   this is a codebase-wide gap, not introduced or worsened structurally by R-007 (huddle.invite is no
   less limited than chat.send); the single-instance MVP posture already accepts unbounded frame rate.
   Recommend a shared per-connection token-bucket (emitting the already-contracted
   `rate_limit_exceeded`) as a follow-up covering chat.send AND huddle.invite together. The pre-parse
   `MAX_FRAME_BYTES` (64 KiB) cap does bound per-frame memory, so this is a nuisance/notification-DoS,
   not a memory-exhaustion vector.
3. **Effective max SDP is slightly below its 64 KiB schema bound (frames.py:113 vs
   pipeline.py:72).** `MAX_SDP_LEN == MAX_FRAME_BYTES == 65536`, but the SDP travels inside a JSON
   envelope, so a schema-maximal 64 KiB `sdp` is rejected pre-parse by `MAX_FRAME_BYTES` before
   pydantic validates it. **Accepted:** this is a functional edge (a legitimate SDP is far smaller
   than 64 KiB), not a security issue — the frame cap fails safe (reject), never over-accepts. Noted
   only so it is not mistaken for a validation bypass.
4. **Narrow disconnect/invite interleave can leave a recoverable phantom-busy peer
   (pipeline.py:345 vs huddle.create).** If the peer's socket drops in the window between the
   `user_connections` liveness snapshot and `create()`, a `ringing` huddle is created marking the
   (now-disconnected) peer busy while the peer's own teardown already ran and found nothing. The
   inviter still holds the session, so the peer's busy marker clears when the inviter hangs up or
   disconnects. **Accepted:** the window is sub-millisecond, self-healing, and within the documented
   single-instance phantom-session limitation (ADR-0007 Fork F / honesty boundary 5); no NEW
   unrecoverable state is introduced.

## Gate
CLEAN — no High/Critical. Cleared for merge on the static-analysis pass. The four Low findings are
documented and accepted within R-007's stated scope (direct-calling presence semantics, single-
instance, no cross-cutting rate limiter yet). Action items before/at merge: (a) re-run the Semgrep
`p/python`/`p/security-audit`/`p/secrets` ERROR scan in a CI environment with `semgrep.dev` egress
(blocked in this session) as defense-in-depth; (b) track the shared rate-limiter as a follow-up
(non-gating). No code change is required to clear the gate.
