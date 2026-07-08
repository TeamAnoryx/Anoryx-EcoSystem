# ADR-0012 — Agent Mailbox Relay + Shared State Store (not a messaging backbone)

- Status: Accepted
- Date: 2026-07-08
- Task: O-012 (twelfth Orchestrator task, fourth task from the Phase 2
  ecosystem-integration layer)
- Builds on: ADR-0003 (O-003 ingest — the narrow-IntegrityError dedup idiom this reuses
  verbatim), ADR-0009 (O-009 relay — the privileged-session chain-append discipline this
  reuses), ADR-0010 (O-010 identity correlation — the tenant-scoped-table-plus-global-chain
  shape this reuses), ADR-0011 (O-011 automation engine — the "only the meaningful
  outcome" chain-audit semantics the shared-state chain reuses, and the "no master switch
  when the trust model doesn't change" reasoning the messaging config reuses)
- Supersedes: nothing. Adds one new package (`messaging`), two independent seams, two new
  tenant-scoped tables, two new global hash chains, and embedded messaging settings; does
  not alter any existing seam, engine, or schema.

This run's default posture is to stop in front of the 🏦 POST-INVESTMENT gate; the task
owner has explicitly authorized proceeding with post-investment tasks in this run — the
same standing authorization already recorded in ADR-0009/ADR-0010/ADR-0011.

## Context

The roadmap lists O-012 as **"Sub-millisecond agent-to-agent messaging backbone.
Low-latency messaging fabric for agent-to-agent comms across the ecosystem. Global
state-sync engine for flawless cross-product state consistency."** — in the same Phase-2
ecosystem-integration tier as O-009/O-010/O-011. This is not buildable as a single, honest
PR today, for two independent reasons:

- **"Sub-millisecond" is a latency SLA no HTTP+Postgres request/response path can
  honestly claim.** There is no message broker (Redis/Kafka/NATS) anywhere in the
  Orchestrator's stack — ADR-0008 already established "no optional heavy extras" for the
  Orchestrator's own dependency footprint, and introducing a new persistent pub/sub broker
  is substantial infra work, not a single reviewable PR. Claiming "sub-millisecond" for
  what is realistically a durable, audited, ordinary web-service-latency relay would
  violate CLAUDE.md's mandatory honest-language rule — the same discipline that forbids
  "100% detection"/"blocks all attacks" forbids a fabricated latency SLA here.
- **"Global state-sync... flawless cross-product consistency" is not buildable, honestly
  or otherwise.** True flawless global consistency across independently-operated products
  is a distributed-consensus problem this PR cannot and should not attempt, and
  "cross-product" implies write access into Delta/Rendly internals that don't exist yet
  and that this task is not scoped to build — this repo's protect-paths hook confines
  `Anoryx-AI-Orchestrator/` code to its own directory; it must not reach into `Delta/` or
  `Rendly/`.

This ADR resolves that tension the same way ADR-0009/ADR-0010/ADR-0011 resolved their own
literal roadmap text: ship the smallest genuinely useful, honest slice — two independent,
INTRA-TENANT, Postgres-backed primitives (a durable poll-based agent mailbox relay, and a
shared key-value state store with optimistic concurrency) — and name everything else (the
broker, the cross-product span, push/webhook delivery, any consensus mechanism) as an
honest, explicit deferral, never implied as done.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "messaging backbone" means without a broker | **A1**: a durable, ordered, POLL-BASED mailbox relay (`POST /v1/messaging/messages` + `GET /v1/messaging/inbox/...`), backed by a single Postgres table with a monotonic `sequence_number` that IS the inbox ordering/pagination cursor directly. No push, no webhook delivery, no broker — a recipient polls its own inbox. |
| **B** — what "state-sync engine" means without consensus | **B1**: a shared key-value store (`PUT`/`GET /v1/state/{state_key}`) with OPTIMISTIC CONCURRENCY — a `version` integer, incremented by exactly 1 on every successful write, checked via an atomic `UPDATE ... WHERE version = :expected`. A single Postgres instance's row is the sole source of truth for a key's current version — this is compare-and-swap, not distributed consensus, and it is scoped to ONE tenant, never cross-product. |
| **C** — cross-tenant scope | **C1**: NO cross-tenant messaging or state sharing in v1. Sender and recipient (for messages) and every state key are all scoped to the SAME tenant_id column, enforced STRUCTURALLY by RLS (both sides of a message live under the caller's own tenant), not merely by an app-layer check that could be bypassed by a bug. |
| **D** — cross-product scope | **D1**: intra-Orchestrator only. Nothing here reaches into Delta or Rendly's own internals (mirrors ADR-0011 Fork D's identical "this agent cannot write to Delta or Rendly" constraint) — a Delta or Rendly "agent" can call these seams as a caller, exactly like any other tenant-authenticated caller, but the Orchestrator does not push into either product. |
| **E** — mailbox idempotency / dedup mechanism | **E1**: `UNIQUE(tenant_id, idempotency_key)` on `agent_messages`, exploited as the dedup gate exactly like O-003's ingest pipeline: the sender's own dedup key. A resend with the SAME key is NOT an error — a narrow `IntegrityError` catch on the INSERT (mirroring the ingest pipeline's own narrow-catch idiom verbatim) treats it as an idempotent no-op, re-fetches, and returns the ORIGINAL message's `sequence_number`/`created_at` unchanged. |
| **F** — mailbox audit-chain semantics ("every attempt" vs. "only genuine outcomes") | **F1**: `agent_messaging_audit_log` records EVERY send ATTEMPT — both a fresh `sent` and a deduped resend get a chain link — matching O-003's `ingest_audit_log` "was this attempt durably processed" semantics, explicitly NOT O-011's `automation_executions` "did an action actually fire" semantics. The reasoning: a message send is a caller-initiated durability claim (like an ingest event) — the caller needs a tamper-evident record that their send attempt, dedup or not, was genuinely processed by the Orchestrator. This is the OPPOSITE choice from Fork G below, made for a reason specific to each domain (see "Honesty boundaries" and the per-table docstrings for the full comparison, mirroring how ADR-0011's Fork I explained ITS choice relative to ADR-0010's identity chain). |
| **G** — state audit-chain semantics ("only genuine outcomes" vs. "every attempt") | **G1**: `agent_state_audit_log` records ONLY a genuine `created`/`updated` write — a version-CONFLICT rejection (409) produces NO row, mirroring O-011's `automation_executions` choice exactly. The reasoning: nothing about the STORED STATE changed on a conflict — there is no new fact to make tamper-evident. A conflict is a normal, expected, high-frequency outcome of optimistic concurrency (every losing racer in a CAS produces one); chain-auditing it would mean the chain's size scales with contention rather than with genuine state mutations, diluting the audit trail's signal. |
| **H** — mailbox payload inspection | **H1**: `body` is OPAQUE JSONB, relayed byte-for-byte — the Orchestrator NEVER inspects, parses, or acts on its contents. This is a deliberate CONTRAST with O-011's automation matcher, which deliberately DOES inspect (flat scalar-equality match against) event payloads. The two modules have opposite payload-inspection postures for opposite reasons: O-011's matcher exists specifically to react to payload content; O-012's relay exists specifically to move opaque application data between two agents without becoming a second, divergent place that interprets it. |
| **I** — master enable/disable switch | **I1**: NONE. Unlike O-011's `ORCH_AUTOMATION_ENABLED` (default `false`, because a matched rule triggers a real side effect — an O-004 distribution re-drive — with NO interactive caller in the loop for that specific trigger), a message send and a state write here are ORDINARY CALLER-INITIATED CRUD: an authenticated tenant principal makes one HTTP call, gets one HTTP response, and nothing autonomous happens afterward. This is the SAME trust model as `POST /v1/policies/distributions` or `POST /v1/automation/rules` (also no master switch) — adding one here would mirror O-011's FORM without its underlying reason (new autonomous behavior with no interactive caller), which the ADR-0011 precedent this task builds on explicitly warns against doing reflexively. |
| **J** — auth model | **J1**: both seams reuse the EXISTING `require_tenant_principal` dependency (`query_service_tokens`) verbatim — the SAME credential already gating `GET /v1/events`, `/v1/identity/events`, and `/v1/automation/rules`. No new principal type, no new trust root. |
| **J2** — intra-tenant agent identity (security-auditor follow-up, named here honestly, not re-architected) | The tenant-wide `require_tenant_principal` credential (Fork J1) is the **ENTIRE** authentication boundary for every one of these seams. `sender_team_id`/`sender_project_id`/`sender_agent_id` and `recipient_team_id`/`recipient_project_id`/`recipient_agent_id` (on message send), the `team_id`/`project_id`/`agent_id` path params (on inbox read), and `updated_by_agent_id` (on state write) are all CALLER-SUPPLIED request fields — never validated against the caller's own credential, because there is no per-agent credential anywhere in this codebase to validate them against. They are caller-asserted LABELS, not authenticated principals. Building a real per-agent credential system is genuine, separate, out-of-scope future work (mirrors ADR-0011 Fork E's identical "no interactive tenant credential available to require instead" reasoning) — this PR names the gap rather than papering over it with a redesign it cannot honestly complete in one pass. |
| **K** — table scope (RLS vs. global) | **K1**: `agent_messages` and `agent_state` are TENANT-SCOPED (RLS, mirrors `ingest_events`/`automation_rules`). Both audit chains (`agent_messaging_audit_log`, `agent_state_audit_log`) are GLOBAL hash chains that ALSO carry RLS on SELECT (mirrors `automation_executions`, NOT `relay_audit_log`/`identity_audit_log`, which carry no RLS at all) — because both chains are genuinely tenant-relevant audit data a tenant could read back, unlike the relay/identity chains' cross-tenant fleet metadata. |
| **L** — since_sequence pagination shape | **L1**: `since_sequence` is a PLAIN INTEGER exclusive lower bound, not a base64-opaque cursor (unlike `GET /v1/events`/`GET /v1/identity/events`/`GET /v1/automation/rules`, which all use an opaque cursor). `sequence_number` is already a bare monotonic position with no sensitive structure to hide — encoding it would add a decode/validation step for no confidentiality or integrity benefit. This is a deliberate, small simplification from the otherwise-uniform cursor convention, named here rather than silently diverging. |
| **M** — the ambiguous "non-null expected_version against a never-created key" case | **M1**: treated as `409 version_conflict` with `current_version: null` (not a separate 404 branch). The roadmap/design text only specifies two outcomes (null expected_version on an existing key → `already_exists`; non-null mismatch → `version_conflict`) and does not name this third combination explicitly. Folding it into `version_conflict` keeps the write endpoint's error surface to exactly one conflict shape (echoing `current_version`, which is simply `null` when there is no row to have a version at all) rather than introducing a second, differently-shaped error path for a single edge case. |

## API additions

- `POST /v1/messaging/messages` — send. Body: `{sender_team_id, sender_project_id,
  sender_agent_id, recipient_team_id, recipient_project_id, recipient_agent_id,
  message_type, body, idempotency_key}` → `202 {sequence_number, created_at, disposition:
  "sent"|"deduped"}`.
- `GET /v1/messaging/inbox/{team_id}/{project_id}/{agent_id}?since_sequence=&limit=` —
  poll. `200 {data: [...], next_since_sequence}`, ascending sequence order.
- `PUT /v1/state/{state_key}` — compare-and-swap write. Body: `{expected_version: int |
  null, value, updated_by_agent_id?}` → `200 {state_key, version, updated_at}` or `409
  {error, current_version}`.
- `GET /v1/state/{state_key}` — `200 {state_key, value, version, updated_at}` or `404`.

All four reuse `require_tenant_principal` (Fork J) — auth: `mutualTLS` (declared, not
enforced until O-008, matching every other seam's honesty posture) + `serviceToken`.

## Data access

`messaging.router` runs every write/read under `get_tenant_session(principal)` (RLS
structurally scopes both mailbox and state rows to the caller's tenant) and every audit
append under `get_privileged_session()` + `session.begin()` (mirrors every other
Orchestrator chain's discipline). `insert_agent_message` mirrors the ingest pipeline's
narrow-`IntegrityError`-catch dedup idiom (Fork E); on conflict, the router opens a FRESH
`get_tenant_session` for the re-fetch (a rolled-back session's transaction-local tenant GUC
is gone — reusing it would run the re-read with no tenant context set, mirroring
`automation/router.py`'s PATCH two-separate-sessions precedent). `update_agent_state_cas`
is a single atomic `UPDATE ... WHERE state_key = :k AND version = :expected` (RLS supplies
the tenant_id half of the predicate) — race-safe under Postgres's MVCC without any
additional lock statement (Fork B).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT sub-millisecond.** Ordinary HTTP+Postgres request/response latency
  applies — typically single-digit-to-low-double-digit milliseconds under normal load —
  NOT measured or guaranteed as an SLA in this PR. No latency benchmark is claimed or
  implied by anything in this codebase.
- **This is NOT a message broker, and there is NO push or pub/sub.** The relay is
  POLL-ONLY — a recipient calls `GET /v1/messaging/inbox/...` to discover new messages.
  There is no webhook, no server-sent stream, no long-poll, no notification of any kind.
- **This is NOT flawless, and it is NOT distributed consensus.** The state store is
  single-Postgres-instance optimistic concurrency (a version number, compare-and-swap) —
  the honest floor of "no silent overwrite under a race," not a claim of any stronger
  consistency property across multiple database instances or products.
- **This is NOT cross-tenant.** Sender/recipient and every state key are structurally
  confined to one tenant via RLS (Fork C) — there is no code path anywhere in this module
  that reads or writes another tenant's row.
- **This is NOT cross-product.** Nothing here reaches into Delta or Rendly's own internals
  (Fork D) — a Delta/Rendly "agent" may call these seams as an ordinary authenticated
  tenant caller, exactly like any other consumer of `require_tenant_principal`, but the
  Orchestrator does not push data into either product.
- **This is NOT the roadmap's literal "backbone" framing.** It ships two narrow, intra-
  tenant primitives, not an ecosystem-wide messaging fabric. The gap between this slice
  and the roadmap's fuller vision is named here explicitly, not implied away.
- **This does NOT provide agent-level authentication or intra-tenant message/state
  isolation — only tenant-level isolation** (Fork J2, security-auditor follow-up).
  `sender_agent_id`, `recipient_agent_id`, and `updated_by_agent_id` are self-asserted
  labels the caller provides, not verified identities — ANY tenant-authenticated caller can
  claim to send as any agent_id, read any agent's inbox, or attribute a state write to any
  agent_id, all within its OWN tenant. A real per-agent credential system is out of scope
  for this PR.
- **Dispatched only via this run's explicit authorization to build post-investment tasks**
  (mirrors ADR-0009/ADR-0010/ADR-0011's identical disclosure) — the roadmap's own 🏦 label
  means this was not scheduled as next-buildable MVP work.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Cross-tenant message read/write | `agent_messages` RLS (FORCE ROW LEVEL SECURITY + the same fail-closed NULLIF predicate every other tenant table uses); both sender and recipient columns live under the SAME tenant_id, and every read/write runs under `get_tenant_session(principal)` — never an explicit tenant filter a caller could widen. |
| Cross-tenant state read/write | `agent_state` RLS, identical shape — a tenant can never read, create, or CAS-update another tenant's `state_key` row, even if it guesses the exact key string. |
| Duplicate/replayed message inflating the mailbox | `UNIQUE(tenant_id, idempotency_key)` + narrow `IntegrityError` catch (Fork E) — a resend is recorded once as data, though every send ATTEMPT (including dedups) is still chain-audited for tamper-evidence (Fork F). |
| Lost update / silent overwrite on concurrent state writes | Atomic `UPDATE ... WHERE version = :expected` (Fork B) — two writers racing with the SAME `expected_version` can never both succeed; the loser gets a genuine 409, proven under real concurrent HTTP requests in the integration e2e (not a mocked race). |
| `message_type` or `body` used as an execution/interpretation vector | `message_type` is bounded, free-text, purely descriptive metadata (Fork H) — never parsed as a command. `body` is opaque JSONB, never deserialized into anything the Orchestrator acts on. |
| Oversized payload / resource exhaustion | `ORCH_MESSAGING_MAX_BODY_BYTES` / `ORCH_MESSAGING_MAX_STATE_VALUE_BYTES` caps enforced at the request boundary before any DB write; `ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE` bounds a single poll's response size. |
| A NUL byte or a deeply-nested body crashing the persist / DLQ-style insert | Reuses `boundary.contains_nul` verbatim + a narrow `RecursionError` catch around `json.loads`/`contains_nul` (mirrors `automation/router.py`'s exact handling), rejecting as 422 rather than 503-ing on an uncaught exception. |
| A malformed (non-object) `body`/`value` bypassing the DB's structural guarantee | Enforced at BOTH the app boundary (422 `schema_invalid` if not a dict) AND the DB layer (`jsonb_typeof(...) = 'object'` CHECK constraints on `agent_messages.body` and `agent_state.state_value` — defense in depth, not merely an app-layer promise). |
| Tamper on either audit chain | Append-only via BEFORE UPDATE/DELETE deny triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_messaging_chain`/`validate_state_chain` re-verify the full chain. |
| **A tenant-authenticated caller can claim to send as any agent_id, or read any agent's inbox, within its own tenant** (Fork J2, security-auditor follow-up, named here honestly, not re-architected) | Bounded to the SAME tenant only — RLS still holds structurally, so there is no CROSS-tenant leak of any kind. But there is NO intra-tenant agent-level isolation or authenticity in v1: `require_tenant_principal` resolves a tenant-wide credential, not a per-agent one, so any caller holding that tenant's credential can populate `sender_agent_id`/`recipient_agent_id`/`updated_by_agent_id` with any value it likes, or poll `GET /v1/messaging/inbox/{team_id}/{project_id}/{agent_id}` for ANY agent_id within its own tenant. A consumer of this data MUST NOT treat `sender_agent_id`/`updated_by_agent_id` as cryptographic proof of origin. There is no per-agent credential anywhere in this codebase to require instead without inventing a wholly new identity/credential concept out of scope for this PR — see Fork J2 and Residual risk. |
| Unbounded per-tenant `agent_messages`/`agent_state` row growth degrading the shared Postgres instance for every OTHER tenant (security-auditor follow-up: a cross-tenant AVAILABILITY concern, not merely tenant-local storage) | `ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT` / `ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT` enforced at insert time via a tenant-keyed `pg_advisory_xact_lock` + `COUNT(*)` before the write (mirrors `lock_automation_rule_cap`/`ORCH_AUTOMATION_MAX_RULES_PER_TENANT` exactly, TOCTOU-safe) — exceeding either is a 422 (`message_limit_exceeded`/`state_key_limit_exceeded`), never a 5xx. A dedup resend or a version-matched CAS update of an existing key is exempt (neither adds a row/key). This bounds total row/key COUNT only — it does NOT bound the send/write RATE (see Residual risk). |

## Residual risk (known, deferred)

- **No agent-level authentication or intra-tenant isolation (Fork J2, security-auditor
  follow-up).** `require_tenant_principal` is a tenant-wide credential; there is no
  per-agent credential in this system. Any tenant-authenticated caller can claim to send
  as any agent_id, read any agent's inbox, or attribute a state write to any agent_id — all
  bounded to its OWN tenant (no cross-tenant leak), but with no authenticity guarantee at
  the agent level. A consumer must not treat `sender_agent_id`/`recipient_agent_id`/
  `updated_by_agent_id` as verified identity. A real per-agent credential/identity system
  is genuine, separate, out-of-scope future work.
- **Per-tenant row/key COUNT is now bounded; per-tenant send/write RATE is still NOT
  bounded (security-auditor follow-up).** `ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT` /
  `ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT` cap the TOTAL number of `agent_messages` rows
  / distinct `agent_state` keys a tenant can accumulate — closing the unbounded-growth gap
  this ADR previously left open. They do NOT throttle how FAST a tenant can send messages
  or create state keys: a tenant can still reach its cap in a single burst, and once below
  the cap can still write at whatever rate the HTTP/Postgres path allows. Rate limiting is
  real, separate, out-of-scope future work (mirrors this same ADR's existing "no TTL/
  retention" and "no presence" deferrals in spirit: a genuine gap, named, not designed
  around in this pass).
- **No TTL or retention policy on `agent_messages`.** A mailbox grows unboundedly (up to
  its new per-tenant cap); there is
  no automatic expiry, archival, or compaction. An operator wanting bounded storage must
  build this as explicit follow-up work.
- **No DELETE endpoint on `agent_state` in v1** (named explicitly in Out of scope below) —
  a stale or unwanted key can only be overwritten via a CAS update, never removed. Keeps
  the reviewable surface smaller for this pass.
- **No presence/liveness signal.** There is no way to ask "is this agent currently online
  / polling its inbox" — the relay is purely a durable store a recipient chooses to poll,
  on whatever cadence it wants.
- **Single-Postgres-instance only.** Neither seam has any notion of multi-region or
  multi-instance replication; the "sole source of truth" language throughout this ADR
  means exactly one Postgres instance, not a distributed store.
- **`since_sequence`'s plain-integer pagination (Fork L) is a deliberate, small departure**
  from the otherwise-uniform opaque-cursor convention used by every other paginated read
  in this codebase — named here so it does not read as an oversight.

## Configuration

New environment variables (all resolved NON-FATALLY — absence is not fatal; no master
enable/disable switch exists here, see Fork I):

- `ORCH_MESSAGING_MAX_BODY_BYTES` — `agent_messages.body` size cap in bytes (default
  16384, minimum 1).
- `ORCH_MESSAGING_MAX_STATE_VALUE_BYTES` — `agent_state.state_value` size cap in bytes
  (default 16384, minimum 1).
- `ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE` — hard ceiling on `GET /v1/messaging/inbox/...`'s
  `limit` query param (default 200, minimum 1); the request's own `limit` is clamped to
  this.
- `ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT` — per-tenant cap on total `agent_messages` row
  count (default 100000, minimum 1), enforced at send time BEFORE the insert via a
  tenant-keyed `pg_advisory_xact_lock` + `COUNT(*)` (mirrors
  `ORCH_AUTOMATION_MAX_RULES_PER_TENANT`); exceeding it is a 422 `message_limit_exceeded`.
  A dedup resend of an existing `idempotency_key` is exempt (security-auditor follow-up —
  bounds unbounded per-tenant growth, a cross-tenant availability concern on the shared
  Postgres instance).
- `ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT` — per-tenant cap on distinct `agent_state` key
  count (default 10000, minimum 1), enforced only on the CREATE path
  (`expected_version: null` against an absent key) via the same tenant-keyed-advisory-
  lock-then-COUNT pattern; exceeding it is a 422 `state_key_limit_exceeded`. A
  version-matched CAS update of an existing key is exempt, since it never adds a new key
  (security-auditor follow-up, same reasoning as above).

## Testing

- **Unit** (`tests/unit/test_messaging_config.py`, `test_hash_chain_messaging.py`,
  `test_hash_chain_state.py`, `test_messaging_router.py`, `test_state_router.py`):
  env-parsing defaults/overrides/misconfiguration; both new hash chains' canonicalization,
  opt-in-when-present (state chain's `updated_by_agent_id`), and tamper-evidence
  properties; the auth boundary (401 with no principal); the validation boundary (422:
  missing field, wrong-typed field, oversized body/value, NUL byte, a deeply-nested body
  via `RecursionError`, unknown field); dedup behavior (mocked insert-conflict + re-fetch
  proving `disposition: "deduped"` and an unchanged `sequence_number`); inbox pagination
  (since_sequence forwarded as the exclusive lower bound, limit clamped to the configured
  ceiling); create-only-if-absent / version-match / version-mismatch semantics (mocked
  repo layer); a tenant-scoping contract test proving the router always opens
  `get_tenant_session` with the caller's OWN resolved principal; the per-tenant message
  cap and state-key cap (mocked count at-or-over the configured limit -> 422, cap check
  NOT invoked at all for a dedup resend or an existing-key CAS update); and the
  `GET /v1/state/{state_key}` oversized-key-length boundary (422, mirroring `PUT`'s
  existing check).
- **Integration** (`tests/integration/test_messaging_e2e.py`, `pytest.mark.integration`,
  gated by `ORCH_REQUIRE_MESSAGING_E2E=1` exactly like the relay/identity/automation e2e
  gates — fails loud if set but unable to run, never silently skips on CI): a NON-STUBBED
  path over a real DB proving two real messages sent between two agents in the same
  tenant are durably recorded and ordered; `since_sequence` is a genuine exclusive lower
  bound; a duplicate send dedupes (no second row, both attempts chain-audited); a message
  never appears in another tenant's inbox; the messaging chain validates in full; the
  state store's create/update/conflict semantics are real; state is invisible across
  tenants; and — the single most important correctness property of the CAS design — TWO
  CONCURRENT real HTTP requests (`asyncio.gather` over `httpx.AsyncClient`, not a mocked
  race) racing on the SAME `(tenant_id, state_key)` with the SAME `expected_version`
  produce EXACTLY ONE success and genuine 409s for the rest, with the state chain
  recording exactly one `updated` link for that version transition.
- `tests/integration/test_migration_roundtrip.py` updated for the new head revision
  (`0009_agent_messaging`) and the four new tables.
- `contracts/openapi.yaml` updated with the four new operations + eight new schemas,
  reusing the `serviceToken` security scheme (no new scheme needed); verified against
  `tests/test_contract.py`.

## Out of scope (do not build here)

A message broker or any pub/sub mechanism; push/webhook/streaming delivery of any kind;
distributed consensus or any multi-instance state-sync mechanism; cross-tenant messaging
or state sharing of any kind; cross-product writes into Delta or Rendly; a DELETE endpoint
on `agent_state`; TTL/retention/archival on `agent_messages`; presence/liveness signaling;
a latency SLA of any kind; the remaining O-013→O-014 ecosystem-integration-layer tasks
(global third-party gateway, command dashboard).

## Consequences

- Agents across the ecosystem gain a real, working, durable, tamper-evident intra-tenant
  mailbox and a race-safe shared key-value store, reusing every existing
  credential/session/RLS/audit pattern this repo already established — entirely additive,
  no existing seam, engine, schema, or credential changed.
- The gap between this slice and the roadmap's fuller "sub-millisecond backbone" /
  "flawless global state-sync" vision is named explicitly (Honesty boundaries, Residual
  risk, Out of scope) rather than implied away, consistent with CLAUDE.md's mandatory
  honest-language rule and ADR-0009/ADR-0010/ADR-0011's identical precedent.
- The messaging chain's "every attempt" semantics and the state chain's "only genuine
  outcomes" semantics deliberately differ from each other (Forks F/G) — each chosen for a
  reason specific to its own domain, not a copy-paste of either O-003's or O-011's
  precedent without re-examining whether the reasoning actually transfers.
