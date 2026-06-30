# R-005 Security Audit — Rendly Real-Time Chat

Task: R-005 (real-time chat over WebSocket + minimal chat REST).
Scope: `Rendly/src/rendly/realtime/**`, `Rendly/src/rendly/persistence/{async_database,chat_models,chat_repo}.py`, migration `0002_chat_schema.py`.
This IS a security task: the spine is (a) tenant isolation and (b) the fail-closed Sentinel inspection seam.

## Independent verdict

An independent `security-auditor` (red-team, Opus) reviewed this change set against the
invariants below before the PR was opened (banked rule 3 — never self-verified). Verdict:
**CLEAN — no High/Critical findings.** Findings and dispositions are recorded in the
"Independent auditor findings" section at the end.

## Threat model + invariants (with enforcement and proof)

### 1. Cross-tenant isolation — storage (RLS)
Enforcement: migration `0002` puts `ENABLE` + **`FORCE` ROW LEVEL SECURITY** on all three chat
tables (`channels`, `memberships`, `messages`), each with one `FOR ALL` policy using the strict
fail-closed predicate in BOTH `USING` and `WITH CHECK`:
`tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')`. The app role
`rendly_app` is `NOBYPASSRLS`. An unset/empty GUC makes the predicate `tenant_id = NULL` → zero
rows (fail-closed, never widening). `tenant_id` is ALWAYS the server-resolved value from the
verified JWT (`AccessTokenClaims.tenant_id`), never a client frame/body field.
Proof: `tests/realtime/test_chat_rls.py` — `test_rls_scopes_channels_and_messages_to_the_guc_tenant`,
`test_unset_guc_yields_zero_rows`, `test_forged_tenant_cannot_read_another_tenants_message_by_id`.

### 2. Cross-tenant isolation — delivery (registry fan-out)
Enforcement: `ConnectionRegistry` keys live sockets by `(tenant_id, channel_id)`; a connection
registers only under its OWN tenant's channels (its membership set is loaded under its own tenant
session, RLS-scoped). A fan-out for `(tenantB, channel)` therefore cannot reach a tenant-A socket.
Proof: `test_chat_ws.py::test_cross_tenant_no_delivery_and_registry_is_tenant_pure` — asserts every
registry bucket is tenant-pure AND that tenant A, after tenant B sends on B's channel, receives only
its own channel's message.

### 3. The cross-tenant MEMBERSHIP invariant (defense in depth)
Enforcement (three layers): (a) the app path mints memberships only via `rendly.bind_membership`,
which raises `ValueError` on a cross-tenant `(user, channel)` pair; (b) migration `0002` gives
`memberships` two SAME-TENANT composite FKs — `(tenant_id, channel_id) → channels` and
`(tenant_id, user_id) → users` — both carrying `tenant_id`, so a membership's tenant must equal BOTH
the channel's and the user's tenant; a cross-tenant pair is structurally unconstructible at the DB;
(c) RLS.
Proof: `test_chat_rls.py::test_cross_tenant_membership_rejected_at_db_layer` (composite FK →
IntegrityError) and `::test_cross_tenant_membership_rejected_at_app_layer` (bind_membership ValueError).

### 4. The fail-closed inspection seam (FORK D — Sentinel non-negotiable #5)
Enforcement: `pipeline.py::handle_chat_send` runs `await inspector.inspect(...)` IN-LINE and BEFORE
persist and BEFORE fan-out. Only a `pass` proceeds to persist → ack `accepted` → fan out. A
`blocked` verdict → `chat.ack` `blocked`/`message_blocked`; a `seam_unavailable` verdict OR an
inspector that **raises** → `chat.ack` `blocked`/`inspection_unavailable`. In every non-pass case the
function returns BEFORE the persist + fan-out block — the message is NEVER written to the DB and
NEVER delivered. An inspector that errors is converted to a BLOCK (a broad `except` around the
`inspect` call maps the failure to `inspection_unavailable`), never a silent pass.
Proof: `test_chat_ws.py::test_seam_block_not_persisted_not_delivered` (a marked message is blocked,
absent from the DB, and never delivered, while a following clean message IS delivered — so the clean
one arriving first proves the blocked one never went out), `::test_seam_unavailable_fails_closed`
(parametrized over a seam_unavailable inspector AND a raising inspector — both → blocked, nothing
persisted), `::test_all_block_inspector_blocks_every_message`.

### 5. Token handling at the WebSocket handshake
Enforcement: `ws.py::_extract_token` reads the JWT ONLY from `Authorization: Bearer <jwt>` or the
`Sec-WebSocket-Protocol: rendly.bearer.<jwt>` subprotocol — **never from the query string/URL** (a
token in the URL leaks into proxy/access logs). The token is verified (`rendly.auth.verify` — ES256
sig + exp + iss + `token_use`) BEFORE `accept()`; a missing/invalid/expired token closes the
handshake (policy-violation close) with no socket opened. The accept response acknowledges NO
subprotocol (the bearer value is never echoed back into the handshake response), and the token /
subprotocol value is never logged by this module. Identity (`tenant_id`/`user_id`) is read off the
verified claims, never a client frame field.
Proof: `test_chat_ws.py::test_token_in_url_is_rejected`, `::test_missing_token_rejected`,
`::test_subprotocol_bearer_authenticates`.

### 6. Per-frame authorization + no existence oracle
Enforcement: the handshake gate is `chat:read`; `chat:write` is enforced PER send-frame
(`pipeline.py` step 2) — a read-only token may open the socket but its `chat.send` is rejected
(`error` `unauthorized`). A send to a channel the user is not a LIVE member of is `unauthorized`
(membership re-checked in the DB on every send, never a cached set). REST history (`rest.py`) is
member-only and resolves a non-member / foreign-tenant channel as a tenant-scoped 404 — the same
response as a non-existent channel, so neither existence nor membership leaks.
Proof: `test_chat_ws.py::test_send_without_chat_write_is_unauthorized`,
`test_chat_rest.py::test_history_requires_membership`, `::test_member_ops_to_foreign_tenant_user_is_404`.

### 7. Message immutability boundary (honest scope)
Enforcement: `messages` grants `rendly_app` only `SELECT, INSERT` — no `UPDATE`/`DELETE`. Messages
are APPEND-ONLY by grant. The hash-chain columns (`prev_record_hash`, `content_hash`) are RESERVED
and always NULL; the tamper-evident CHAIN is R-009, NOT built here (no false immutability claim).
Proof: `test_chat_rls.py::test_rendly_app_cannot_update_or_delete_messages`.

### 8. Rule 6 — double-begin fail-open (now on the async engine)
Enforcement: `async_database.py::get_tenant_session` sets the txn-local GUC before `yield`
(autobegin) and is NEVER wrapped in `async with session.begin()` — the double-begin error a broad
`except` could swallow into a fail-OPEN control (the F-007/F-009/F-018 class). The fail-closed
`TenantContextRequiredError` is raised BEFORE any session opens on a blank/whitespace tenant.

### 9. Input bounds / DoS
Enforcement: inbound frames are JSON text, bounded — `content` ≤ 16384 (enforced in the send
pipeline AND by a DB `CHECK`), correlation ids charset-bounded, closed-schema (extra keys rejected).
A binary frame or malformed JSON is answered with a single `error` frame and the connection
survives. The inspection no-op holds no state.
Proof: `test_chat_ws.py::test_message_too_large_is_blocked`,
`test_chat_presence_typing.py::test_malformed_and_unknown_frames_get_error`.

## Tooling
- ruff + black: clean on the full change set (CI `rendly-contracts` lint step).
- Non-stubbed e2e: real local Postgres + a real in-process ASGI WebSocket (Starlette TestClient).
  Full suite green (150 base + the realtime chat suite); the persistence + realtime coverage floor
  is gated at ≥90% in CI (`rendly-db` lane).

## Honesty boundaries (verbatim — see ADR-0005)
Chat only, NOT signaling (R-007). Seam only, NOT inspection (R-008). Archival fields only, NOT
immutability/hash-chain (R-009). Single-instance, NOT multi (cross-instance fan-out is a documented
seam). Delta-mapping columns nullable, NOT mapped (R-006).

## Independent oversight findings + dispositions

Two independent reviewers ran on the change set (neither wrote the code): a `code-reviewer`
(correctness / contract-conformance) and a `security-auditor` (red-team, Opus, with live-DB +
Semgrep probes). The security-auditor verdict is **CLEAN — no High/Critical**; it confirmed all
four spine invariants against the live database (RLS FORCE + NULLIF collapse proven three ways, the
cross-tenant membership FK rejection proven by a live insert, the fail-closed seam ordering, and
the SELECT,INSERT-only message grant). Semgrep `p/python,p/security-audit,p/secrets --severity=ERROR`
over the 22 changed files: **0 findings**. The code-reviewer returned a BLOCK driven by a High
(missing `internal_error` notification) plus Mediums/Lows. Every actionable finding was fixed before
this PR:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | High | recv loop had no try/except — a handler error (DB outage mid-persist) closed the socket with no `internal_error` frame (the contract defines `internal_error` for this). Fail-closed held (not persisted) but the notification was skipped. | **FIXED** — `ws.py` wraps `dispatch_frame` in try/except → sends `internal_error` and keeps the socket up. Test: `test_chat_hardening.py::test_handler_exception_yields_internal_error_frame` (monkeypatches the persist to raise). |
| 2 | Med | A removed member kept RECEIVING new fan-out (the registry was not evicted on `DELETE` member) until reconnect — a secure-channel boundary gap. | **FIXED** — `ConnectionRegistry.remove_user_from_channel` + the `remove_member` REST handler evicts the member's live socket from the channel bucket. Test: `::test_removed_member_is_evicted_from_live_registry`. |
| 3 | Med | Send-side check→persist TOCTOU: membership checked in session 1, persisted in session 2 — a membership revoked DURING inspection could let one last message through. | **FIXED** — the membership is re-checked in the SAME transaction as the persist (`pipeline.py`); a revoked sender is rejected `unauthorized`, nothing persisted. |
| 4 | Low | `_iso` emitted `+00:00`, not the `Z` form the contract examples use. | **FIXED** — `frames._iso` emits `Z`. Test: `test_frames.py::test_timestamps_use_z_suffix`. |
| 5 | Low | `to_message_record` mutated the dict from `build_chat_message` (project immutability rule). | **FIXED** — returns a new dict via comprehension. |
| 6 | Low | Inbound WS frame parsed before any size bound (the REST path caps at 64 KiB pre-parse). | **FIXED** — `dispatch_frame` rejects a raw frame > 64 KiB (`MAX_FRAME_BYTES`) before `json.loads`. Test: `::test_oversized_frame_rejected_before_parse`. |
| 7 | Low | WS session outlives token expiry (no per-socket TTL re-check). | **DEFERRED (documented)** — access tokens are 15 min (R-003); the higher-impact *revoked membership* case is now closed by eviction (#2). Per-socket expiry enforcement / max session age is a future hardening (noted for R-010 deploy). |
| 8 | Low | Test imports the private `_get_app_session_factory`. | **ACCEPTED** — mirrors R-004's persistence conftest, which uses the same factory to prove the no-GUC RLS fail-closed path; kept consistent. |
| 9 | Info | `Authorization` scheme match is case-sensitive (`"Bearer "`). | **ACCEPTED** — matches the merged R-003 `get_principal`; consistency over a non-functional nit. |

Overall: **CLEAN** — no High/Critical outstanding; all actionable findings fixed and covered by
new tests.
