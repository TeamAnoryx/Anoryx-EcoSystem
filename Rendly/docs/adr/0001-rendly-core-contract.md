# ADR-0001 — Rendly Core Platform API Contract (R-001)

- **Status:** Proposed
- **Date:** 2026-06-26
- **Deciders:** api-architect (contract — `Rendly/contracts/openapi.yaml`,
  `messages.schema.json`, `ids.md`), security-auditor (penultimate gate — focus on the auth
  scheme + the inspection-seam error contract), Affu (solo founder & product owner — resolved
  the STEP-0 forks during planning: **A = A1** OpenAPI + JSON-Schema catalog; **B = B1**
  Rendly self-contained OAuth2 + JWT; **C = C1** archival fields baked now; **D = D1**
  synchronous fail-closed pre-send inspection seam; **E = E1** signaling over the chat
  WebSocket).
- **Relationship to the ecosystem:** R-001 is **self-contained**. It depends only on the
  shipped Sentinel **F-001** as a *style precedent* (it copies the contract dialect — closed/
  bounded schemas, the fixed-message `Error` envelope, the four-ID discipline) and takes **no
  runtime dependency** on Sentinel F-014, the Orchestrator (O-001 has not landed), or Delta.
  The cross-product seams (O-010 identity, R-008 inspection, R-006/D-016 channel-mapping) are
  documented stubs only. The contract files win over this ADR on any conflict.
- **Feature:** R-001 — the contract lock for the Rendly secure-comms MVP (auth, profiles,
  role-based channels, team chat over WebSocket, 1-on-1 huddle signaling, a Sentinel safety
  seam, and archival-ready envelopes). It defines the surface; it is NOT a server, persistence
  (R-004), migrations, a DB, or a signaling server.

---

## 1. Context

Rendly (MVP) is a zero-trust enterprise comms platform — a Slack/Teams/Zoom replacement whose
core promise, inherited from Sentinel, is **data never leaves the org**. R-001 is the contract
that R-002 → R-010 build against. Per roadmap v3 it depends only on shipped F-001 and is
parallel-safe alongside O-001/D-001. The shipped Sentinel contracts
(`Anoryx-Sentinel/contracts/`) provide the proven dialect we mirror: OpenAPI 3.1 + JSON Schema
Draft 2020-12, `oneOf` + `const` dispatch, `additionalProperties:false`, bounded fields, a
fixed-template no-PII error envelope, and an authoritative credential→ID binding.

The STEP-0 forks below were surfaced with a minimal-surface (rule 13) default and approved.

## 2. Decisions

### D1 — Real-time format (FORK A = A1)
OpenAPI 3.1 for the REST surface **+ a JSON Schema Draft 2020-12 message catalog**
(`messages.schema.json`) for the WebSocket chat + signaling frames. This mirrors Sentinel
exactly and reuses the ecosystem's existing `jsonschema` tooling — **no new toolchain**.
- *Rejected:* OpenAPI + AsyncAPI 3.0. More expressive for WS/pub-sub but adds a parallel spec
  format + a CI validator the ecosystem has never used, for a small 2-family surface.
- *Future seam:* adopt AsyncAPI if the real-time surface grows (group huddles R-011 /
  streaming R-014, both post-investment).

### D2 — Identity (FORK B = B1) — security-sensitive
Rendly issues its **own self-contained OAuth2 + JWT** (R-003 implements issuance). The access
token's claims (`AccessTokenClaims`) are the authoritative, server-resolved source of truth for
`tenant_id` + `user_id`; tenant binding is fail-closed (a request addressing a different tenant
→ 403 `tenant_context_mismatch`). This is the Rendly analog of Sentinel's virtual-API-key → ID
binding.
- *Rejected:* federate human auth through Sentinel F-014 SSO. F-014 is explicitly "human
  **operators** on the **admin** surface only; the /v1 data plane is untouched." Rendly needs
  **end-user (employee)** auth — a different population — and federating would couple R-001 to
  Sentinel internals, breaking parallel-safety.
- *Future seam (reserved either way):* O-010 unified cross-product identity (post-investment).
  Reserved as the `idp_subject` claim (null in R-001) + an `authorization_code`/OIDC flow noted
  but not offered. R-001 issues Rendly's own tokens and federates nothing.
- *Non-obvious sub-decision:* the OAuth2 **token endpoint uses the Rendly `Error` envelope**
  (not the RFC 6749 error object) so every surface shares one fixed-message, no-PII envelope.
  The success response stays standard OAuth2 (`access_token`/`token_type`/`expires_in`/
  `refresh_token`/`scope`) so SDKs work on the happy path; only the error shape is unified.

### D3 — Archival fields (FORK C = C1)
Message and huddle records carry **hash-chain-ready archival metadata now** (`ArchivalMeta`:
`schema_version`, `record_id`, `created_at`, `seq`, and reserved `prev_record_hash` /
`content_hash`), mirroring the Sentinel F-003 audit pattern. **Define-only** — R-001 sets the
ordering fields and leaves the hashes null; immutable archiving (chain construction +
verification) is R-009.
- *Rejected:* a minimal envelope now + a v2 envelope when R-009 lands → an envelope-version
  bump rippling through R-005/R-007 records already in flight.
- *Driver:* the Scope-IN text mandates archival-ready fields in the envelope; baking 3–4
  reserved fields once is low surface and avoids a later migration.

### D4 — Inspection in the send path (FORK D = D1) — security-sensitive
The Sentinel safety seam runs **synchronously and fail-closed BEFORE delivery/persist**. A
block, or any inspection-seam error, **rejects the send** — content carrying a secret/PII is
never delivered. The contract reserves an `InspectionResult` object (`status: pass | blocked |
seam_unavailable`) and the fail-closed error codes: 403 `message_blocked` on the REST content
writes, and a `chat.ack` with `status:"blocked"` + `error_code` on the WS send path. This
matches Sentinel non-negotiable #5 (on ANY inspection error → BLOCK) and the "data never
leaves" promise.
- *Rejected:* async inspect-and-flag — a leaked secret/PII is already delivered to recipients
  before inspection runs, violating "data never leaves" and fail-safe.
- *Honesty boundary:* the seam governs chat **message content** + signaling **metadata** only;
  huddle **media** (P2P WebRTC) is NOT content-inspected. **Detection is R-008** — R-001
  reserves the fields and the fail-closed semantics only.
- *Tradeoff stated:* synchronous inspection adds per-message latency on the send path; accepted,
  because fail-closed is non-negotiable for a zero-trust comms product.

### D5 — Signaling transport (FORK E = E1)
WebRTC signaling (offer/answer/ICE) rides the **same chat WebSocket** (`GET /realtime`) as a
distinct typed message family (`signal.send` / `signal.relay`). One transport, one auth
handshake, one connection.
- *Rejected:* a dedicated signaling WebSocket — cleaner separation but two transports + two
  handshakes for a low-volume 1-on-1 signaling surface.
- *Future seam:* split a dedicated signaling channel if group huddles (R-011) / streaming
  (R-014) arrive.

### D6 — Identifier schema (non-obvious)
Five LOCKED/IMMUTABLE IDs (`tenant_id`/`user_id`/`channel_id`/`message_id`/`huddle_id`).
`tenant_id` is **shape-compatible with the Sentinel/ecosystem join key** so a future O-010
cross-product join needs no migration, but R-001 takes no dependency on it. `user_id` is an
opaque surrogate, never PII (mirrors the Sentinel `actor_id` discipline). See `ids.md`.

## 3. Consequences

- **Positive:** parallel-safe (no cross-product dependency); a downstream builder can implement
  R-003/R-004/R-005 with no further questions; the dialect matches Sentinel so reviewers and
  tooling carry over; fail-closed + no-PII posture is baked into the contract, not deferred.
- **Negative / accepted:** synchronous inspection adds send latency (D4); REST and WS duplicate
  the `ArchivalMeta`/`InspectionResult` shapes across two transports (acceptable — they are two
  wire surfaces); the token endpoint deviates from RFC 6749's error object (D2, deliberate).
- **CI:** a new `.github/workflows/rendly-ci.yml` validation lane (path filter `Rendly/**`,
  Python 3.12) validates the OpenAPI doc, the message catalog, and **every example** against its
  schema. The lane must be verified to EXECUTE (not skip) on a fresh tree (banked rule 4: CI is
  authoritative).

## 4. Threat-model notes (for the independent security review)

- **Auth scheme (D2).** Token is the sole source of truth for tenant/user; client payload can
  never widen scope (403 `tenant_context_mismatch`). Fail-closed on missing/expired/forged
  token (401). `jti` reserved for replay/revocation. `Error` envelope never echoes request
  content or PII; `message` is fixed per `error_code` (no interpolation). NotFound is uniform
  for cross-tenant vs non-existent (no existence oracle).
- **Inspection error contract (D4).** Block AND seam-error both fail closed; there is no path
  where unininspected content is delivered. `seam_unavailable` is an explicit BLOCK status, not
  a pass. The WS `chat.ack` carries `error_code` but never the offending content; `detectors`
  is metadata-only.
- **Honesty boundaries** (§ below) are non-removable and stated verbatim in the specs.

## 5. Honesty boundaries (verbatim, non-removable)

1. **Huddles are 1-on-1 ONLY.** Group/multi-party huddles are R-011 (post-investment) and are
   out of scope. There is no participant-list surface.
2. **The Sentinel inspection integration is a SEAM ONLY.** R-001 reserves the result fields and
   the fail-closed error codes; the actual PII/injection/secret detection is R-008 and is NOT
   implemented. Huddle media is never content-inspected.
3. **The Delta-team → channel auto-mapping is a SEAM ONLY.** The channel `source` /
   `external_ref` fields document the extension point; the mapping is R-006 vs D-016 with a
   manual fallback. R-001 never auto-maps — every channel defaults to `source:"manual"`.
4. **Archival fields are defined ONLY.** Immutable archiving is R-009.
5. **Self-contained.** No dependency on Orchestrator/Delta contracts; only documented
   future-seam stubs (O-010 identity, R-008 inspection, R-006/D-016 channel-mapping).
