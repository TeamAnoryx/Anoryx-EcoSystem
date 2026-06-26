# R-001 Rendly Core Platform API Contract -- Independent Security Audit

- Task: R-001 (Rendly contract-lock; analog of Sentinel F-001)
- Scope: CONTRACT SURFACE ONLY (no server/persistence/signaling -- R-003+). Audited the
  security properties of the contract, focus on the auth scheme and the inspection-seam
  error contract per the dispatch.
- Branch / commit: feat/R-001-rendly-api-contract @ 9133cf3
- Auditor stance: independent red-team. No benefit of the doubt. Code not written by auditor.
- Date: 2026-06-26

## Files reviewed (committed, in-scope only)

- Rendly/contracts/openapi.yaml
- Rendly/contracts/messages.schema.json
- Rendly/contracts/ids.md
- Rendly/docs/adr/0001-rendly-core-contract.md
- Rendly/contracts/README.md
- Rendly/tests/contracts/test_contracts.py
- .github/workflows/rendly-ci.yml

All other modified/untracked working-tree files were ignored (out of scope -- parallel sessions).

## Verdict

PASS -- no High/Critical findings in this pass.
0 Critical, 0 High. Nothing requires human escalation.
1 Medium, 6 Low recorded below as hardening items for the contract and for the downstream
builders (R-003 issuance, R-005 channels, R-008 detection) that conform to it.

Tooling: Semgrep p/python,p/security-audit,p/secrets (ERROR severity) on
tests/contracts/test_contracts.py -> 0 results, 0 errors. No hardcoded secrets in any
in-scope file (examples use REDACTED / truncated non-tokens).

---

## What the contract gets RIGHT (verified, not assumed)

These were attacked and held:

- No tenant/identity widening surface. No request body, client->server WS frame, header, or
  path parameter anywhere carries a client-supplied tenant_id or sender_user_id. ChatSend,
  HuddleInvite, ChannelCreate, UserUpdate, MembershipUpsert, TokenRequest are all free of
  identity/tenant inputs. Tenant/user are structurally server-resolvable-only. This is
  stronger than reject-on-mismatch -- the client cannot even assert a tenant.
- TokenRequest.scope is a documented subset of granted scopes (no widening). Token roles are
  explicitly non-authoritative for channel RBAC (re-resolved server-side) -- defense in depth.
- No cross-tenant existence oracle. NotFound is uniform for cross-tenant vs non-existent;
  read-by-id endpoints (GET /channels/{id}, GET /users/{id}) expose 404 but not 403, and
  ids.md mandates that a cross-tenant id resolves to 404 BEFORE any role check. No 403/404
  enumeration leak in the GET surface.
- Fail-closed inspection is coherent across both transports. REST: block -> 403
  message_blocked; seam-unavailable/internal -> 500 internal_error (BLOCKED, traffic never
  passed through on internal failure). WS: chat.ack.status is binary accepted|blocked, and
  blocked covers BOTH a detector block and seam-unavailable (error_code
  inspection_unavailable). There is no accepted-despite-seam-error path, and there is no REST
  create-message endpoint (send is WS-only), so the synchronous pre-send seam cannot be
  bypassed.
- 1-on-1 huddle boundary is structural. HuddleInvite/HuddleUpdate carry a single scalar
  peer_user_id (not an array) under additionalProperties:false -- a participant list cannot
  be smuggled.
- DoS-via-parse bounds are comprehensive. Every string has maxLength, every array has
  maxItems, additionalProperties:false is on every object (including nested ice_servers items
  and Signal variants), and a body-size cap is enforced at the edge before parse
  (413 request_too_large). No unbounded field found.
- REST Error envelope cannot leak PII/content: message is constrained to a fixed enum of 10
  templates -- structurally impossible to interpolate request data.
- WS auth avoids the token-in-URL anti-pattern. Token rides Authorization: Bearer or the
  Sec-WebSocket-Protocol: rendly.bearer.<jwt> subprotocol (the standard browser workaround),
  never a query string; a bad token fails the handshake 401 with no socket opened.
- idp_subject / external_ref reserved fields are null/ignored in R-001; the JWT documentation
  schema is closed (additionalProperties:false) and token_use:const access prevents
  refresh-as-access confusion.

---

## Findings

### MED-1 -- WS ErrorFrame.message is unconstrained free-text (the REST no-PII guarantee is not mirrored on the WebSocket)
- Severity: Medium
- File: Rendly/contracts/messages.schema.json:541 (ErrorFrame.properties.message)
- Issue: The REST Error.message is locked to a fixed enum (openapi.yaml ~733), so it is
  structurally incapable of carrying request content or PII. The WebSocket ErrorFrame.message
  is declared only {type:string, maxLength:200} -- no enum, no const, no code->message
  binding -- yet its description claims it is a FIXED template chosen SOLELY by error_code that
  never echoes frame content, field names, or PII. The invariant is asserted in prose but not
  enforced by the schema, on the one transport that actually carries the most sensitive data
  (chat text_content).
- Exploit path (contract-as-law): A downstream R-003/R-008 builder conforming to the catalog
  may legitimately emit {msg_type:error, error_code:invalid_message, message:"content
  rejected: <first 100 chars of the chat body>"} and still pass schema validation and CI. On a
  data-never-leaves-the-org product, an error frame that echoes part of a blocked/oversized
  message body back to the sender (or into a frame-logging sink) is exactly the leak the no-PII
  discipline exists to prevent. The schema provides no guard, so the protection rests entirely
  on each builder re-reading the prose.
- Fix: Mirror the REST envelope -- give ErrorFrame.message an enum of fixed templates (one per
  error_code), or split ErrorFrame into a oneOf that binds each error_code const to its message
  const. Add a test asserting WS error messages are drawn only from the fixed set (parallel to
  the REST parity test). This is on the explicitly in-scope inspection-seam error-contract
  surface.

### LOW-1 -- UUID-typed identifiers have no charset pattern (only non-assertive format:uuid + maxLength); inconsistent with the log-injection discipline used elsewhere in the same contract
- Severity: Low
- File: Rendly/contracts/openapi.yaml -- UserIdPath ~556, ChannelIdPath ~565,
  AccessTokenClaims.jti ~851 (and sub/tenant_id/record_id); same in messages.schema.json
  tenant_id/user_id/channel_id/message_id/huddle_id defs.
- Issue: format:uuid is a non-assertive annotation under JSON Schema Draft 2020-12 (most
  validators do not enforce it), so these fields are effectively any string of <= 64 chars with
  any characters. By contrast client_msg_id and request_id carry pattern ^[A-Za-z0-9._-]{1,64}$
  precisely to forbid control characters and whitespace (a stated log-injection defense). jti
  is described as logged for revocation/replay -- an unconstrained jti (or path id) containing
  CR/LF could enable log injection / forged audit lines, in a contract that otherwise guards
  against exactly that.
- Exploit path: A 64-char value with an embedded newline placed in {user_id}/{channel_id} (or,
  post-R-003, in a jti) is schema-valid; if any builder logs it before UUID parsing, it forges
  or splits log lines. Blast radius is limited (cross-tenant ids resolve to 404), but the
  stated log-hygiene posture is not uniformly enforced.
- Fix: Add pattern ^[0-9a-fA-F-]{36}$ (or a strict UUIDv4 regex) to the UUID id schemas, and at
  minimum a charset pattern to jti, matching the discipline already applied to client_msg_id
  and request_id.

### LOW-2 -- Delivered ChatMessage.inspection.status can structurally be blocked/seam_unavailable (the delivered-implies-pass invariant is prose-only)
- Severity: Low
- File: Rendly/contracts/messages.schema.json:261 (ChatMessage.properties.inspection)
- Issue: ChatMessage (a delivered frame) references InspectionResult, whose status enum allows
  pass|blocked|seam_unavailable. The description states a delivered message always carries
  status=pass (fail-closed pre-send means only passed content is delivered), but the schema
  does not enforce it -- a conforming server could emit a delivered chat.message tagged
  blocked/seam_unavailable, contradicting the fail-closed invariant on the wire.
- Exploit path: Not a delivery bypass (the block prevents delivery; anything delivered has
  already passed), but it weakens the structural guarantee a downstream consumer relies on to
  trust inspection.status on received messages, and could mask a server-side fail-open bug.
- Fix: Constrain the delivered-message inspection to a pass-only subschema (status:{const:pass})
  on ChatMessage, keeping the full tri-state enum only on ChatAck/InspectionResult where a
  non-pass value is legitimate.

### LOW-3 -- tenant_context_mismatch (403) is documented but unreachable on the current surface
- Severity: Low (informational / contract clarity)
- File: Rendly/contracts/openapi.yaml:620-624 (Forbidden.examples.tenantMismatch); also ids.md:21-27.
- Issue: The 403 tenant_context_mismatch error is described as the response when a request names
  a different tenant in a path/body. But no path parameter, body field, or header in the entire
  R-001 surface carries a tenant_id -- so the code currently has no trigger. This is NOT a
  vulnerability (the absence of any tenant input is the strongest possible design); the actual
  cross-tenant control is the uniform-404 resource scoping. The only risk is documentation
  confusion: a reviewer could believe a tenant-mismatch check is the primary control when in
  fact 404-uniformity is.
- Fix: Keep the code reserved for forward-compat, but add a one-line note that in R-001
  cross-tenant isolation is enforced solely via tenant-scoped 404 resolution, and
  tenant_context_mismatch activates only if/when a future field accepts a tenant reference.

### LOW-4 -- ChannelCreate accepts a reserved-and-ignored external_ref (and a source) write input
- Severity: Low (informational)
- File: Rendly/contracts/openapi.yaml:961-969 (ChannelCreate.properties)
- Issue: external_ref is documented RESERVED; ignored in R-001, yet it is an accepted optional
  property on the create body (and source is accepted, constrained to [manual]).
  Silently-accepted-but-ignored input is a future-confusion seam: a later builder (R-006/D-016
  auto-mapping) could begin honoring a client-supplied external_ref without re-review, letting a
  client seed the Delta-team mapping pointer.
- Fix: Prefer omitting external_ref from ChannelCreate entirely in R-001 (it is
  server/seam-populated, never client-set), or document that the server MUST reject (not ignore)
  a non-null external_ref until R-006 lands.

### LOW-5 -- No explicit log-redaction directive for the Sec-WebSocket-Protocol bearer token
- Severity: Low
- File: Rendly/contracts/openapi.yaml:440-445 (GET /realtime description)
- Issue: The contract correctly avoids token-in-URL, but the
  Sec-WebSocket-Protocol: rendly.bearer.<jwt> value carries a live bearer token in a request
  header that proxies/servers may log, and that a naive server may echo verbatim in the
  handshake response Sec-WebSocket-Protocol header. Given the contract is otherwise explicit
  about log hygiene (the client_msg_id charset note), the absence of a directive to redact the
  bearer subprotocol value from logs and to not echo the raw token in the response is a gap.
- Fix: Add a normative note to GET /realtime: the server MUST treat the rendly.bearer.<jwt>
  subprotocol value as a secret -- never log it, never archive it, and acknowledge only a
  non-secret subprotocol token in the upgrade response.

### LOW-6 -- test_error_code_message_enum_parity checks cardinality, not the 1:1 code->message pairing it implies
- Severity: Low (test quality)
- File: Rendly/tests/contracts/test_contracts.py:171-179
- Issue: The contract states the code/message pairing is NOT schema-enforced (independent enums)
  and MUST be covered by a unit test. The only test asserts len(codes) == len(messages) -- it
  would pass even if every message were paired with the wrong code. The covered-by-a-test
  assurance is therefore weaker than it reads. (Not a PII risk: message is still confined to the
  fixed enum, so a mispairing yields a wrong-but-fixed string, never request content.)
- Fix: Either add a structural code->message binding in the schema (e.g. a oneOf of
  {error_code:const, message:const} pairs) and validate it, or rename the test to reflect that it
  is a cardinality guard only and add the real pairing assertion once R-003 maps codes to
  messages.

---

## Escalation

No Critical or High findings. No human escalation required for this pass. MED-1 is the priority
hardening item (it closes a stated no-PII invariant gap on the WebSocket error surface); the Low
items are defense-in-depth and clarity hardening for the contract and its downstream conformers.

---

## Disposition (post-review follow-up, same PR / branch)

Both independent reviews — security PASS (0 Critical / 0 High) and code-review BLOCK
(1 HIGH + 5 MED + 6 LOW) — were verified correct and applied in the follow-up commit:

- **HIGH (code-review):** `Membership` now carries `tenant_id` (every resource does, per ids.md).
- **MED-1 (security + code-review):** WS `ErrorFrame.message` is now an 8-value fixed enum (one
  per `error_code`), closing the no-PII free-text gap; companion WS parity test added.
- **MED (code-review):** `ChatAck` accepted/blocked invariant is schema-enforced (`if/then`);
  `/realtime` requires only `chat:read` (read-only clients can receive); 4 server→client frames
  now carry `tenant_id`.
- **LOW:** UUID-shape patterns on id fields + `jti` charset (log-injection); `ChatMessage.inspection`
  narrowed to `status:pass`; `ChannelCreate` rejects (not ignores) the reserved mapping-seam fields;
  `tenant_context_mismatch` documented as reserved (isolation is tenant-scoped 404); `oauth2`
  reference fixed; `X-Request-Id` on 204s; honest-language reword; cross-file
  `ArchivalMeta`/`InspectionResult` drift-guard test; stronger canonical error-pairing tests.

All contract examples re-validate; black/ruff clean; 57 contract tests green.
