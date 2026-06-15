# ADR-0002: OpenAI-Compatible API Surface

**Date:** 2026-06-15  |  **Status:** Accepted

## Context
Sentinel is a zero-trust AI gateway: a reverse proxy that sits between enterprise
systems and the AI models they use (ADR-0001 establishes it as the data path for
the whole ecosystem). To be adopted, it must impose near-zero migration cost on
the teams it protects. Those teams already use the OpenAI SDKs and the OpenAI HTTP
shapes. We need to decide the public API surface for Phase 0, and lock it in
`contracts/openapi.yaml` as the single source of truth that all builder agents,
plus Anoryx-AI-Orchestrator and Delta, conform to.

## Decision

### OpenAI-compatible surface
We expose an OpenAI-compatible API so a client changes ONE base URL and nothing
else — existing OpenAI SDKs work unmodified. Phase 0 surface (no more, no less):

- `POST /v1/chat/completions` — non-streaming JSON and `stream: true` SSE
- `POST /v1/completions` — legacy text completion, non-streaming JSON and SSE
- `GET  /v1/models` — model discovery, filtered by policy allow-list

Streaming responses use `text/event-stream`: each event is a `data:` line carrying
a chunk object, terminated by a `data: [DONE]` sentinel, matching the OpenAI wire
format.

### Auth model
A single security scheme, `bearerAuth` (`http` / `bearer`), is applied globally.
The Bearer token is a **virtual API key** issued by Sentinel. It maps server-side
to a vaulted upstream provider credential, so clients never hold provider keys.

- Missing / malformed / revoked / unknown key -> `401`.
- Valid key without permission for the requested resource (model, action, routing
  context) -> `403`.

### Four-ID propagation mechanism and authoritative key→ID binding
The four stable IDs from `contracts/ids.md` (LOCKED, IMMUTABLE) travel as REQUIRED
request headers via a reusable `parameters` component referenced by all three paths:

| Header                 | ID         | Type             |
|------------------------|------------|------------------|
| `X-Anoryx-Tenant-Id`   | tenant_id  | UUID v4          |
| `X-Anoryx-Team-Id`     | team_id    | UUID v4          |
| `X-Anoryx-Project-Id`  | project_id | UUID v4          |
| `X-Anoryx-Agent-Id`    | agent_id   | lowercase slug   |

`agent_id` names the internal Sentinel component, NOT the end-user AI model name
(`model` lives in the request body). All four are required on every inbound
request; missing or malformed ANY of them returns `400` (`missing_required_header`).
Each ID header is bounded at `maxLength: 64`; an overlong value is rejected `400`.

**Key→ID binding (security-critical, supersedes naive header trust).** The ID
headers are NOT the source of truth. Trusting them verbatim would be
impersonation-by-design: any caller could claim any tenant. Instead, Sentinel
resolves `tenant_id` / `team_id` / `project_id` AUTHORITATIVELY and SERVER-SIDE
from the scope bound to the virtual API key. The headers are a cross-check ONLY:
if any supplied ID does not match the key's authorized scope, the request is
REJECTED `403` with the new error code `id_context_mismatch`. Headers can never
widen, override, or impersonate a context the key does not already authorize. The
attribution propagated onto outbound events (`contracts/events.schema.json`,
the join key to Delta) and onto audit logs is always the server-resolved value,
never the raw client header. This decision is recorded in the `bearerAuth`
security-scheme description and in all four parameter descriptions in the spec.

### Error shape (no-leakage, code→message 1:1)
Every non-2xx response uses one minimal envelope:

```json
{ "error_code": "string", "message": "string", "request_id": "string" }
```

It carries no request body, no headers, and no PII (`additionalProperties: false`).
To eliminate message-leakage, both fields are now CONSTRAINED:

- `error_code` is an `enum`: `missing_required_header`, `invalid_request`,
  `request_too_large`, `invalid_api_key`, `id_context_mismatch`, `policy_blocked`,
  `rate_limit_exceeded`, `internal_error`.
- `message` is an `enum` of fixed template strings (`maxLength: 200`), one per
  code, selected SOLELY by `error_code`. There is NO request-derived
  interpolation — no header names, field names, values, or body content are ever
  inserted, so each code maps 1:1 to one stable string. (The prior `BadRequest`
  example interpolated a header NAME; it is now a constant.)
- `request_id` is bounded `maxLength: 64`.

The `request_id` (mirrored in the `X-Request-Id` response header) is the only
correlation handle. Status mapping: `400` malformed/missing/overlong IDs or
out-of-bounds/unknown body (oversized may surface `413`), `401` auth, `403`
policy/inspection denial AND `id_context_mismatch`, `429` rate limit, `500`
internal failure.

### Request-body bounds (fail-safe sizing) and closed schemas
Unbounded bodies are a denial-of-service and a passthrough risk, so:

- A global request-body cap of **1 MiB (1048576 bytes)** is enforced at the edge.
  Oversized requests are rejected `400`/`413` BEFORE parsing or inspection (so an
  attacker cannot exhaust inspection resources) — fail-safe sizing.
- Both `CreateChatCompletionRequest` and `CreateCompletionRequest` set
  `additionalProperties: false` and enumerate every accepted field (`model`,
  `messages`/`prompt`, `max_tokens`, `temperature`, `top_p`, `n`, `stream`,
  `stop`, `user`). Unknown keys are rejected, never silently forwarded upstream.
- Field bounds: `ChatMessage.content` / `prompt` strings `maxLength: 131072`;
  `messages` and `prompt`-array `maxItems: 256`; `stop` strings `maxLength: 256`
  with `stop`-array `maxItems: 4`; `user` / `model` / `name` `maxLength: 256`;
  `max_tokens` `maximum: 131072`; `n` defined explicitly as `minimum: 1,
  maximum: 8` (no longer left to passthrough).

### Rate limiting (enforced server-side, not header-only)
On success and on `429`, responses carry `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `X-RateLimit-Reset` (Unix epoch seconds); `429` also
carries `Retry-After`. These headers REPORT state — they are not the control.
Limits are ENFORCED server-side. Phase 0 defaults, overridable per-key and
per-tenant by Delta policy (`contracts/policy.schema.json`):

- **600 requests per 60-second sliding window**;
- scoped BOTH per virtual key AND per server-resolved `tenant_id` (the stricter
  applies);
- a maximum of **20 concurrent open streaming (SSE) connections per resolved
  tenant**.

Exhausting either the request window or the concurrent-stream cap returns `429`
with `Retry-After`. This supports the Delta budget-enforcement path that throttles
over-budget agents at the gateway.

### Streaming fail-safe (SSE)
Streaming must not fail open. The contract:

- Output chunks are inspected BEFORE they are flushed to the client.
- On any mid-stream inspection/policy finding, the gateway STOPS emitting content
  chunks and emits exactly one terminal `event: error` frame carrying the standard
  `Error` envelope (schema `SSEErrorEvent`), then closes the stream WITHOUT
  `data: [DONE]`. The `text/event-stream` 200 body is `oneOf` the chunk schema or
  `SSEErrorEvent`.
- On an output-policy denial the final emitted chunk carries
  `finish_reason: content_filter`.
- A client that receives a stream ending WITHOUT `data: [DONE]` MUST treat it as
  BLOCKED / incomplete, never as a successful completion.

### Fail-safe semantics
On ANY inspection or policy-evaluation error, Sentinel BLOCKS: a policy/inspection
denial surfaces as `403`, an internal evaluation failure as `500`. Traffic is never
silently passed through on error. Ambiguous or uninterpretable requests are
rejected (`400`) rather than forwarded.

## Consequences
- `contracts/openapi.yaml` moves from `0.1.0-stub` (empty paths) to `1.0.0` with
  the full Phase 0 surface, and is now the binding contract for all builders.
- Migration cost for adopters is a base-URL change plus four routing headers.
- Provider keys stay vaulted behind virtual keys; clients cannot exfiltrate them.
- The four-ID header contract makes every request attributable and every event
  joinable to Delta records — with attribution anchored to the key-resolved values,
  not client-supplied headers, so attribution cannot be forged.

### F-001 security re-work (audit pass)
A security-auditor pass blocked the first draft of `contracts/openapi.yaml`. The
following were applied to this contract and recorded above:

1. (CRITICAL) Authoritative key→ID binding — tenant/team/project resolved
   server-side from the virtual key; headers are cross-check only; mismatch -> `403`
   `id_context_mismatch`. (See Auth / four-ID section.)
2. (HIGH) Bounded request bodies — `maxLength`/`maxItems`/`maximum` everywhere,
   bounded `n`, and a documented global 1 MiB cap rejected before inspection.
3. (HIGH) Closed request schemas — `additionalProperties: false` with every field
   enumerated; no silent passthrough to the upstream model.
4. (HIGH) Streaming fail-safe — terminal `event: error` (`SSEErrorEvent`),
   `finish_reason: content_filter` on output denial, no-`[DONE]`-means-blocked,
   inspect-before-flush.
5. (MEDIUM) Rate limiting — default values, window, dual key+tenant scope, and a
   concurrent-stream cap, all enforced server-side.
6. (MEDIUM) Error-message leakage closed — `error_code` and `message` enums map
   1:1; no request-derived interpolation; `maxLength`; constant `BadRequest` example.
7. (LOW) `maxLength: 64` on `agent_id` and all four ID headers; overlong -> `400`.

## Intentionally deferred (out of Phase 0 scope)
- Embeddings, images, audio, moderation, files, batch, and assistants endpoints.
- Tool/function-calling request and response fields beyond the `tool` role and
  `tool_calls` finish reason placeholders.
- Per-model rate-limit and budget policy schema (lands with `contracts/policy.schema.json`).
- OAuth / mTLS client auth (virtual Bearer key only in Phase 0; internal mTLS is
  an orchestration concern, not part of this public surface).
- Pagination on `GET /v1/models` (current volume does not warrant it — YAGNI).

## Change discipline
Any change to an existing field requires a new ADR; the old field is marked
deprecated with a sunset before removal. The four IDs are immutable and cannot be
renamed without an ADR plus a full migration plan. Framing here is intentionally
"audit-ready" and "risk reduction", never "compliant" or "blocks all attacks".
