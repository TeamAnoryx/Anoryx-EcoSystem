# ADR-0007: Orchestration Hooks — Inspection Layer Between Gateway and Upstream

- **Status:** Accepted (human-approved 2026-06-16; all 3 contract reconciliations ratified)
- **Date:** 2026-06-16
- **Task:** F-005 (Orchestration Hooks)
- **Owner:** api-architect
- **Supersedes:** none
- **Related:** ADR-0002 (OpenAI-compatible surface), ADR-0003 (event/policy schemas), ADR-0004 (persistence / hash-chained audit), ADR-0006 (gateway architecture)
- **Contracts referenced (FROZEN — read-only for this ADR):**
  - `contracts/openapi.yaml` (F-001)
  - `contracts/events.schema.json` (F-002)
  - `contracts/ids.md` (Phase 0, LOCKED)

> Honest-language note (per CLAUDE.md): this document says "high-coverage detection," "risk reduction," and "likely defect" — never "100% detection," "blocks all attacks," "compliant," or "certified." F-005 reduces exposure; it does not eliminate it.

---

## 1. Context

F-004 shipped the OpenAI-compatible gateway: a reverse proxy on FastAPI with a fixed, non-bypassable middleware order and a single in-handler pipeline in `src/gateway/routes/chat_completions.py::create_chat_completion`. That handler validates the request body, resolves tenant context, rate-limits, then proxies to the upstream model — with terminal audit emitted on every outcome.

F-005 inserts an **inspection layer** between the validated request and the upstream call (and between the upstream response and the client flush). This layer must:

1. Detect and act on PII (mask / tokenize / block) — emitting `pii_blocked`.
2. Detect prompt injection — emitting `injection_detected`.
3. Detect secrets in inbound and outbound traffic — emitting `secret_leaked`.
4. Provide an *event-emission primitive* for shadow-AI signals — `shadow_ai_detected` (gated OFF by default; see §13).

All four events must conform **exactly** to `contracts/events.schema.json` (F-002), which is FROZEN. F-005 writes no new endpoints, changes no error envelope, and does not reorder middleware. It attaches inside the existing handler only (Decision D6).

This ADR records the architecture and every load-bearing decision. The downstream detector implementations (`src/data_protection/`, `src/defense/`) conform to the contracts and decisions stated here.

### 1.1 Contract shapes verified against the frozen files (not a summary)

Read directly from `contracts/events.schema.json` and `contracts/openapi.yaml` on 2026-06-16:

**Common envelope** (every event variant, all REQUIRED):
`event_type`, `tenant_id` (uuid), `team_id` (uuid), `project_id` (uuid), `agent_id` (slug `^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64 — internal Sentinel component name, NOT the model name), `event_id` (uuid), `event_timestamp` (RFC3339 UTC, ≤64), `request_id` (`^[A-Za-z0-9._-]{1,64}$`). All objects are `additionalProperties:false` and all fields bounded.

**`pii_blocked`** — required: `pattern_name` (≤128, never the matched value), `severity` (`low|medium|high|critical`), `action_taken` (`masked|tokenized|blocked`). Optional: `sample_excerpt_redacted` (≤256, pattern requires a redaction marker `[REDACTED]` or `***` to be PRESENT — the schema does NOT guarantee absence of raw PII; suppression is the emitter's runtime obligation; omit if it cannot be guaranteed).

**`injection_detected`** — required: `classifier_score` (number 0..1), `rule_matched` (≤128, never the offending text), `action_taken` (`blocked|logged`).

**`secret_leaked`** — required: `secret_type` (`api_key|token|private_key|credential` — exactly these 4), `direction` (`inbound|outbound`), `action_taken` (`masked|tokenized|blocked`).

**`shadow_ai_detected`** — required: `detected_endpoint` (≤256, pattern `^[^?#@\s]+$` — host/path only; no `?`, `#`, `@`, or whitespace, so query/fragment/userinfo cannot ride along), `traffic_volume` (int 0..1e9), `first_seen_at` (RFC3339 UTC).

**`policy_violated` EXISTS in the frozen schema** (event_type `policy_violated`) — required: `policy_id` (uuid), `violation_type` (`^[A-Za-z0-9._-]{1,128}$`), `action_taken` (`blocked|throttled|warned`). The F-005 context pack suspected it might be absent; it is present. F-005 does **not** emit `policy_violated` (that belongs to Delta-sourced policy enforcement, a later task); F-005 emits only the four inspection events above. This is recorded so no one re-derives the wrong conclusion.

**Error envelope** (`contracts/openapi.yaml`, `Error.error_code` enum, exact):
`missing_required_header`, `invalid_request`, `request_too_large`, `invalid_api_key`, `id_context_mismatch`, `policy_blocked`, `rate_limit_exceeded`, `internal_error`. **There is no `policy_violated` error_code and no new code may be added** (contract frozen). The `Forbidden` (403) response description explicitly covers "an inspection finding (e.g. detected secret leak or injection) blocks it." The `SSEErrorEvent` schema specifies the mid-stream fail-safe: emit one `event: error` frame carrying the standard `Error` envelope, then close the stream WITHOUT a `data: [DONE]` sentinel.

**Auth:** `bearerAuth` (HTTP bearer, virtual API key). F-005 adds no auth surface.

---

## 2. Decision: a hook-chain (not middleware, not decorators)

**Decision.** F-005 inspection runs as an ordered **hook-chain** invoked *inside* `create_chat_completion`, not as new ASGI middleware and not as route decorators.

**Why not middleware.** The F-004 middleware order is immutable (`TerminalAudit → CORS → RequestValidation → TenantContext → Auth`, then in-handler `resolve_tenant_context → check_rate_limit → body validation → upstream`). Inspection needs the *typed, validated* `CreateChatCompletionRequest` and the *server-resolved* `TenantContext` (four stable IDs + `virtual_key_id`). Those exist only after body validation inside the handler. A middleware layer sees raw bytes before validation (wrong data) or would have to re-parse (duplicate work, parser-differential risk). Inserting middleware would also violate D6 and the frozen order.

**Why not decorators.** Decorators bind statically at import and are awkward to (a) inject a test registry into and (b) order deterministically across request/response phases. A decorator stack also obscures the pre-upstream vs post-upstream split that secrets-on-response requires.

**Why a hook-chain.** A registry of ordered hook objects gives: explicit, testable ordering (Decision D1); a clean dependency-injection seam (Decision D8); per-phase placement (pre-upstream request hooks vs post-upstream response hooks); and a single fail-safe wrapper (Decision D3) around the whole chain. It is the smallest change that satisfies the frozen contracts.

---

## 3. Decision: Presidio for PII detection

**Decision.** PII detection uses Microsoft **Presidio Analyzer** (recognizer engine) behind the `src/data_protection/` interface, not hand-rolled regex and not a commercial DLP SaaS.

**Why not custom regex.** PII (names, addresses, SSNs, phone numbers, credit cards with Luhn, IBANs) needs context-aware NER plus checksum validators. Hand-rolled regex has a high false-positive rate and poor recall — it would undercut the "high-coverage detection" claim and produce noisy `pii_blocked` events.

**Why not commercial DLP.** A SaaS DLP egresses customer prompt content to a third party — unacceptable for a zero-trust gateway whose own traffic is the asset being protected. It also adds a network hop inside the request path (latency budget, §15) and a vendor dependency in the security-critical path.

**Why Presidio.** Runs in-process (no content egress), is open-source and auditable, provides a confidence score per finding (maps to `severity` and gates on `PII_CONFIDENCE_THRESHOLD`), and ships extensible recognizers. The confidence-to-severity mapping is an emitter-side decision; the contract only constrains the enum.

**Honest scope.** Presidio is English-first. Multi-language PII is explicitly deferred to F-005b (§16). F-005 does not claim multi-language coverage.

---

## 4. Decision: rule-based injection detection for F-005 (ML deferred to F-007)

**Decision.** Prompt-injection detection in F-005 is **rule/heuristic-based** (curated pattern set + lightweight scoring producing `classifier_score ∈ [0,1]`). The ML classifier is deferred to F-007.

**Why.** A rule engine is deterministic, auditable, cheap (fits the latency budget, §15), and gives a stable `rule_matched` ID and an explainable score today. An ML classifier needs a labelled corpus, an eval harness, drift monitoring, and a model-hosting story — none of which exist in Phase 0. Shipping rules now provides risk reduction immediately; F-007 raises recall on obfuscated attacks.

**Contract fit.** `classifier_score` is required and numeric `[0,1]`; the rule engine emits a normalized heuristic score in that range. The field name says "classifier" but the contract does not mandate an ML model — a normalized rule score satisfies it and is documented as such so downstream consumers do not over-read the value. `action_taken` is `blocked` when `classifier_score ≥ INJECTION_SCORE_THRESHOLD` (default 0.75), otherwise `logged`.

---

## 5. Decision: windowed streaming inspection for secrets (Decision D2)

**Decision.** Outbound (response-side) secret inspection over a stream uses a **bounded sliding window**, not naive per-chunk inspection and never full-response accumulation.

**Why.** SSE delta content arrives in chunks (`chunk.delta.content` is available before `yield` at ~line 317 of the handler). A secret (e.g. an `sk-...` key, a PEM block) can straddle a chunk boundary; per-chunk inspection would miss the split token (threat #8 — splitting; see also threat #5). Accumulating the whole response to inspect it would let a hostile or runaway upstream exhaust gateway memory (threat #8 — memory exhaustion).

**Pattern.** Carry forward only the **tail** of the previous chunk — at most `STREAM_INSPECT_BUFFER_BYTES` (default **8192 bytes / 8 KiB**, the longest secret pattern plus margin). On each chunk: inspect `(carried_tail + new_chunk)`; then retain only the last `STREAM_INSPECT_BUFFER_BYTES` bytes as the next tail. The buffer is bounded and constant; the full response is never held. If a secret is found mid-stream, the gateway stops emitting content chunks and emits exactly one `SSEErrorEvent` (`event: error` with the standard `Error` envelope, `error_code: policy_blocked`), then closes WITHOUT `[DONE]` — per the frozen `SSEErrorEvent` schema and the streaming fail-safe.

---

## 6. Decision D1: hook-chain ordering + the masking-vs-injection rule

**PreRequestHooks (pre-upstream, after body validation, before proxy call), in this fixed order:**

1. **Secret (inbound, `direction:"inbound"`)** — scan raw user content first; a secret in a prompt is the highest-confidence, lowest-false-positive signal and we want it caught before any mutation.
2. **Injection** — scan against an **immutable snapshot of the original user content** taken before any PII masking mutates the payload.
3. **PII** — mask / tokenize / block last, so masking mutates the payload only after injection has already scored the original text.

**PostResponseHooks (post-upstream, before flush / before the non-stream JSONResponse; windowed for streams):**

1. **Secret (outbound, `direction:"outbound"`)** — catch keys/credentials the model echoed back.

**The masking-vs-injection rule (threat #7).** Injection MUST score the *original, unmasked* user content. If PII masking ran first, masked spans (e.g. `[REDACTED]`) could hide or fragment an injection payload, lowering recall. Therefore: **injection inspects an original-content snapshot captured before PII masking; PII masking runs after and operates on the payload that is actually forwarded upstream.** The two hooks read the same original input; only PII mutates what is forwarded. State of record: *no inspection hook ever reads a payload already mutated by a different inspection hook.* Each hook receives the original snapshot for detection; mutation (PII masking/tokenization) is applied to the outgoing copy in a defined, last-position step.

**Role scoping (threat #4 — system-role spoof).** Inspection hooks examine **only messages with `role:"user"`**. The `system` (and `assistant`/`tool`) roles are caller-owned trusted context per the OpenAI surface; treating attacker-supplied `system` text as trusted is out of scope — we do not let a client elevate injected text by relabeling its role, because we simply do not grant `system` any inspection-bypass: we just never *trust* user content, and we never *inspect* system content as if it were adversarial input the caller didn't author. Documented honestly: a caller that pastes attacker text into its own `system` prompt is trusting that text by construction; F-005 does not defend the caller against itself.

---

## 7. Decision D3: failure-mode semantics (FAIL-SAFE BLOCK)

**Decision.** If any hook raises an *unexpected* exception (not a clean detection result), the request is **BLOCKED**. Inspection failure never falls through to the upstream (CLAUDE.md non-negotiable #5: "on ANY inspection or policy error → BLOCK").

**What is emitted.** The fail-safe block is recorded as an audit row via the terminal-audit path the handler already runs on every outcome. F-005 does **not** invent a new event type for hook-exception failures and does **not** emit `policy_violated` (that is reserved for Delta-policy enforcement). The fail-safe is captured by the existing terminal record plus an `internal_error`-level structured log (no content, no PII — correlate by `request_id`). If a *clean detection* (not an exception) decides to block, the corresponding inspection event (`pii_blocked` / `injection_detected` / `secret_leaked`) with `action_taken:"blocked"` is appended; the fail-safe path is reserved for *exceptions*.

**HTTP / SSE response.**
- **Pre-upstream (non-stream):** raise a `GatewayError` that surfaces as **403 `policy_blocked`** for a clean detection-block, or **500 `internal_error`** for an unexpected hook exception (fail-safe). Both reuse existing enum codes; no contract change.
- **Stream (mid-stream finding or hook exception):** stop content, emit one `SSEErrorEvent` (`event: error`, `error_code: policy_blocked` for a detection-block, `internal_error` for an exception), close WITHOUT `[DONE]`. Once 200 headers are committed the status cannot change — the SSE error frame is the fail-safe signal, consistent with ADR-0006's streaming-audit constraint.

---

## 8. Decision D4: event cap per request

**Decision.** Each detector emits at most `EVENTS_PER_DETECTOR_CAP` (default **10**) events per request (threat #9 — event-flood DoS). A document with 500 emails must not produce 500 `pii_blocked` events.

**Where enforced.** The cap is enforced **inside the hook-chain executor** (the per-request hook context), not in the detector and not in the repository. The executor holds a per-`request_id`, per-detector counter; once the cap is hit, further findings of that type are still *acted on* (masked/blocked) but **coalesced** — no further events for that detector are appended for that request. The action (the security outcome) is never suppressed; only the event volume is bounded. This keeps the audit log bounded without weakening enforcement.

---

## 9. Decision T1: `secret_type` mapping table (9 formats → 4 enum values)

The detector recognizes 9 formats; the frozen enum has exactly 4 values (`api_key`, `token`, `private_key`, `credential`). Mapping, with rationale:

| # | Detected format                                  | `secret_type` | Rationale |
|---|--------------------------------------------------|---------------|-----------|
| 1 | OpenAI `sk-...`                                  | `api_key`     | Provider API key — long-lived service credential. |
| 2 | Anthropic `sk-ant-api03-...`                     | `api_key`     | Provider API key. |
| 3 | AWS `AKIA...`                                    | `api_key`     | Access key ID is the public half of a long-lived API credential pair. |
| 4 | Stripe `sk_live_...` / `pk_live_...`             | `api_key`     | Provider API key (live). |
| 5 | Slack `xoxb-...` / `xoxp-...`                    | `token`       | OAuth bearer/bot token — session-style bearer, not a static provider key. |
| 6 | GitHub `ghp_` / `gho_` / `ghs_`                  | `token`       | Personal/OAuth/server access token — bearer token semantics. |
| 7 | JWT `eyJ...` (`header.payload.signature`)        | `token`       | Bearer token by definition. |
| 8 | SSH / PEM `-----BEGIN ... PRIVATE KEY-----`      | `private_key` | Asymmetric private key material. |
| 9 | Generic high-entropy string                      | `credential`  | Unclassifiable secret-like material; `credential` is the catch-all. |

**Design rule:** provider-issued **static keys** → `api_key`; **bearer/OAuth tokens** (Slack, GitHub, JWT) → `token`; **asymmetric private keys** → `private_key`; **everything else secret-like** → `credential`. The secret value itself is NEVER placed in any event field (enforced by the schema and by D7). Downstream detector implementations conform to this table.

## 10. Decision T2: `redact` action → `action_taken: "masked"`

The spec's data-protection feature wants a `[REDACTED:<type>]` substitution on responses. The frozen `pii_blocked` / `secret_leaked` `action_taken` enums have no `redact` value (`masked|tokenized|blocked`). **Decision:** "redact" is a form of masking — emit `action_taken:"masked"`. Tokenization (reversible token swap) maps to `tokenized`; full rejection maps to `blocked`. No contract change.

## 11. Decision T3: which existing `error_code` a hook BLOCK surfaces as

Confirmed from `contracts/openapi.yaml` (no `policy_violated` error_code exists; the enum is the 8 codes listed in §1.1). Mapping for blocks:

| Block cause                                        | HTTP | `error_code`     | Source of authority |
|----------------------------------------------------|------|------------------|---------------------|
| PII detection → block (`PII_ACTION=block`)         | 403  | `policy_blocked` | Forbidden response covers inspection-finding blocks. |
| Injection detection → block                        | 403  | `policy_blocked` | Forbidden response: "detected secret leak or injection blocks it." |
| Secret detection → block                           | 403  | `policy_blocked` | Same Forbidden clause names secret leak. |
| Hook unexpected exception (fail-safe, D3)          | 500  | `internal_error` | InternalError response: inspection cannot complete → block. |

PII handled by **mask/tokenize** (not block) does **not** error — the request proceeds with a mutated payload and a `pii_blocked` event with `action_taken:"masked"|"tokenized"`. We do **not** use `invalid_request` (400) for PII: PII is not a malformed request, it is a policy/inspection outcome, so 403 `policy_blocked` is correct. **Event for fail-safe block:** there is no `policy_violated` *event* emitted by F-005 (see §1.1 and §7); the fail-safe is captured by the existing terminal audit record, not by a new event type.

---

## 12. Decision D7: info-disclosure invariants on event fields (threat #11)

- `sample_excerpt_redacted` (pii_blocked, optional) MUST be **loud-redacted** and MUST NEVER contain raw PII even after redaction. The schema only checks that a marker is *present*; it does not prove raw PII is *absent*. **Invariant:** the emitter constructs the excerpt by replacing the matched span with a marker derived solely from the pattern type — it never copies surrounding raw characters that could themselves be PII. If the emitter cannot guarantee this for a given finding, it **omits the field** (the contract makes it optional precisely for this).
- `rule_matched` (injection) and `pattern_name` (pii) are **stable rule/pattern IDs** — never the offending input text. **Invariant:** these fields are drawn from a fixed catalog of identifiers; attacker payload never flows into them (log-injection and disclosure defense, consistent with the contract's charset restrictions on other ID fields).
- The secret value is **never** emitted in any field; `secret_type` carries only the 4-value classification.
- `detected_endpoint` (shadow_ai) is host/path only; the schema structurally forbids `?`, `#`, `@`, whitespace so query/fragment/userinfo (which can carry keys/PII) cannot ride along. The emitter strips these before emission anyway (defense in depth).

---

## 13. Honest shadow-AI scope (threat #10)

**F-005 ships only the `shadow_ai_detected` event-emission primitive.** It is gated behind `SHADOW_AI_EMISSION_ENABLED` (default **false**). F-005 contains **no real shadow-AI detection**: it does not monitor network egress, does not inspect DNS, and cannot observe traffic to endpoints that bypass the gateway. Real detection (network egress monitoring) is **deferred to F-007**.

When the flag is enabled, the primitive can emit a contract-valid `shadow_ai_detected` event (host/path-only `detected_endpoint`, bounded `traffic_volume`, `first_seen_at`) from an out-of-band signal source — but in F-005 no such source is wired. This is stated plainly so no one reads F-005 as delivering shadow-AI detection. It delivers the *event shape and the emission seam*, nothing more.

---

## 14. Threat model — 12 vectors, each with a defense or an honest deferral

| # | Threat | F-005 response |
|---|--------|----------------|
| 1 | Encoded PII (base64 / hex / URL-encode / ROT13) | **Honest deferral.** F-005 does NOT decode-then-scan; it inspects literal content. Encoded PII is likely missed → deferred to F-007 (ML) / F-005b. Stated, not hidden. |
| 2 | Char-substitution / leetspeak PII | **Honest deferral.** Rule/Presidio recall on obfuscated text is limited; deferred to F-007. Not claimed as covered. |
| 3 | Injection split across multiple messages | Partial: F-005 concatenates all `role:"user"` messages into the injection-scan snapshot, so simple cross-message splits are scored together. Sophisticated semantic splitting deferred to F-007. |
| 4 | System-role spoof | Inspection examines **only `role:"user"`** content (D1). `system` is caller-owned trusted context; F-005 does not let a client launder injected text by relabeling roles, and does not defend a caller against text it placed in its own system prompt. |
| 5 | Secret regex line-split / comment bypass | Inbound: scan the joined user content (not per-line). Outbound stream: bounded sliding window (D2/§5) catches secrets straddling chunk boundaries. Deeply restructured secrets (interleaved comments) may evade → noted limitation. |
| 6 | Entropy false-positive cascade on UUIDs | Before the entropy check: **allowlist UUIDv4** and **common base64 padding shapes**; require `MIN_TOKEN_LENGTH_FOR_ENTROPY` (default 20) and `ENTROPY_THRESHOLD`. Reduces the false-positive flood that would otherwise trip `credential` on every request ID. |
| 7 | Masking hides injection | **Defended.** Injection scans the original-content snapshot taken BEFORE PII masking mutates the payload (D1 masking-vs-injection rule). |
| 8 | Streaming memory exhaustion | **Defended.** Bounded sliding window, max `STREAM_INSPECT_BUFFER_BYTES` (8 KiB); full response never accumulated (D2). |
| 9 | Event-flood DoS | **Defended.** `EVENTS_PER_DETECTOR_CAP` (10) per detector per request, enforced in the executor; action never suppressed, only event volume coalesced (D4). |
| 10 | Shadow AI bypassing the gateway | **Honest deferral.** F-005 has no egress monitoring; emission primitive only, default OFF (§13). Deferred to F-007. |
| 11 | Info disclosure via event fields | **Defended.** Loud-redacted excerpts, rule/pattern IDs only, secret value never emitted, endpoint host/path only (D7/§12). |
| 12 | Hook failure passes traffic through | **Defended.** Fail-safe BLOCK on any unexpected hook exception (D3); inspection failure → 403/500/SSE-error, never upstream pass-through. |

---

## 15. Trade-offs

- **False-positive rate.** Rule-based injection + entropy-based generic-secret detection will produce false positives. Mitigations: `INJECTION_SCORE_THRESHOLD` (0.75) and `PII_CONFIDENCE_THRESHOLD` (0.85) gates, UUID/base64 allowlisting (threat #6), and `MIN_TOKEN_LENGTH_FOR_ENTROPY` (20). We accept residual false positives in exchange for fail-safe behavior; this is "risk reduction," not "blocks all attacks."
- **Per-detector latency budget.** Inspection sits in the synchronous request path. Target budget: PII ≤ ~30 ms, injection ≤ ~5 ms, inbound secret scan ≤ ~5 ms on typical bodies, bounded by `MAX_PII_INSPECT_CHARS` (50000). Bodies beyond that cap are truncated for inspection (the truncation itself is a known recall limitation, recorded honestly).
- **Memory bounds.** Streaming inspection is O(1) in response size (8 KiB window). Non-stream inspection is bounded by `MAX_PII_INSPECT_CHARS` and the 1 MiB body cap already enforced upstream by F-004.
- **Determinism vs recall.** F-005 chooses deterministic, auditable rules over higher-recall ML — a deliberate Phase-0 trade favoring explainability and the audit-ready posture; recall improves in F-007.

---

## 16. Deferred to future tasks

- **ML injection classifier** → F-007 (raises recall on encoded/obfuscated/semantic-split injection; threats #1, #2, #3).
- **Multi-language PII** → F-005b (Presidio is English-first today; §3).
- **Shadow-AI network egress monitoring** → F-007 (F-005 ships emission primitive only, default OFF; §13, threat #10).
- **Per-tenant custom regex / custom PII recognizers** → F-008.
- **Decode-then-scan (base64/hex/URL/ROT13)** → F-007 (threat #1).

---

## 17. Decision D6: integration touch points on F-004

Hooks attach **inside `create_chat_completion` only**:

- **PreRequestHooks:** after Step-7 body validation (`validated: CreateChatCompletionRequest` ready, `tenant_context` resolved, `request_id` from `request.state.request_id`) and **before** the upstream proxy call (before `proxy_non_stream` / before building the `StreamingResponse`).
- **PostResponseHooks (non-stream):** after `proxy_non_stream` returns the full `ChatCompletionResponse` and **before** the `JSONResponse` is constructed.
- **PostResponseHooks (stream):** inside `_generate()`, applied to each chunk's `delta.content` (available before `yield`) via the bounded sliding window; a finding stops content and emits the `SSEErrorEvent` before the chunk would have been yielded.

**No change to:** the immutable middleware order (`TerminalAudit → CORS → RequestValidation → TenantContext → Auth`), the in-handler pipeline order (`resolve_tenant_context → check_rate_limit → body validation → upstream`), the route set, or the `Error` envelope. F-005 adds no endpoints, no headers, and no error codes.

**Event persistence.** Each inspection event is appended via the existing privileged-session path:
`async with get_privileged_session() as session: async with session.begin(): AuditLogRepository(session).append(event_data)` — where `event_data` keys match `events.schema.json` field names **exactly**, including all four stable IDs (sourced from the resolved `TenantContext`, server-resolved — never raw client headers), `event_id` (new UUIDv4), `event_timestamp` (RFC3339 UTC), and `request_id` (from `request.state.request_id`). `agent_id` is the emitting component slug (e.g. `data-protection` for PII/secret, `defense` for injection), not the model name.

---

## 18. Decision D8: HookContext shape and DI seam

**HookContext** (the per-request object passed to each hook; field names illustrative, not a contract):

- `tenant_context: TenantContext` — the four server-resolved stable IDs + `virtual_key_id`.
- `request_id: str` — the one canonical ID from `request.state.request_id`.
- `original_user_content: str` — immutable snapshot of joined `role:"user"` content, captured before any masking (basis for injection scan; D1).
- `phase: Literal["pre_request", "post_response"]`.
- `event_budget: dict[detector, int]` — per-detector remaining event allowance (D4).
- `emit(event: dict) -> None` — appends a contract-valid event via the privileged-session repository path; enforces the per-detector cap; stamps the four IDs + `event_id`/`event_timestamp` so individual hooks cannot forget or forge them.

**DI seam.** A `HookRegistry` (ordered PreRequest and PostResponse hook lists) is **injected into the handler** rather than imported as a module global, so tests stub the registry (e.g. a recording hook, a raising hook to exercise fail-safe, an empty registry for passthrough). The registry's order is fixed per D1; injection controls *which* hooks, not their relative order. Detectors live in `src/data_protection/` and `src/defense/` and depend only on the abstract hook interface, not on FastAPI.

---

## 19. Configuration surface

All from runtime env / settings (Vault/KMS for any secret material; never in code or logs per non-negotiable #4). Defaults shown:

| Setting | Default | Purpose |
|---------|---------|---------|
| `PII_DETECTION_ENABLED` | `true` | Master toggle for the PII hook. |
| `PII_ACTION` | `mask` | One of `mask` / `tokenize` / `block` → `action_taken` `masked`/`tokenized`/`blocked` (T2). |
| `PII_CONFIDENCE_THRESHOLD` | `0.85` | Min Presidio confidence to act/emit. |
| `MAX_PII_INSPECT_CHARS` | `50000` | Upper bound on chars inspected (latency/memory cap). |
| `INJECTION_DETECTION_ENABLED` | `true` | Master toggle for the injection hook. |
| `INJECTION_SCORE_THRESHOLD` | `0.75` | `classifier_score ≥` ⇒ `action_taken:"blocked"`, else `logged`. |
| `SECRET_DETECTION_ENABLED` | `true` | Master toggle for secret hooks (inbound + outbound). |
| `SECRET_REDACT_CHARACTER` | `*` | Char used for masking redaction output. |
| `ENTROPY_THRESHOLD` | tuned | Shannon-entropy bar for the generic high-entropy → `credential` detector. |
| `MIN_TOKEN_LENGTH_FOR_ENTROPY` | `20` | Min token length before entropy is even evaluated (threat #6). |
| `SHADOW_AI_EMISSION_ENABLED` | `false` | Gates the shadow-AI emission primitive; F-005 has no real detection (§13). |
| `EVENTS_PER_DETECTOR_CAP` | `10` | Max events per detector per request (D4). |
| `STREAM_INSPECT_BUFFER_BYTES` | `8192` | Bounded sliding-window size for outbound stream secret inspection (D2). |

---

## 20. Consequences

- F-005 inserts a fail-safe inspection layer with zero changes to the frozen contracts and zero changes to the F-004 middleware order — by attaching a DI-injected hook-chain inside the existing handler.
- The four inspection events conform exactly to `events.schema.json`; blocks reuse the existing `policy_blocked` (403) and `internal_error` (500) codes and the `SSEErrorEvent` streaming fail-safe.
- Coverage is honest: high-coverage English PII, rule-based injection, multi-format secret detection with bounded streaming; encoded/obfuscated PII, multi-language PII, ML injection, and shadow-AI detection are explicitly deferred. F-005 reduces risk; it does not eliminate it.
- Downstream detector tasks conform to the `secret_type` mapping table (§9), the redact→masked rule (§10), the block error-code mapping (§11), and the disclosure invariants (§12).
