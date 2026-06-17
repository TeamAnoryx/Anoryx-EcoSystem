# ADR-0008 — Multi-Provider Model Router (F-006)

- **Status:** Proposed
- **Date:** 2026-06-16
- **Deciders:** api-architect (owner), gateway-core (STEP-5 implementer), security-auditor (gate), orchestration-lead
- **Supersedes / amends:** Extends ADR-0006 (gateway architecture, single-upstream proxy) and ADR-0007 (orchestration hooks / F-005 inspection). Frozen by ADR-0002 (OpenAI-compatible surface) and the contracts in `Anoryx-Sentinel/contracts/`.
- **Feature:** F-006 — turn the single-upstream gateway into a router across OpenAI (Chat Completions), Anthropic (Messages API), and AWS Bedrock (Converse API).

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

F-004 shipped an OpenAI-compatible gateway: a FastAPI reverse proxy with a fixed,
non-bypassable middleware order and one in-handler pipeline in
`src/gateway/routes/chat_completions.py::create_chat_completion`. Steps 5–8 (ID
cross-check, rate-limit, body validation, upstream proxy) run in the handler.
The single upstream is reached via `src/gateway/upstream/openai_proxy.py`
(`proxy_non_stream` / `_proxy_stream_generator`) over one module-global
`httpx.AsyncClient` built in `main.py::_lifespan`. F-005 (ADR-0007) added pre-
and post-response inspection hooks; the post-response hook inspects the *outbound
OpenAI-shape bytes* — non-stream via `json.dumps(completion.model_dump())`
(chat_completions.py:357), streaming via a bounded 8 KiB sliding window inside
`_handle_stream` (chat_completions.py:510, `_extract_chunk_content` L683–699).

The placeholder cost rates in `src/gateway/middleware/audit.py:63-64` already carry
the comment *"Will be replaced by model-specific pricing table in F-006/F-010"* —
F-006 is that table.

### 1.2 Decision (one paragraph)

We introduce a **provider-router seam INSIDE `chat_completions.py`** between the
end of the F-005 pre-request hooks (L305) and the upstream dispatch (L309). The
router selects a **provider adapter** (OpenAI / Anthropic / Bedrock) from a
**per-tenant routing policy** (new `tenant_routing_policy` table), applies a
**security-aware fallback chain**, enforces **client-side cost-estimate ceilings**,
and returns a **translated OpenAI-shape** `ChatCompletionResponse` (non-stream) or
**OpenAI-shape SSE lines** (stream) so that F-005 inspection, the audit path, and
the client all keep seeing the unchanged OpenAI surface on the same
`/v1/chat/completions` endpoint. The OpenAI adapter is a thin delegate to the
existing `proxy_non_stream` / `_proxy_stream_generator`. Anthropic and Bedrock
adapters translate request → provider API and response/stream → OpenAI shape
**before** the F-005 streaming window. We add ONE new event variant
`routing_decision` to `contracts/events.schema.json` for routing observability
(NOT overloading `policy_violated`, which is reserved for Delta-sourced policy).

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-006) |
|---|---|
| `/v1/chat/completions` path, request/response schema, status set `{200,400,401,403,413,429,500}` (ADR-0002) | Internal dispatch: a router wraps the two upstream call sites |
| Route-handler signature `create_chat_completion(request, hook_registry=None)` | New `src/gateway/router/*` adapters + `tenant_routing_policy` table/repo (gateway-core, STEP 5) |
| Middleware pipeline + order (ADR-0006) | Per-provider `httpx.AsyncClient`s created/torn down in `_lifespan` |
| Four stable IDs (`contracts/ids.md`); event common fields | ONE new event variant `routing_decision` (this ADR edits the contract) |
| F-005 invariant: outbound inspection sees OpenAI-shape bytes | Provider→OpenAI translation happens **before** the F-005 window |
| `policy_violated` reserved for Delta policy (ADR-0007 §1.1) | Routing/allowlist/cost blocks emit `routing_decision`, never `policy_violated` |
| `ErrorResponse` envelope + `ERROR_TABLE` codes (no new wire codes) | Provider 4xx/5xx collapse to existing codes per the terminal matrix |

---

## 2. Decision: Provider Adapter Protocol

### 2.1 The interface

Every provider adapter implements one abstract protocol (gateway-core authors it
under `src/gateway/router/adapters/`; this ADR fixes the contract shape):

```text
class ProviderAdapter(Protocol):
    name: Literal["openai", "anthropic", "bedrock"]

    async def complete(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> tuple[ChatCompletionResponse, int, int]:
        """Non-stream. Returns (OpenAI-shape response, tokens_in, tokens_out).
        On provider transport/HTTP failure raises ProviderError(kind=...) — NEVER
        a raw httpx error and NEVER upstream body text."""

    async def stream(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> AsyncIterator[str]:
        """Stream. Yields OpenAI-shape SSE lines ('data: {chunk-json}\n'),
        terminal 'data: [DONE]', or an 'event: error\ndata: {ErrorResponse}\n\n'
        frame then close WITHOUT [DONE] — IDENTICAL framing to
        _proxy_stream_generator. Translation to OpenAI shape happens INSIDE the
        adapter, before any bytes leave it."""
```

`RoutingContext` (router-internal, not a wire type) carries: `request_id`,
`resolved_provider`, `resolved_model`, the per-provider client handle, the
`request_timeout_seconds` deadline / remaining budget, and the attempt index.
It does **not** carry tenant secrets beyond the provider client already bound to
a config-pinned key.

The return contract of `complete()` deliberately mirrors `proxy_non_stream`'s
`(ChatCompletionResponse, int, int)` so the handler's existing
`completion, tokens_in, tokens_out = ...` call site (chat_completions.py:328)
changes only its right-hand side to a router call.

### 2.2 `ProviderError` taxonomy (drives the fallback matrix in §6)

Adapters never raise `httpx` errors or `GatewayError` directly. They raise
`ProviderError(kind, *, status=None)` with `kind ∈`:

| kind | Meaning | Retryable (see §6) |
|---|---|---|
| `transient` | 5xx, connect error, read/idle/overall timeout | YES |
| `rate_limited` | provider 429 | YES (respect Retry-After cap within budget) |
| `auth` | provider 401/403 (our key/SigV4 rejected) | NO — TERMINAL |
| `content_policy` | provider content-filter / safety 4xx (e.g. 400 with safety stop) | NO — TERMINAL |
| `bad_request` | provider 4xx for malformed request (our translation bug) | NO — TERMINAL |
| `parse` | response/stream un-translatable to OpenAI shape | NO — TERMINAL |

The router maps these to wire outcomes; no `ProviderError` ever reaches the client
or the logs with upstream body text attached.

### 2.3 OpenAI adapter (delegate)

`OpenAiAdapter.complete` calls the existing
`proxy_non_stream(validated_body, request_id, upstream_api_key=<config>, overall_timeout=remaining_budget)`
verbatim; `.stream` delegates to `_proxy_stream_generator(...)` verbatim. The only
addition: it wraps the existing `GatewayError("internal_error")` outcomes back into
`ProviderError(kind="transient")` (for 5xx/timeout) or `auth`/`bad_request` based
on the status the proxy already classifies, so the fallback layer can decide
retry vs terminal. Because `openai_proxy.py` currently collapses ALL non-200 to
`internal_error`, gateway-core adds a thin status-classifier in the adapter (it
already has `resp.status_code` at the call boundary). The OpenAI wire shape needs
**no translation** — it is already the canonical shape.

### 2.4 Anthropic adapter (translate)

- **Request → Messages API.** Map only the allow-listed fields (§8 vector #12):
  `model` → `model`; `messages` → split: any `role:"system"` messages are
  concatenated into the top-level `system` string (Anthropic carries system
  separately), remaining `user`/`assistant` messages map 1:1 to
  `messages:[{role, content}]`; `max_tokens` → `max_tokens` (Anthropic
  **requires** it — if the client omitted it, inject the config default
  `ROUTER_ANTHROPIC_DEFAULT_MAX_TOKENS`); `temperature` → `temperature`;
  `top_p` → `top_p`; `stop` (str|list) → `stop_sequences` (list); `stream` →
  `stream`. `n` > 1 is **not** supported by Messages API → if `n>1` and the
  resolved provider is Anthropic, this is a `bad_request` TERMINAL for that
  attempt (the router may fall back to a provider that supports it only if the
  fallback order allows; otherwise exhaustion → 500). No other fields are sent.
- **Response → OpenAI shape.** `content[].text` blocks joined → `choices[0].message.content`;
  `stop_reason` map: `end_turn`→`stop`, `max_tokens`→`length`,
  `stop_sequence`→`stop`, `tool_use`→`tool_calls`, refusal/safety→`content_filter`;
  `usage.input_tokens`→`prompt_tokens`, `usage.output_tokens`→`completion_tokens`,
  sum→`total_tokens`; synthesize `id` (`"chatcmpl-"+uuid4hex`), `object:"chat.completion"`,
  `created:int(time.time())`, `model:<resolved_model>`. The result is a real
  `ChatCompletionResponse` (validated by the Pydantic model) so F-005 non-stream
  inspection sees a normal OpenAI dict.
- **Stream → OpenAI SSE.** Anthropic streams typed SSE events
  (`message_start`, `content_block_delta` with `delta.text`, `message_delta`
  with `stop_reason`, `message_stop`). The adapter translates each into an
  OpenAI `chat.completion.chunk` SSE line: first chunk carries
  `delta.role:"assistant"`; each `content_block_delta.text` → a chunk with
  `delta.content`; the final chunk carries `finish_reason` (mapped as above) and
  the adapter then emits `data: [DONE]`. **Translation is complete before the
  line is yielded**, so the F-005 sliding window in `_handle_stream` receives
  OpenAI-shape SSE exactly as it does for the OpenAI provider (§9).

### 2.5 Bedrock adapter (translate + SigV4)

- **Request → Converse API.** `messages` → Converse `messages:[{role, content:[{text}]}]`
  (system messages → top-level `system:[{text}]`); inference params →
  `inferenceConfig`: `max_tokens`→`maxTokens`, `temperature`→`temperature`,
  `top_p`→`topP`, `stop`→`stopSequences`. `model` → the Bedrock `modelId`
  resolved from the F-006 model-map (§7 / honest deferral §12 for fine-tune
  mapping). `n>1` unsupported → `bad_request` TERMINAL (same rule as Anthropic).
- **Response → OpenAI shape.** `output.message.content[].text` → `choices[0].message.content`;
  `stopReason` map: `end_turn`→`stop`, `max_tokens`→`length`,
  `stop_sequence`→`stop`, `tool_use`→`tool_calls`, `content_filtered`→`content_filter`;
  `usage.inputTokens`/`outputTokens`/`totalTokens` → OpenAI `UsageBlock`;
  synthesize `id`/`object`/`created`/`model` as in §2.4.
- **Stream → OpenAI SSE.** Converse streaming (`ConverseStream`) yields event-stream
  parts (`messageStart`, `contentBlockDelta.delta.text`, `messageStop.stopReason`,
  `metadata.usage`). Adapter translates each into OpenAI `chat.completion.chunk`
  SSE lines, emits `finish_reason` on the terminal chunk, then `data: [DONE]`.
  **Translation precedes the F-005 window** (§9).
- **SigV4 and region.** All Bedrock calls are SigV4-signed with the credentials
  and **region pinned from config** (`AWS_REGION`, never client-influenced). See
  §11 for the library decision.

---

## 3. Decision: Provider Transport Model

One `httpx.AsyncClient` **per provider**, created in `main.py::_lifespan` and torn
down on shutdown, mirroring the existing `init_http_client` config
(`follow_redirects=False`; `httpx.Timeout(connect=min(10,rt), read=stream_timeout,
write=rt, pool=rt)`). Provider base URLs are **CONFIG-PINNED**, never derived from
the request body or any client header (SSRF defense, §8 vector #9).

| Provider | base_url source | Auth header scheme | Notes |
|---|---|---|---|
| OpenAI | `UPSTREAM_BASE_URL` (existing) | `Authorization: Bearer <OPENAI key>` | reuse existing module-global client |
| Anthropic | `ANTHROPIC_BASE_URL` (default `https://api.anthropic.com`) | `x-api-key: <ANTHROPIC_API_KEY>` + `anthropic-version: 2023-06-01` | dedicated client |
| Bedrock | derived from `AWS_REGION` (`https://bedrock-runtime.<region>.amazonaws.com`), config-pinned | SigV4 (service `bedrock`, region `AWS_REGION`) | via `aioboto3` session (§11) |

Implementation note for gateway-core: generalize the module-global single client
into a small registry (`get_provider_client(name)`), keeping
`init_http_client`/`close_http_client` backward-compatible for the OpenAI path so
existing tests are undisturbed. Initialise all configured providers in `_lifespan`;
a provider with no configured key is **not** initialised and is treated as
**not-allowed** for every tenant (a tenant policy listing it still cannot route to
it — fail-closed).

**Alternative considered:** one shared client with per-request base_url override.
**Rejected** — base_url is a client-construction property in httpx; per-request
override invites SSRF and muddies pinning. Per-provider clients keep base URLs
immutable and auditable.

---

## 4. Decision: Per-Tenant Routing Policy Storage

### 4.1 New table `tenant_routing_policy`

Created in **migration 0007** (gateway-core) using the `0004_policies.py`
`op.create_table` template, with FK `tenant_id → tenants.tenant_id ondelete="RESTRICT"`,
the four stable IDs as `String(64)`, and an index on `tenant_id`.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | String(64) PK, FK→tenants | one routing policy row per tenant (PK = tenant_id) |
| `team_id` | String(64) NOT NULL | stable ID (carried for join symmetry) |
| `project_id` | String(64) NOT NULL | stable ID |
| `agent_id` | String(64) NOT NULL | stable ID (component slug) |
| `allowed_providers` | String(64) NOT NULL | CSV subset of `{openai,anthropic,bedrock}`; CHECK non-empty; app validates membership |
| `fallback_order` | String(128) NOT NULL | ordered CSV of providers; MUST be a permutation-subset of `allowed_providers` |
| `cost_ceiling_cents` | Numeric(20,6) NULL | optional per-request client-side cost-estimate ceiling; NULL = no ceiling |
| `created_at` / `updated_at` | DateTime(tz) server_default now() | as in 0004 |

A CHECK constraint enforces `allowed_providers` non-empty. Provider-token
membership and `fallback_order ⊆ allowed_providers` are validated in the
repository (mirrors `policy_repository.py` validation style); a Postgres CHECK
cannot easily validate CSV subset relationships, so the app layer is the gate and
the CHECK is the non-empty backstop.

### 4.2 Default when no tenant row exists (DOCUMENTED)

If a tenant has **no** `tenant_routing_policy` row, the default is:
**all three providers allowed** (`openai,anthropic,bedrock`), **no cost ceiling**
(`cost_ceiling_cents = NULL`), and **`fallback_order = [openai, anthropic, bedrock]`**
— but a provider with no configured credential (§3) is silently excluded from the
effective allow-list (fail-closed on missing key). This default is generous by
design (F-006 is additive; tenants tighten via Delta later) and is recorded here
so it is not re-derived.

### 4.3 Write-path and GRANTs (DECIDES migration 0007 GRANTs)

- **Reads (routing decisions):** via `get_tenant_session(tenant_id)` +
  `RoutingPolicyRepository.get_for_tenant(tenant_id, caller_tenant_id)`. The
  repo's `WHERE tenant_id = caller_tenant_id` is defense-in-depth on top of RLS
  (mirrors `policy_repository.get_by_id`).
- **Writes (provisioning a tenant's routing policy):** **tenant-session write**
  (`sentinel_app`, RLS-enforced), like `policies`. Routing policy is tenant
  config, not the global audit chain, so it does **not** use the privileged
  session.

**Therefore migration 0007 MUST, for `tenant_routing_policy`:**
1. `GRANT SELECT, INSERT, UPDATE ON tenant_routing_policy TO sentinel_app`
   (no DELETE — deactivate via UPDATE, matching 0006's `_DELETE_TABLES = []`).
2. Apply the RLS pattern verbatim from 0006:
   `ALTER TABLE tenant_routing_policy ENABLE ROW LEVEL SECURITY;`
   `ALTER TABLE tenant_routing_policy FORCE ROW LEVEL SECURITY;`
   `CREATE POLICY tenant_isolation ON tenant_routing_policy USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')) WITH CHECK (<same>);`

Without these GRANTs a tenant session cannot read the table (a NEW table gets NO
access by default, per ADR-0005 / 0006). This is called out explicitly so
gateway-core does not ship a table the gateway cannot read.

**Alternative considered:** store routing policy inside the existing Delta-sourced
`policies` table as a new `policy_type`. **Rejected for F-006** — `policies` is
signature-gated Delta intake (`policy.schema.json`, F-008 crypto). Tenant routing
config is Sentinel-local operational state, not signed Delta policy; conflating
them would force routing config through the F-008 signature path prematurely and
muddy the Sentinel↔Delta boundary. (When Delta later wants to *constrain* routing,
it does so via the existing `model_allowlist`/`budget_limit` policy types, which
the router also consults — see §7.)

---

## 5. Decision: Routing Event (`routing_decision`)

### 5.1 Decision

Add a **dedicated `routing_decision`** event variant to
`contracts/events.schema.json`. We do **NOT** overload `policy_violated`
(reserved for Delta-sourced policy enforcement per ADR-0007 §1.1 and the schema's
own `PolicyViolatedEvent` description). Routing/allowlist/cost decisions are a
Sentinel-internal routing concern, not a Delta policy violation; keeping them
separate preserves the Sentinel↔Delta integration semantics.

### 5.2 Variant shape (closed, all fields bounded)

`RoutingDecisionEvent` carries the four stable IDs + `event_id` +
`event_timestamp` + `request_id` (common required fields) plus:

| Field | Type | Bound / enum | Meaning |
|---|---|---|---|
| `event_type` | const | `"routing_decision"` | discriminant |
| `routing_reason` | string slug | `^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64 | e.g. `tenant-allowlist`, `cost-routing`, `fallback-transient`, `fallback-rate-limit` |
| `selected_provider` | enum | `openai\|anthropic\|bedrock` | provider chosen for THIS decision |
| `outcome` | enum | `selected\|allowlist_denied\|cost_blocked\|fallback_attempted\|exhausted` | the routing outcome |
| `attempt_index` | integer | 0..16 | which attempt in the fallback chain (0 = primary) |
| `requested_model` | string | ≤256 | the model the client asked for (echo; never a secret) |
| `action_taken` | enum | `routed\|blocked\|failed_over` | mitigation/disposition (see §5.4) |

`requested_model` is bounded to 256 (same as `UsageEvent.model`). All strings are
bounded; `attempt_index` is capped at 16 (well above any realistic fallback depth)
to remove a DoS-via-inspection vector. The object is `additionalProperties:false`.

### 5.3 Which routing decisions emit an event, and `agent_id`

`agent_id` is the **emitting component slug** = **`gateway-core`** (the router runs
inside the gateway; confirmed by `src/gateway/middleware/audit.py:114` and
ADR-0007 D8 — `agent_id` is the component, never a model/provider name; provider is
carried in `selected_provider`).

| Routing situation | Emits `routing_decision`? | `outcome` | `action_taken` |
|---|---|---|---|
| Primary provider selected and used | YES (1 per request) | `selected` | `routed` |
| Tenant allow-list denies the only/last viable provider | YES | `allowlist_denied` | `blocked` |
| Cost-ceiling breach (pre-request or stream-time) | YES | `cost_blocked` | `blocked` |
| Each fallback attempt (after a retryable failure) | YES (1 per attempt) | `fallback_attempted` | `failed_over` |
| Fallback chain exhausted | YES | `exhausted` | `failed` (mapped to `blocked` if `failed` not in enum) |

> NOTE for gateway-core: the `action_taken` enum above is
> `{routed, blocked, failed_over}`. Map "exhausted/failed" to `blocked`
> (terminal, request not served) to keep the enum minimal; `exhausted` is already
> distinguishable via the `outcome` field. Do NOT add a new `action_taken` value
> without an ADR.

Event volume is bounded by the fallback depth (≤ number of allowed providers ≤ 3
in F-006), so no per-detector cap is needed beyond the natural bound; gateway-core
SHOULD still respect the existing event-budget plumbing if it routes these through
the same emit path.

### 5.4 `action_taken` and `ACTION_TAKEN_BY_EVENT_TYPE`

`routing_decision` **carries `action_taken`** (enum `{routed, blocked, failed_over}`).
Therefore gateway-core MUST add it to `ACTION_TAKEN_BY_EVENT_TYPE`
(`events_audit_log.py:57`):
`"routing_decision": frozenset({"routed", "blocked", "failed_over"})`, and extend
the DB `ck_eal_action_taken` union CHECK (events_audit_log.py:200-204) to include
`'routed','failed_over'` (the column already permits `'blocked'`).

### 5.5 FOUR places gateway-core MUST edit for the new event_type

Adding `routing_decision` requires editing **four** sites. **(1) is done in this
ADR** (the contract is mine). gateway-core does **(2)–(4)** at STEP 5:

1. **`contracts/events.schema.json`** — `oneOf` entry + `$defs/RoutingDecisionEvent`
   + discriminator note. **(api-architect — this ADR; see §13 patch.)**
2. **`src/persistence/models/events_audit_log.py:40`** — add `"routing_decision"`
   to the `VALID_EVENT_TYPES` frozenset.
3. **`src/persistence/models/events_audit_log.py:57`** — add the
   `ACTION_TAKEN_BY_EVENT_TYPE["routing_decision"]` entry (§5.4).
4. **DB `CheckConstraint ck_eal_event_type` (events_audit_log.py:150-157)** — add
   `'routing_decision'` to the `event_type IN (...)` list **via an ALTER in
   migration 0007** (drop + recreate the named CHECK).

### 5.6 New audit columns required (gateway-core, migration 0007)

`routing_decision` introduces content fields not present as columns on
`events_audit_log` (single-table, nullable-variant design, ADR-0004). gateway-core
MUST, in migration 0007, add nullable columns and wire them through the repository:

- Add nullable columns: `selected_provider String(16)`, `routing_reason String(64)`,
  `outcome String(32)`, `attempt_index BigInteger`, `requested_model String(256)`.
  (`action_taken` column already exists and is reused.)
- Add bounded CHECK constraints mirroring the schema enums (e.g.
  `selected_provider IN ('openai','anthropic','bedrock')`,
  `outcome IN ('selected','allowlist_denied','cost_blocked','fallback_attempted','exhausted')`,
  `attempt_index IS NULL OR (attempt_index >= 0 AND attempt_index <= 16)`).
- Add these columns to `_row_to_hash_data` (`audit_log_repository.py:82`) AND to the
  `EventsAuditLog(...)` construction in `append()` (`audit_log_repository.py:229`),
  so the hash chain covers the new fields. **Order matters for the hash:** append
  the new keys in a fixed, documented position; once a row is written the canonical
  JSON is frozen.

This is stated explicitly so the new variant is actually persistable and
tamper-evident, not merely schema-valid on the bus.

---

## 6. Decision: Fallback Retry / Terminal Matrix (security boundary)

The router attempts providers in `fallback_order` (from the tenant policy, §4).
A provider attempt either succeeds (→ 200, stop) or raises `ProviderError`
(§2.2). The disposition is a **literal table** — security-auditor cites these:

| Trigger (`ProviderError.kind` / situation) | Provider HTTP | Disposition | Wire outcome if it is the LAST viable provider | Audit |
|---|---|---|---|---|
| `transient` (5xx, connect, read/idle/overall timeout) | 5xx / none | **RETRY** next provider (within budget) | `internal_error` (500) | `routing_decision` `fallback_attempted` |
| `rate_limited` | 429 | **RETRY** next provider (respect Retry-After capped to remaining budget) | `internal_error` (500) | `routing_decision` `fallback_attempted` |
| `auth` (our key/SigV4 rejected) | 401 / 403 | **TERMINAL — NEVER retried** | `internal_error` (500) | `routing_decision` `exhausted` + ERROR log (no upstream text) |
| `content_policy` (provider safety 4xx) | 4xx | **TERMINAL — NEVER retried** | `internal_error` (500) | `routing_decision` `exhausted` |
| `bad_request` (translation/`n>1`/malformed) | 4xx | **TERMINAL for that provider** (router MAY try next only if the cause is provider-capability, e.g. `n>1` unsupported; a true translation bug is TERMINAL for all) | `internal_error` (500) | `routing_decision` |
| `parse` (un-translatable response) | 200-but-garbage | **TERMINAL** | `internal_error` (500) | `routing_decision` `exhausted` |
| **allow-list deny** (provider not in tenant allow-list) | n/a | **TERMINAL + audit — NEVER silent fallback** | `policy_blocked` (403) | `routing_decision` `allowlist_denied` |
| **cost-ceiling breach** | n/a | **TERMINAL + audit — no silent downgrade** | `policy_blocked` (403) | `routing_decision` `cost_blocked` |
| chain exhausted (all retryable attempts failed) | — | **TERMINAL** | `internal_error` (500) | `routing_decision` `exhausted` |

**Hard rules (non-negotiable):**

- **401/403 from a provider = TERMINAL, never retried.** Retrying an auth failure
  against the next provider would mask a misconfigured credential and burn budget;
  worse, blind fallback after auth failure can leak which providers are configured.
- **Provider content-policy 4xx = TERMINAL, never retried.** A safety refusal is a
  decision, not a transient fault; retrying elsewhere is provider-shopping around a
  safety control and is forbidden.
- **Allow-list deny = TERMINAL + audit, NEVER silent fallback.** If a tenant's
  policy forbids a provider, the router does not quietly pick another; it denies
  with `policy_blocked` (403) and emits `routing_decision` `allowlist_denied`.
  (Within the allow-listed set, retrying *allowed* providers on `transient`/`429`
  is permitted — that is normal fallback, not allow-list bypass.)
- **Exhaustion → 500 `internal_error`, no upstream text leak.** The generic
  `ERROR_TABLE["internal_error"]` message is returned; the true cause is logged
  server-side, correlated by `request_id`, with NO provider body/text (mirrors
  `openai_proxy.py` discipline).

**Retry budget / ordering source.** All attempts share ONE wall-clock budget =
`request_timeout_seconds` (the existing `settings.request_timeout_seconds`,
threaded as the `overall_timeout` to each adapter, decremented by elapsed time per
attempt). A new `ROUTER_MAX_FALLBACKS` (default 2, i.e. up to 3 total attempts in
F-006) bounds attempt count independent of provider list length. `fallback_order`
comes solely from the tenant `tenant_routing_policy` row (or the §4.2 default).
There is no per-attempt timeout multiplication that could exceed the overall
budget: each attempt's `overall_timeout` is `min(remaining_budget,
per_attempt_cap)`.

**Streaming caveat (inherited from ADR-0006).** Fallback can only occur **before
the first byte** of a stream is yielded. Once 200 SSE headers are committed, a
mid-stream provider failure follows the existing rule: emit one
`event: error` frame (`internal_error`), close WITHOUT `[DONE]` — no retry, no
status change. The router therefore performs all fallback decisions for streaming
requests during connection establishment, before `_handle_stream` yields.

---

## 7. Decision: Cost-Routing Primitives (client-side cost estimate)

### 7.1 Hard-coded per-provider+model cost table (F-006 scope)

F-006 ships a **hard-coded** `COST_TABLE: dict[(provider, model_prefix), (in_cents_per_1k, out_cents_per_1k)]`
in `src/gateway/router/cost.py` (gateway-core). It is explicitly a **client-side
cost estimate**, never an authoritative bill (CLAUDE.md honest-language rule). It
replaces the placeholder rates currently in `audit.py:63-64` for routed requests;
gateway-core SHOULD have the usage event's cost reflect the resolved provider+model
rate (see §7.4). Unknown (provider, model) → fall back to a documented conservative
default rate AND emit nothing special (estimate is best-effort).

### 7.2 Pre-request estimate

Before dispatch, estimate cost from `max_tokens` (the only token signal available
pre-flight): `estimate = prompt_tokens_estimate * in_rate + max_tokens * out_rate`,
where `prompt_tokens_estimate` is a cheap word-count proxy of the messages (the
gateway already uses word-count proxies for stream token accounting,
chat_completions.py:552/598). If `cost_ceiling_cents` is set and `estimate >
ceiling` for the candidate provider+model, that candidate is a **cost block**
(TERMINAL + audit, §6) — the router does NOT silently downgrade to a cheaper model
or provider.

### 7.3 Per-attempt recalculation on the resolved provider+model

Cost is **recalculated for the actually-resolved provider+model on every attempt**
(threat #4). Fallback to a different provider re-evaluates the ceiling against that
provider's rates; a fallback that would breach the ceiling is itself a cost block,
not a silent overspend.

### 7.4 Stream-time enforcement at chunk boundaries

For streaming, the router/handler accumulates an output-token proxy at **chunk
boundaries** (reusing the existing per-chunk accounting in `_handle_stream`,
chat_completions.py:543-554) and recomputes the running cost estimate against
`cost_ceiling_cents`. On breach mid-stream: stop content, emit one
`event: error` frame (`policy_blocked`), close WITHOUT `[DONE]` — identical fail-safe
shape to the F-005 streaming block (ADR-0007 §7). This is a **TERMINAL + audit**
(`routing_decision` `cost_blocked`), no silent downgrade.

### 7.5 How the `usage`/cost event reflects multi-attempt routing

Exactly **one** `usage` event is emitted per request (the existing terminal-audit
contract is unchanged). On a successful route, `usage.model` and
`usage.cost_estimate_cents` reflect the **final successful provider+model** and its
token counts; failed prior attempts do not produce separate `usage` events (they
produce `routing_decision` `fallback_attempted` events for observability). On a
fully-failed request, the existing rejection-audit path emits a `usage` event with
`tokens_in/out = 0` (as today). The cost figure remains a client-side estimate.

**Alternative considered:** emit a `usage` event per attempt. **Rejected** — it
would double-count tokens/cost for Delta and break the one-request-one-usage join
assumption Delta relies on. Per-attempt visibility lives in `routing_decision`.

---

## 8. Threat Model — 12 Vectors (CANONICAL; cite these numbers)

All later gates (esp. security-auditor) cite vector numbers **#1–#12**.

| # | Vector | Attack | Control | Enforced where |
|---|---|---|---|---|
| 1 | **Provider-credential isolation / no key logging** | Provider API keys / AWS secrets leak via logs, errors, or events | Each provider key is read only by its own adapter/client; keys never placed in events (`routing_decision` carries no key), errors, or log fields; a structlog processor drops any key matching `*_API_KEY` / `*_SECRET_*` / `AWS_*` ; per-provider env scoping (§10) | adapters + `_lifespan` client construction + structlog filter (gateway-core); honest-language + secrets rules (CLAUDE.md #4) |
| 2 | **Allow-list deny never silent-fallbacks** | A tenant-forbidden provider is reached via fallback | Allow-list deny is TERMINAL: `policy_blocked` (403) + `routing_decision` `allowlist_denied`; fallback only ever iterates the *allowed* set | router fallback loop (§6) + `RoutingPolicyRepository` (§4) |
| 3 | **Cost enforced pre-request AND at stream chunk boundaries** | Over-budget spend slips through streaming or large `max_tokens` | Pre-request estimate vs `cost_ceiling_cents` (§7.2) AND running estimate at chunk boundaries (§7.4); breach = TERMINAL + audit, no silent downgrade | `cost.py` + handler/`_handle_stream` (gateway-core) |
| 4 | **Per-attempt cost recalculation on resolved provider+model** | Cost computed once against the cheap provider, then fallback routes to an expensive one | Recompute estimate for the actual resolved (provider, model) on EVERY attempt (§7.3) | router attempt loop (§7.3) |
| 5 | **Auth-failure (401/403) terminal — never retried** | Misconfigured key triggers provider-shopping / budget burn / config disclosure | `auth` kind is TERMINAL; never retried; collapses to 500 with generic message | fallback matrix (§6) |
| 6 | **Provider content-policy 4xx terminal — never retried** | Client/route shops a safety refusal across providers | `content_policy` kind is TERMINAL; never retried | fallback matrix (§6) |
| 7 | **Bedrock SigV4 region pinned per config** | Region/endpoint manipulation (e.g. client-chosen region) to a rogue or cheaper-but-unauthorized endpoint | `AWS_REGION` is config-pinned; Bedrock base_url derived from it; SigV4 service/region fixed; never client-influenced | Bedrock adapter + §3 + §11 |
| 8 | **Outbound secret/PII detection sees TRANSLATED bytes** | A provider's native shape evades the F-005 outbound inspectors | Anthropic/Bedrock → OpenAI translation happens BEFORE the non-stream `json.dumps(model_dump())` inspection and BEFORE the streaming 8 KiB window; adapters return real OpenAI-shape objects/SSE | adapters (§2.4/§2.5) + existing F-005 hooks (chat_completions.py:357, :510) — F-005 invariant preserved |
| 9 | **Provider base-URL SSRF / pinning** | Request body or header redirects the gateway to attacker-controlled host | Base URLs config-pinned per provider; `follow_redirects=False`; no per-request base_url; request field-allowlist forbids URL-bearing fields | §3 transport + `_build_upstream_request` allow-list discipline |
| 10 | **Error-envelope minimalism (no upstream body/text leak)** | Provider error bodies (which may carry prompt echoes, internal detail) reach the client | All provider failures collapse to `ERROR_TABLE` codes with fixed messages; provider body/text NEVER returned and NEVER logged (only status + request_id) | `ProviderError` mapping (§2.2) + matrix (§6) + `exceptions.py` |
| 11 | **Cross-tenant routing-policy isolation (RLS)** | Tenant A reads/uses Tenant B's routing policy or cost ceiling | `tenant_routing_policy` under the 0006 RLS pattern (ENABLE+FORCE, NULLIF predicate) + repo `WHERE tenant_id = caller_tenant_id` defense-in-depth | migration 0007 RLS (§4.3) + `RoutingPolicyRepository` |
| 12 | **Request field-allowlist preserved through translation** | Translation smuggles an undeclared/dangerous field to a provider | Adapters map ONLY the allow-listed `CreateChatCompletionRequest` fields (§2.4/§2.5); no raw passthrough, mirroring `_build_upstream_request`; unknown client keys already rejected by the closed request schema | adapters + closed request model (`models.py`) |

---

## 9. Decision: Streaming Memory Bounds

- The existing **8 KiB sliding-window invariant** (`stream_inspect_buffer_bytes`,
  default 8192, chat_completions.py:510) is **preserved unchanged**. Because each
  adapter emits already-translated **OpenAI-shape SSE lines**, the window in
  `_handle_stream` operates on the same bytes it does today; `_extract_chunk_content`
  (L683–699) parses `choices[].delta.content` from those lines unchanged. The full
  response is never buffered.
- **Per-provider translation buffering is bounded.** Anthropic and Bedrock stream
  *deltas*; the adapter translates one upstream event → one OpenAI chunk line and
  yields immediately. The adapter holds **at most one upstream event plus one
  in-flight OpenAI chunk** — O(1) in the number of chunks, bounded by the largest
  single delta (capped by provider chunking, not accumulated). Adapters MUST NOT
  accumulate the full message to translate; translation is strictly incremental.
- Net effect: total streaming memory = O(8 KiB window) + O(1 largest delta), the
  same order as the OpenAI path today.

---

## 10. Decision: Config (extend `GatewaySettings` — single fail-loud surface)

Extend `GatewaySettings` (`src/gateway/config.py`). Provider keys are **secrets**
(never logged; the existing module docstring's "NEVER log" list is extended to
include the new secret fields).

| Field | Type | Required / default | Notes |
|---|---|---|---|
| `anthropic_api_key` | `str \| None` | default `None` | secret; if None, Anthropic is not initialised → not allowed for any tenant (fail-closed) |
| `anthropic_base_url` | `str` | default `https://api.anthropic.com` | config-pinned |
| `aws_region` | `str \| None` | default `None` | required to enable Bedrock; pins SigV4 region + base_url |
| `aws_access_key_id` | `str \| None` | default `None` | secret; if None, Bedrock disabled |
| `aws_secret_access_key` | `str \| None` | default `None` | secret; if None, Bedrock disabled |
| `router_max_fallbacks` | `int` | default `2` | total attempts = 1 + this; validator `>= 0`, `<= 8` |
| `router_default_providers` | `list[str]` | default `["openai","anthropic","bedrock"]` | the §4.2 default allow-list (intersected with configured providers) |
| `router_anthropic_default_max_tokens` | `int` | default `1024` | injected when client omits `max_tokens` for Anthropic (which requires it); `<= max_tokens_per_request` |

**Fail-loud posture:** consistent with ADR-0006 Decision 9, the OpenAI path stays
**required** (`upstream_base_url`). Anthropic and Bedrock are **opt-in**: missing
their keys does not crash startup; it simply makes those providers unavailable
(and a tenant policy that lists them still cannot route to them — fail-closed, not
fail-open). This avoids forcing every deployment to hold all three providers'
credentials while keeping the single fail-loud surface for anything that IS
configured (e.g. `aws_region` set but `aws_secret_access_key` missing → startup
validation error, since a half-configured provider is a misconfiguration).

**Alternative considered:** make all provider keys required. **Rejected** — would
break existing single-provider deployments and the F-004 test matrix, and forces
secret sprawl. Opt-in-but-fail-closed is the safer default.

---

## 11. Decision: SigV4 Library Choice

**Decision: `aioboto3`** (async wrapper over boto3/botocore) for the Bedrock
adapter, using `session.client("bedrock-runtime", region_name=AWS_REGION)` with
`converse` / `converse_stream`.

**Rationale:**
- botocore owns the canonical SigV4 implementation and the Bedrock model — using
  it eliminates a class of hand-rolled-signing bugs (vector #7) and tracks AWS API
  changes (Converse is a first-class botocore operation).
- `aioboto3` keeps the call path async, consistent with the gateway's
  `httpx.AsyncClient` model; credentials and **region are pinned from config**
  (`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), never client-derived.
- Converse / ConverseStream give a provider-uniform request/response shape, which
  simplifies the §2.5 translation and reduces model-specific branching.

**Alternative considered:** `aiohttp` + `aws-requests-auth` (or hand-rolled SigV4
over `httpx`). **Rejected** — re-implements signing and Bedrock request shaping by
hand; more surface for SigV4 defects and drift from AWS API changes. The marginal
dependency-weight saving is not worth the security risk on a security product.

> Transport note: this is the one place the gateway uses a non-`httpx` client.
> The Bedrock adapter still honors the same timeout budget (§6) via botocore
> config (`connect_timeout`/`read_timeout` set from `request_timeout_seconds` /
> `stream_timeout_seconds`) and never follows redirects. gateway-core MUST add
> `aioboto3` to `infra`/dependency manifests.

---

## 12. Honest Deferrals

- **Dynamic / live pricing** and **custom provider plugins** → **F-008**. F-006
  ships a hard-coded `COST_TABLE` (client-side estimate only).
- **Regional failover** (multi-region Bedrock, cross-region retry) → **F-010**.
  F-006 pins ONE `AWS_REGION`.
- **Fine-tune / custom model-name mapping** (mapping arbitrary client model names
  to provider-specific fine-tuned `modelId`s) → **F-011**. F-006 uses a static
  model-map for the well-known base models per provider.
- **Crypto-verification of routing-policy signatures.** `tenant_routing_policy`
  is Sentinel-local operational config and is **not** signed in F-006 (unlike
  Delta `policies`, whose signature verification is F-008). If a future
  requirement demands signed routing policy, that verification follows the F-008
  pattern; noted here so the absence is deliberate, not an oversight.
- **OpenAI-proxy status classification.** `openai_proxy.py` currently collapses
  all non-200 to `internal_error`; F-006's OpenAI adapter adds a thin status
  classifier at the adapter boundary (it already has `resp.status_code`) WITHOUT
  changing `openai_proxy.py`'s public behavior for the existing direct call path.

---

## 13. Contract Change — `contracts/events.schema.json`

This ADR adds ONE event variant, `routing_decision`. **api-architect owns this
edit.** The exact, ready-to-apply patch is below. (In this run the contract write
was blocked by the path-protection hook because the agent-identity env var
`ANORYX_ACTIVE_AGENT=api-architect` was not provisioned into the agent process by
the conductor — see §14. The patch is recorded verbatim so it applies cleanly the
moment the identity is provisioned; it is the ONLY change to `contracts/`.)

**Patch 1 — add to `oneOf` (after `ShadowAiDetectedEvent`):**

```json
    { "$ref": "#/$defs/ShadowAiDetectedEvent" },
    { "$ref": "#/$defs/RoutingDecisionEvent" }
```

**Patch 2 — append a new `$defs` variant (after `ShadowAiDetectedEvent`'s `$defs`
entry, before the closing braces):**

```json
    ,
    "RoutingDecisionEvent": {
      "type": "object",
      "additionalProperties": false,
      "description": "Emitted by the multi-provider model router (F-006, ADR-0008) when it makes a routing decision: provider selection, allow-list denial, cost-ceiling block, a fallback attempt, or chain exhaustion. NOT a Delta policy violation (that is policy_violated, reserved per ADR-0007). agent_id is the emitting component slug 'gateway-core' (the router runs inside the gateway), NEVER a provider or model name; the provider is carried in selected_provider. No provider credential, API key, or upstream body text is EVER carried on this event.",
      "required": [
        "event_type",
        "tenant_id",
        "team_id",
        "project_id",
        "agent_id",
        "event_id",
        "event_timestamp",
        "request_id",
        "routing_reason",
        "selected_provider",
        "outcome",
        "action_taken"
      ],
      "properties": {
        "event_type": { "const": "routing_decision" },
        "tenant_id": { "$ref": "#/$defs/tenant_id" },
        "team_id": { "$ref": "#/$defs/team_id" },
        "project_id": { "$ref": "#/$defs/project_id" },
        "agent_id": { "$ref": "#/$defs/agent_id" },
        "event_id": { "$ref": "#/$defs/event_id" },
        "event_timestamp": { "$ref": "#/$defs/event_timestamp" },
        "request_id": { "$ref": "#/$defs/request_id" },
        "routing_reason": {
          "type": "string",
          "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$",
          "maxLength": 64,
          "description": "Lowercase slug for why this decision was made (e.g. 'tenant-allowlist', 'cost-routing', 'fallback-transient', 'fallback-rate-limit'). Charset restricted to a slug to forbid control characters and whitespace (log-injection defense)."
        },
        "selected_provider": {
          "type": "string",
          "enum": ["openai", "anthropic", "bedrock"],
          "description": "The upstream provider chosen for THIS routing decision. Never a model name; never a credential."
        },
        "outcome": {
          "type": "string",
          "enum": ["selected", "allowlist_denied", "cost_blocked", "fallback_attempted", "exhausted"],
          "description": "The routing outcome for this decision."
        },
        "attempt_index": {
          "type": "integer",
          "minimum": 0,
          "maximum": 16,
          "description": "Zero-based index of this attempt in the fallback chain (0 = primary). Bounded to 16 to cap inspection cost (DoS-via-inspection defense)."
        },
        "requested_model": {
          "type": "string",
          "maxLength": 256,
          "description": "The model the client requested (echo for correlation). Never a secret."
        },
        "action_taken": {
          "type": "string",
          "enum": ["routed", "blocked", "failed_over"],
          "description": "Disposition the router applied: 'routed' (served by selected_provider), 'blocked' (allow-list/cost terminal), 'failed_over' (retryable failure, advancing the fallback chain)."
        }
      }
    }
```

**Discriminator note:** the existing non-normative `discriminator: event_type`
hint already covers the new const (`routing_decision`) with no change needed;
dispatch remains normative via `oneOf` + the unique `event_type` const under
Draft 2020-12.

**Diff summary (one line):** add `RoutingDecisionEvent` to the top-level `oneOf`
and a closed, fully-bounded `$defs/RoutingDecisionEvent` variant (4 stable IDs +
event_id/event_timestamp/request_id + `routing_reason` slug + `selected_provider`
enum `{openai,anthropic,bedrock}` + `outcome` enum + bounded `attempt_index` +
bounded `requested_model` + `action_taken` enum `{routed,blocked,failed_over}`);
no existing field changed, so no deprecation/sunset is required.

---

## 14. Consequences

### 14.1 Positive

- Clients keep the unchanged OpenAI surface and base URL (ADR-0002 honored); the
  router is internal.
- F-005 inspection, audit, RLS, and the contract status set are all preserved
  because every adapter returns OpenAI-shape bytes before inspection.
- Security boundaries are explicit and testable: the §6 matrix and §8 vectors are
  canonical reference points for security-auditor.
- Routing observability does not pollute Delta semantics (`routing_decision`
  separate from `policy_violated`).

### 14.2 Negative / costs

- New dependency (`aioboto3`) and three live provider integrations widen the
  attack surface — mitigated by the §8 controls.
- gateway-core must touch the audit-log model, repository, and migration 0007 in
  several coordinated places (§5.5/§5.6) for the new event to be persistable and
  tamper-evident; this is enumerated to avoid a half-wired variant.
- Translation fidelity (Anthropic/Bedrock → OpenAI) is a maintenance burden as
  provider APIs evolve (deferred dynamic handling to F-008/F-011).

### 14.3 Explicit handoffs to gateway-core (STEP 5)

1. `src/gateway/router/` — adapter protocol + OpenAI/Anthropic/Bedrock adapters +
   fallback loop + `cost.py` (`COST_TABLE`, estimators).
2. `src/gateway/router/` integration at the chat_completions.py seam (L305→L309),
   **without** changing the route-handler signature, middleware, or endpoints.
3. Per-provider `httpx.AsyncClient`s + Bedrock `aioboto3` session in `_lifespan`
   (+ teardown); extend the "NEVER log" secret list in `config.py`.
4. `GatewaySettings` fields (§10) + validators.
5. `tenant_routing_policy` table + `RoutingPolicyRepository` (§4); **migration
   0007**: create table, RLS (ENABLE+FORCE+NULLIF policy), `GRANT SELECT,INSERT,
   UPDATE TO sentinel_app`, new audit columns, ALTER `ck_eal_event_type` and
   `ck_eal_action_taken`.
6. Event-type wiring sites **(2)–(4)** in §5.5 + audit-column wiring §5.6.
7. structlog secret-dropping processor for `*_API_KEY` / `*_SECRET_*` / `AWS_*`
   (vector #1).
8. Tests (router unit, translation golden tests, fallback matrix, cost ceilings,
   RLS isolation) — gateway-core's STEP-5 responsibility, not this ADR's.

### 14.4 Process note (this run)

The contract edit to `contracts/events.schema.json` (§13) is authored and ready
but was **blocked at apply-time** by `.claude/hooks/protect-paths-and-secrets.sh`:
the hook authorizes contract edits only when the agent identity is `api-architect`,
which it reads from the `ANORYX_ACTIVE_AGENT` environment variable supplied by the
conductor ("Agent identity comes from the conductor via env"). In this run that
variable was not set, so the hook saw the raw harness agent id and blocked. The
remediation is environment provisioning only — export
`ANORYX_ACTIVE_AGENT=api-architect` into the api-architect agent's process (or run
this task under that identity) and re-apply §13 verbatim. The protection logic was
NOT modified or weakened, and no write to `.claude/` was made.
