# ADR-0023 — Integration Suite (Slack / Jira / Splunk outbound webhooks — metadata-only, SSRF-guarded, best-effort egress)

- **Status:** Approved
- **Feature:** F-020
- **Date:** 2026-06-24
- **Builds on:** ADR-0010 (F-007 — the "egress must never break user traffic" precedent), ADR-0017 (F-014 — `secret_box` credential encryption), ADR-0018 (F-015 — Redis Streams consumer-group worker pattern + DLQ/retry/checkpoint), F-005 (orchestration emission seam), F-009 (shared Redis pool), ADR-0001 (F-003 hash-chained audit)

---

## 1. Context

Every feature before F-020 kept data **inside** the org boundary. F-020 is the **first feature that deliberately sends data OUT** of Sentinel, to tenant-controlled third parties (Slack, Jira, Splunk). That collides head-on with the product's killer differentiator — *"data never leaves the organization."* So the load-bearing decisions (what may leave, how an outbound URL is trusted, how delivery is isolated from the request path) are settled **here, before any dispatch code**.

Three codebase facts constrain the design:

1. **No arbitrary-URL egress exists today.** Every provider call is config-pinned with `follow_redirects=False` (SSRF defense, threat #9 — `src/gateway/router/registry.py:11`, `src/gateway/config.py:70`); bulk storage binds to ONE endpoint ("SSRF surface structurally removed" — `src/bulk/storage/base.py:7`). F-020 introduces the **first** tenant-supplied outbound URL, so its SSRF guard is **net-new** and is the control the whole feature is judged on.
2. **F-007's "egress monitor" is an inbound *classifier*, not a dispatcher** (`src/gateway/middleware/egress_monitor.py:59-84`) — an httpx `request` event-hook that detects Sentinel's own calls to unexpected providers and emits a detect-only event, *never* raising into the call. It cannot be reused to *send*, but it is the binding precedent: **an egress mechanism must never break user traffic** (Fork E).
3. **Event records are already metadata-only, closed, and bounded** — `additionalProperties:false`, `maxLength`/`maximum`, carrying the four stable IDs + verdict + severity + sanitized endpoints, and **never** raw prompt/response or plaintext PII (non-negotiable #6; `contracts/events.schema.json:1-60`). So a webhook that forwards an event record leaks zero payload **by construction** (Fork A).

F-020 reuses the F-015 async-worker machinery, the F-014 credential vault, and the F-005/F-009 event/Redis seams; it adds an **SSRF URL guard**, three **provider adapters**, a per-tenant **config + delivery ledger**, an outbound **HMAC signer**, and three **audit event variants**. **It extends existing seams; it does not fork a parallel egress engine (R5).**

---

## 2. Fork decisions (STEP 0 — approved by Affu)

| # | Fork | Decision | Why |
|---|---|---|---|
| D1 | **What data may leave** (Fork A) | **Metadata-only — the v1 default AND the only allowed mode.** The webhook body is the existing `events.schema.json` record (type, severity, four IDs, verdict/action_taken, policy/rule name, sanitized endpoint). NO payload, NO PII. | The sensitive content was never in the event envelope, so there is **no leak path to misconfigure** — v1 is *structurally incapable* of egressing payload/PII, not merely configured against it. Content-egress is a **separate future feature** with its own loud per-tenant opt-in, its own audit, and explicit buyer-facing disclosure that it relaxes the core promise. |
| D2 | **SSRF posture** (Fork B) | **Hybrid: provider-templated hosts for Slack/Jira; strict URL guard for Splunk + any custom host.** | Slack (`hooks.slack.com`) and Jira (`*.atlassian.net`) have known host shapes → host-pattern allowlist, near-zero surface. Splunk HEC is necessarily a tenant-supplied (often self-hosted) host → it MUST pass the strict guard. The guard is the single most important control in F-020 (§7). |
| D3 | **Delivery model** (Fork C) | **Async outbound worker — reuse the F-015 Redis Streams consumer-group pattern.** New `webhook-dispatcher` worker (separate process, like `bulk-worker`) on a dedicated delivery stream off the F-009 pool; bounded retry + backoff + DLQ + per-delivery audit. **Never** in the request path. | The machinery already exists (`bulk/worker.py`, `bulk/queue.py`): at-least-once, per-consumer pending/reclaim, DLQ via XADD, checkpoint, KEDA-scalable. Reuse, do not reinvent. |
| D4 | **Credentials** (Fork D) | **Reuse F-014 `secret_box` (AES-256-GCM) at rest + HMAC-SHA256-sign outbound generic/Splunk deliveries.** The signature timestamp is **part of the signed payload**, not just a header. Slack/Jira use their **native auth** (Slack webhook URL / signing secret, Jira token) — not double-wrapped. | No new crypto primitive (reuse the audited `secret_box` path — `src/admin/sso/secret_box.py:127-154`). Signing the timestamp inside the body gives the receiver authenticity **and** replay rejection that a strip-able header cannot. Per-tenant key derivation deferred — `secret_box` is already global-key + tenant-row-scoped at rest. |
| D5 | **Failure posture** (Fork E) | **Best-effort, fail-OPEN. A delivery failure NEVER touches the user's request path.** Failures are bounded-retried, then DLQ'd; every terminal failure is audited. | Delivery is **downstream notification, not an inspection gate**, so the fail-CLOSED non-negotiable #5 does not apply — see §4.1 (scoped exception, same reasoning as F-007 §1 and F-016 WARN-on-scanner-failure). |
| D6 | **Scope** (Fork F) | **All three providers — Slack + Jira + Splunk — outbound-only, narrow.** Slack channel post (HIGH/CRITICAL); Jira create-issue (policy violations, basic fields); Splunk HEC event forward. | Roadmap names all three (`anoryx-ecosystem-roadmap-v2.md:313`). Bidirectional/workflow/extra-provider scope deferred (§8). |
| D7 | **policy_type** | **NONE.** Webhook config is **per-tenant configuration, not a request-path security policy** — it never allows/denies/gates traffic. It lives in its own `webhook_config` table, NOT in `_VALID_POLICY_TYPES`. | This sidesteps the F-016 CRIT-2 trap entirely (CRIT-2 = a policy_type that validates but never enforces). See §5.1. A future "delivery policy" gating *which* events may leave WOULD be a real policy_type needing the 5-site registration — out of scope for v1. |
| D8 | **Audit events** | **THREE new variants** via the 4-site + hash rule, migration head → 0030: `webhook_delivered`, `webhook_delivery_failed`, `webhook_config_updated`. | F-020's own actions are auditable. See §5.4. |

---

## 3. What is reused vs what F-020 adds (anti-rebuild, R5)

| Concern | REUSE (do not fork) | F-020 (this feature) |
|---|---|---|
| Delivery runtime | F-015 Redis Streams consumer-group worker + DLQ/retry/checkpoint (`bulk/worker.py`, `bulk/queue.py`); F-009 pool (`gateway/redis_client.get_client`) | `webhook-dispatcher` worker + a dedicated delivery stream |
| Outbound payload | `events.schema.json` records — already metadata-only, closed, bounded | per-provider **adapters** that map an event record → Slack/Jira/Splunk request body (no new fields invented) |
| Credentials at rest | F-014 `secret_box.encrypt/decrypt` (AES-256-GCM, `SENTINEL_IDP_SECRET_KEY`) | `webhook_config.credential` (bytea, encrypted blob) + an HMAC signing secret |
| Egress discipline | F-007 "monitor never raises into the call" (ADR-0010 §1) | the same isolation applied to delivery failures (D5/§4.1) |
| Config admin surface | F-012a admin auth (`require_admin`, `emit_admin_event`, `actor_id` — `src/admin/auth.py`, `src/admin/util.py:46`) | tenant-admin endpoints to CRUD webhook config |
| Net-new | — | **SSRF URL guard** (§7), HMAC signer, `webhook_config` + `webhook_delivery` tables, 3 audit event variants |

---

## 4. Honesty boundary (mandatory)

- **"Sentinel forwards security-event metadata,"** not "exports your AI data." v1 is structurally incapable of egressing prompt/response payload or PII (D1).
- **"SSRF-guarded egress,"** not "immune to SSRF." The guard blocks private/reserved ranges and resolve-and-pins to defeat DNS-rebind; it reduces, not eliminates, the risk class inherent in letting a tenant name an outbound host (D2).
- **"best-effort, out-of-band delivery,"** not "guaranteed delivery." Delivery can fail; failures are retried, DLQ'd, and audited, but never block the request (D5).
- **Outbound-only, v1.** No inbound/bidirectional, no Slack/Jira workflow callbacks (§8).

### 4.1 Scoped exception to non-negotiable #5 (must be explicit)

Non-negotiable #5 — *"on ANY inspection or policy error → BLOCK, never silently pass"* — governs the **inspection/security path**. Webhook delivery is **downstream notification**, not an inspection gate: a failed Slack post does not make a request less safe. So delivery fails **OPEN** (best-effort), exactly as F-007's monitor never breaks traffic and F-016 WARNs on scanner failure. This is documented here so the fail-open path is never mistaken for a #5 violation in review.

---

## 5. Design

### 5.1 No policy_type — CRIT-2 is N/A by design, but the 4-site event rule applies

F-020 introduces **no** `policy_type`, so the F-016 CRIT-2 five-site countermeasure does not apply — `_VALID_POLICY_TYPES` and the two policy CHECK constraints are **untouched**. The equivalent "register everywhere or it is inert" discipline for F-020 is the **4-site event rule** for its audit variants (§5.4): a new `event_type` that the DB CHECK rejects is a silent persistence failure of exactly the CRIT-2 class. That rule is therefore mandatory and is gated by a non-stubbed persistence test (vector 12).

### 5.2 Persistence (RLS-scoped, migrations 0028–0030; head 0030)

- **`webhook_config`** (migration **0028**, `down_revision="0027"`) — `tenant_id`, optional scope (`team_id`/`project_id`), `provider` (`slack`|`jira`|`splunk`), `target_url` (validated at write *and* re-validated at send), `credential` (bytea, `secret_box`-encrypted), `signing_secret` (bytea, encrypted), `min_severity` (`high`|`critical` threshold), `enabled`, `created_at`/`updated_at`. **Tenant-scoped RLS** (mirror an existing tenant table). Plaintext credential/URL secret **never** stored.
- **`webhook_delivery`** (migration **0029**, `down_revision="0028"`) — the delivery ledger: `(event_id, config_id)` unique key for **at-least-once dedup**, `status` (`pending`|`delivered`|`failed`|`dead_lettered`), `attempts`, `last_http_status_class` (bounded class, **never** response body), `created_at`/`updated_at`. Terminal status is the worker's checkpoint (mirrors `batch_files`, F-015 R5).
- **Event-type widen** (migration **0030**, `down_revision="0029"`, **head=0030**) — drop+recreate `ck_eal_event_type` with the three new variants; add the action-taken values (`delivered`/`failed`) to `ck_eal_action_taken` if absent; add the minimal nullable signal columns (`webhook_provider VARCHAR(16)`, `delivery_attempts SMALLINT`) — bounded, **no URL/body/PII**. Reversible (mirror `0024_shadow_ai_candidate_variant.py`).

### 5.3 Dispatch path (async, isolated)

1. F-005 emission seam already appends every event to the hash-chained audit log and the Redis Streams bus. The dispatcher **consumes** the bus (a new consumer group), filters by `webhook_config` (tenant + scope + `min_severity` + `enabled`), and **enqueues one delivery job per (event, matching config)** onto the delivery stream — never inline in the request path.
2. The `webhook-dispatcher` worker dequeues, **dedups** against `webhook_delivery` terminal status (at-least-once → effectively-once), builds the provider body via the adapter, and POSTs through the **guarded HTTP client** (§7).
3. Outcome → `webhook_delivery` status + `webhook_delivered`/`webhook_delivery_failed` event. Bounded retry with exponential backoff; on retry-exhaustion → DLQ (XADD) + `dead_lettered` + audited (F-015 R6/R7 pattern).
4. **Any** guard rejection, build error, or transport failure is caught, audited, and dropped — it never propagates to the request path (D5/§4.1).

### 5.4 Events & attribution (4-site + hash rule)

Three variants. **4 sites** each: (1) `VALID_EVENT_TYPES` / `ACTION_TAKEN_BY_EVENT_TYPE` in `src/persistence/models/events_audit_log.py`; (2) `ck_eal_event_type` widen — migration **0030**; (3) new `$def` + `oneOf` entry in `contracts/events.schema.json` (**api-architect only**); (4) emit primitive + tests.

- `webhook_delivered` / `webhook_delivery_failed` — emitted by the worker; carry the four stable IDs of the **source event**, `webhook_provider`, `action_taken` (`delivered`/`failed`), `delivery_attempts`. **No target URL, no response body** (bounded status class only).
- `webhook_config_updated` — emitted by the F-012a admin surface on config CRUD via `emit_admin_event(actor_id=actor_id(request), target_tenant_id=...)`; attributed to the admin principal + target tenant, never nil-UUID, never the tenant's own id (R6).

Hash-chained via `audit_log_repository` append on the privileged session, following the F-014 **opt-in `actor_id`-iff-nonNull** hash rule (`hash_chain.py`). **No new audit columns beyond the two bounded signal columns** in 5.2; the `webhook_provider` column is added to `CANONICAL_FIELDS` so it is folded into the tamper-evident row hash.

### 5.5 Credentials & signing (D4)

`secret_box.encrypt` seals each credential and the per-config `signing_secret` at write; `decrypt` is called **only** in the worker at send time. Generic/Splunk deliveries are signed `HMAC-SHA256(signing_secret, f"{timestamp}.{body}")`; the request carries `X-Sentinel-Timestamp` **and** the same timestamp is the first signed element, so a replay cannot strip it. Receivers reject a timestamp outside the tolerance window. **`WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 300`** (5 minutes — the Slack/Stripe convention), documented and config-surfaced. Slack/Jira are NOT HMAC-wrapped (native auth).

---

## 6. Adversarial threat model (≥12 vectors, empirical)

| # | Vector | Test |
|---|---|---|
| 1 | config URL → cloud metadata `169.254.169.254` (link-local) | test_ssrf_link_local_blocked |
| 2 | config URL → loopback/private (`127.0.0.1`, `10/8`, `172.16/12`, `192.168/16`) | test_ssrf_private_ranges_blocked |
| 3 | DNS-rebind: host resolves public at validate, private at connect | test_dns_rebind_pinned (resolve-and-pin) |
| 4 | redirect (`302 → http://169.254…`) | test_redirect_to_internal_blocked (follow_redirects=False) |
| 5 | non-TLS `http://` webhook | test_https_only_enforced |
| 6 | non-allowlisted port (`:22`, `:25`) | test_port_allowlist_enforced |
| 7 | IPv6 ULA / IPv4-mapped (`::ffff:127.0.0.1`, `fc00::/7`) | test_ipv6_mapped_and_ula_blocked |
| 8 | delivery failure must not affect request path | test_delivery_failure_does_not_touch_request (fail-open) |
| 9 | credential at rest is ciphertext (no plaintext token/URL secret in DB) | test_webhook_secret_encrypted_at_rest |
| 10 | outbound HMAC valid + timestamp **inside** signed payload | test_hmac_signs_timestamp_in_body |
| 11 | replay outside tolerance window rejected by signature contract | test_replay_outside_window_detectable |
| 12 | **full real path, NON-STUBBED**: real event → dispatcher → guarded POST to test sink → `delivered` + audited; forced failure → retry → DLQ + audited | test_e2e_nonstubbed_delivery |
| 13 | body ⊆ event-envelope fields — NO prompt/response/PII egresses | test_no_payload_egress |
| 14 | at-least-once redelivery not double-posted | test_delivery_idempotent (dedup on `webhook_delivery`) |
| 15 | tenant A config/credentials never used for tenant B events | test_webhook_config_tenant_scoped (RLS) |
| 16 | webhook config CRUD is admin-only; no data-plane/virtual-key path | test_only_admin_can_configure_webhook |

---

## 7. Five hardening points (applied to the SSRF guard — the load-bearing control)

1. **Deny-by-default IP classification.** Resolve the host, then block every private/reserved/loopback/link-local/ULA/IPv4-mapped-IPv6 range; allow **only** publicly-routable addresses (vectors 1,2,7).
2. **Resolve-and-pin.** Resolve once, validate the resolved IP is public, then connect to the **pinned** IP — closing the TOCTOU/DNS-rebind window between validation and connect (vector 3).
3. **No redirects, TLS-only, port allowlist.** `follow_redirects=False` (reuse the registry pattern — redirect-to-internal is the classic bypass), `https://` only, ports restricted to 443 + Splunk HEC 8088 (vectors 4,5,6).
4. **Provider-templated hosts for Slack/Jira.** Known host patterns shrink the arbitrary-URL surface to the one provider (Splunk/custom) that genuinely needs it (D2).
5. **Fail-open isolation.** A guard rejection or any delivery error is audited and dropped — it never raises into, blocks, or slows the request path (vectors 8; D5/§4.1).

The guard is its **own** reviewed + tested module (`src/orchestration/webhooks/url_guard.py` or equivalent), independently exercised by vectors 1–7 — not inlined into the dispatcher.

---

## 8. Deferred scope (explicit)

Bidirectional / inbound (no acks, no Slack/Jira callbacks); Jira workflow transitions / custom-field mapping (create-issue only); Splunk beyond HEC; additional providers (Teams / PagerDuty / generic-webhook-builder UI); per-event message-templating language; in-UI retry-policy editor; **content-egress (D1 option 2)**; per-tenant key derivation. No new `policy_type`. No `/v1` auth change.

---

## 9. Rollback

Each migration is reversible. `alembic downgrade 0027` removes the event-type/action widening + signal columns (0030), the `webhook_delivery` ledger (0029), and the `webhook_config` table (0028), in order. With no `webhook_config` rows present the dispatcher matches nothing and emits nothing; reverting the code (dispatcher worker + adapters + url_guard + admin routes + 3 variants) restores exactly pre-F-020 behaviour, with no residual egress and no change to the request path.
