# ADR-0026 — Cross-Product Safety-Event Visibility: Rendly -> Orchestrator Oversight Log (X-004)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0008 (R-008 — the real self-hosted PII/injection/secret inspection + the
``inspection_audit_log`` administrative-oversight trail; Fork A2, "no calls to Sentinel's
detectors," is UNCHANGED by this ADR), Anoryx-Sentinel ADR-0023 (F-020 Fork E / D5 — "a delivery
failure NEVER touches the user's request path," the fail-open precedent this ADR replicates in
spirit), ``Anoryx-AI-Orchestrator/contracts/openapi.yaml`` (the X-004 ``safety`` tag /
``POST /v1/safety/events`` / ``SafetyEventIngestRequest`` / ``safetySourceBearer`` — the
api-architect-owned wire contract this ADR conforms to, never edits).

## Context

`anoryx-ecosystem-roadmap-v3.md`'s X-004 gives the Orchestrator a cross-product safety-event
oversight log: Sentinel, Delta, and Rendly each push a normalized "a LOCAL safety inspection
produced a non-pass outcome" record after their OWN in-product inspection fires, so an operator
watching the ecosystem gets one correlated view of "who blocked what, where, and how often"
without any product's detectors, message content, or detection logic being shared, federated, or
duplicated. The Orchestrator-side ingestion endpoint (`POST /v1/safety/events`) and its runtime
are being built concurrently by another agent on this same branch — this task is scoped
STRICTLY to the Rendly side: emit conforming events, never touch
`Anoryx-AI-Orchestrator/**` or `Anoryx-Sentinel/contracts/**`.

Rendly already has the real half of the story: R-008 (ADR-0008) inspects every chat message with
self-hosted, in-process, no-network detectors (`realtime/detectors.py`) before persist, and on a
non-pass outcome the message is fail-closed blocked and the rejection is durably recorded in
`inspection_audit_log` — real, non-stubbed, already shipped. X-004 asks for exactly one additive
thing on top: forward that ALREADY-REAL block outcome to the Orchestrator, as bounded metadata,
best-effort. It is a visibility seam, not a new detector, not a new enforcement point, and not a
reason to touch the local block/persist/ack decision, which has already been made by the time this
seam is ever invoked.

## Decisions (one per resolved fork)

### Fork A — what triggers an emission: **A1 (a genuine detector `blocked` outcome ONLY — never `seam_unavailable`, never `pass`)**
`pipeline.py`'s `handle_chat_send` has three non-pass branches: a raising/unavailable inspector
(`seam_unavailable`), a real `blocked` verdict (one or more of `detectors.py`'s three categories
fired), and a defensive `status != "pass"` catch-all. Only the middle branch — an actual
`pii`/`injection`/`secret` category tripping — maps onto the Orchestrator's wire contract, whose
`SafetyEventIngestRequest.category` enum is `[pii, injection, secret]` and whose `outcome` enum
accepts only `block` in v1. `seam_unavailable` has no category to report (it is an infrastructure
failure, not a policy finding) and forcing it into one of the three categories would be a
fabricated, misleading signal in the oversight log — worse than not reporting it at all. Rejected:
A2 (also report `seam_unavailable`, e.g. as all three categories or a synthetic fourth value) —
not a real finding, not representable in the closed wire enum without either lying about the
category or requiring an Orchestrator contract change (out of scope here — `api-architect` owns
that surface).

### Fork B — one event vs. one call: **B1 (one event PER blocking category, since a single message can trip more than one detector at once)**
All three detectors always run (`sentinel_inspector.py`), so a single blocked send can carry
multiple `block` findings simultaneously (e.g. an email address AND an AWS-key-shaped token in the
same message). The wire contract's `SafetyEventIngestRequest` carries exactly one `category` per
event (no array), so `safety_event_emitter.emit_block_events_best_effort` schedules one POST per
`DetectorFinding` whose `outcome == "block"`, each with its own `idempotency_key` (Fork D). This
is the only way to report N simultaneous category findings without inventing a new
multi-category wire shape (not this task's call to make — `api-architect` owns the contract).

### Fork C — delivery model: **C1 (a thin, direct, fire-and-forget `asyncio.create_task` HTTP call — NOT a new queue/worker system)**
Sentinel's own outbound-egress precedent (F-020 / ADR-0023) built a whole Redis-Streams
consumer-group worker with DLQ/retry/checkpoint for its Slack/Jira/Splunk webhooks — justified
there by reusing F-015's ALREADY-EXISTING worker infrastructure for a multi-provider, at-least-once
delivery guarantee. Rendly has none of that infrastructure, and this is a single, bounded,
best-effort HTTP call to ONE endpoint — building a parallel queue/worker system for it would be
exactly the kind of scope-widening a bounded oversight-visibility task should not do unilaterally.
`emit_block_events_best_effort` is instead a plain SYNCHRONOUS function: it schedules one
`asyncio.create_task` per blocking category and returns immediately (never awaited by
`pipeline.py`), so it adds zero latency to the `chat.ack` and cannot itself raise into the caller.
Each scheduled task has its own bounded timeout (3s) and swallows every exception (network error,
timeout, non-2xx, DNS failure) — this is the SAME reasoning ADR-0023 §4.1 documents as the
"scoped exception to non-negotiable #5": delivery is downstream notification, not an inspection
gate, so it fails OPEN, exactly as the security-path fail-CLOSED decision (R-005/R-008,
non-negotiable in THIS product's own send pipeline) is left completely untouched — the two
postures coexist because they gate different things. Rejected: C2 (await the POST inline before
sending the `chat.ack`) — would make an unrelated third-party HTTP call latency-gate (and, on a
hung Orchestrator, potentially block) the sender's own block acknowledgment; a direct violation of
the "delivery failure NEVER touches the user's request path" precedent. Rejected: C3 (build a
Rendly-local outbound queue/worker, mirroring F-020) — real infrastructure this task's scope does
not justify; nothing here needs at-least-once delivery or a DLQ (Fork E honesty boundary below).

### Fork D — idempotency key: **D1 (derived from the SAME `audit_id` already written to `inspection_audit_log`, plus the category)**
`pipeline.py` now generates one `audit_id` per non-pass branch (previously generated inside
`_record_inspection_audit`, now generated by the caller and passed in) so the SAME id anchors both
the local audit row and, on the `blocked` branch, every emitted event's
`idempotency_key = f"rendly-inspection-{audit_id}-{category}"`. This is stable (retrying the exact
same inspection outcome reproduces the exact same key set) and unique per (inspection-audit-row,
category) — safe for the Orchestrator to dedup on (`disposition: duplicate`) without Rendly
needing its own delivery ledger.

### Fork E — configuration / default posture: **E1 (env-var gated, no-op when unconfigured — mirrors `realtime/ice.py`'s degrade-not-block pattern)**
`RENDLY_ORCHESTRATOR_SAFETY_URL` (the Orchestrator's base URL) and
`RENDLY_ORCHESTRATOR_SAFETY_TOKEN` (the `safetySourceBearer` credential the Orchestrator resolves
to `source_product: rendly`) must BOTH be set for `emit_block_events_best_effort` to schedule
anything; either missing is a silent, safe no-op — no task scheduled, no exception, no log noise
beyond nothing happening. This is the correct default for every Rendly deployment that has not yet
wired up Orchestrator connectivity (which is every deployment today, since the Orchestrator
runtime for this endpoint does not exist on `main` yet) — R-008's own block/persist/audit behavior
is 100% unaffected either way, exactly as `ice.py`'s STUN/TURN bootstrap degrades to an empty
`ice_servers` list rather than failing when unconfigured.

## What's built

- `realtime/safety_event_emitter.py` (new) — `emit_block_events_best_effort` (sync, schedules
  fire-and-forget tasks) + `_post_event` (the actual bounded, exception-swallowing POST) +
  `_build_payload` (the closed `SafetyEventIngestRequest` shape, no `source_product` — the
  contract states it is server-resolved from the bearer and must never be supplied in the body).
- `pipeline.py` — `_record_inspection_audit` now takes `audit_id` as a caller-supplied parameter
  (previously self-generated) so it can be shared with the emitter; `handle_chat_send`'s
  `outcome.status == "blocked"` branch calls `emit_block_events_best_effort` immediately after the
  existing `_record_inspection_audit` call. The `seam_unavailable` / raising branches are
  unchanged apart from now passing a freshly generated `audit_id` through (Fork A: no emission).
- `pyproject.toml` — `httpx` promoted from a dev-only dependency (the FastAPI `TestClient`
  transport) to a core runtime dependency, since `safety_event_emitter.py` needs it in the deployed
  image (`.[server]`), not just in tests.

## Honesty boundary (mandatory, verbatim)

- **"best-effort, metadata-only oversight visibility,"** not "guaranteed delivery" and not "a
  detector dependency." A lost notification (Orchestrator down, network partition, a malformed
  response) is silently dropped after one attempt — no retry, no backoff, no dead-letter queue.
  This is an ACCEPTABLE loss because the signal is oversight (a human dashboard later sees fewer
  incidents than actually happened), never enforcement (R-008's own fail-closed block/persist/ack
  decision on the CURRENT message is complete and correct with or without this seam ever firing).
- **"the same taxonomy R-008 already uses,"** not a new classification. `category` is exactly one
  of R-008's own three detector categories; this ADR introduces no new detection, no new
  heuristic, and no change to what counts as PII/injection/secret.
- ADR-0008 Fork A2 ("no calls to Sentinel's own detector code, no shared cross-product inspection
  endpoint") is UNCHANGED: this seam runs strictly AFTER Rendly's own detectors have already
  produced a verdict — nothing here inspects, re-scans, or asks any other product's code to
  classify anything.

## Deferred (explicit)

- Retry / backoff / dead-letter queue for a failed delivery — a Rendly-local F-020-style worker
  is deliberately NOT built (Fork C); a future task could add one if the oversight log's
  completeness becomes load-bearing rather than best-effort.
- The genuine "two real apps" end-to-end test (Rendly's real pipeline AND the Orchestrator's real
  `POST /v1/safety/events` running together) — this task's integration test uses a lightweight
  local HTTP sink standing in for the Orchestrator specifically because the Orchestrator runtime
  is being built concurrently and was not available to this task in isolation; a later task owns
  the genuine non-stubbed two-app e2e.
- Any Rendly-side read/query of the Orchestrator's `GET /v1/safety/events` — out of scope; this
  ADR is about the WRITE side only.
- Reporting `seam_unavailable` in any form (Fork A) — deferred until/unless a future Orchestrator
  contract change adds a representable value for it.

## Consequences

- An operator watching the Orchestrator's cross-product safety-event oversight log now sees
  Rendly's REAL R-008 block outcomes (category + tenant + opaque channel target + timestamp)
  alongside Sentinel's and Delta's, with zero risk of message content or PII crossing the
  product boundary (the emitted payload is a strict subset of what `inspection_audit_log` already
  stores locally, itself already metadata-only).
- Every existing R-008 behavior (detection, fail-closed block, local audit log) is provably
  unchanged: `tests/realtime/test_chat_inspection_sentinel.py` and
  `tests/realtime/test_detectors.py` pass unmodified.
- A Rendly deployment that never configures `RENDLY_ORCHESTRATOR_SAFETY_URL` /
  `RENDLY_ORCHESTRATOR_SAFETY_TOKEN` (every deployment today) behaves EXACTLY as before this ADR —
  the seam is additive and fully optional.
