# ADR-0017 — Rendly ↔ Orchestrator Wiring Validated (X-004, non-stubbed)

- Status: Accepted
- Date: 2026-07-10
- Task: X-004 (Cross-product integration, 🔮 speculative-tagged in the roadmap checklist —
  scoped down to a bounded metadata-only oversight seam via the Orchestrator, per Rendly's
  own ADR-0026; NOT a direct Rendly-Sentinel wire, NOT a detector integration)
- Depends on: R-008 (Rendly's self-hosted PII/injection/secret message inspector,
  `realtime/detectors.py` + `realtime/inspector.py`), the Orchestrator `safety` seam built
  concurrently on this same branch (`src/orchestrator/safety/router.py`,
  `persistence/migrations/versions/0012_safety_events.py`)
- Builds on: ADR-0016 (X-001, Sentinel ↔ Orchestrator wiring validated — same shape of
  finding, same pattern: drive the OTHER product's real pure functions in-process, POST the
  result into this product's real app); Rendly ADR-0026 (the Rendly-side design record for
  `safety_event_emitter.py` — the Fork A-E decisions on trigger/batching/delivery/idempotency/
  configuration this ADR's test payload is built from, unchanged and un-re-litigated here)
- Numbering: this is Orchestrator ADR **0017** — the next unused number in this product's own
  sequence (0001–0016 already assigned; 0016 is X-001's sibling wiring-validated ADR). Mirrors
  the X-001 precedent directly: the non-stubbed wiring test lives in
  `Anoryx-AI-Orchestrator/tests/integration/` (this is where a payload built from the OTHER
  product's real code is POSTed into THIS product's real app), so the ADR documenting that
  proof lives here too — exactly where ADR-0016 lives for X-001. (Contrast X-002, whose
  wiring-validated ADR lives in `Delta/docs/adr/0016-...md` because ITS wiring test lives in
  Delta's own tree, driving Orchestrator's code from there — the convention is "the ADR lives
  wherever the proof does," not "always in Orchestrator.")
- Supersedes: nothing. Adds one new test file; zero new tables, zero new migration, zero new
  endpoint, zero new production code (beyond the contract's `(ADR — X-004)` placeholder
  strings now resolving to this file — a documentation-only edit).

## Context

X-004 gives the Orchestrator a cross-product safety-event oversight log (`POST`/`GET
/v1/safety/events`, `contracts/openapi.yaml`'s `safety` tag). Two other agents built both
halves of this seam independently but concurrently on the same branch, each against the SAME
OpenAPI contract:

- **Orchestrator** (`src/orchestrator/safety/`): the real ingest + read runtime, proven by its
  own non-stubbed `tests/integration/test_safety_e2e.py` (real persistence, idempotency,
  cross-tenant RLS isolation, hash-chain validation) — driven by a HAND-BUILT, schema-valid
  request.
- **Rendly** (`realtime/safety_event_emitter.py`): a best-effort, fail-open notifier wired into
  the real R-008 send pipeline, proven by its own non-stubbed
  `tests/realtime/test_chat_inspection_safety_events.py` — driven against a local test HTTP
  sink standing in for the Orchestrator (which did not exist yet when Rendly's side was built;
  Rendly's own ADR-0026 names this exact gap under "Deferred").

Neither suite proves the two are actually wire-compatible with EACH OTHER: that a payload
Rendly's real code genuinely produces is something Orchestrator's real app actually accepts.
X-001 closed this identical gap for Sentinel→Orchestrator; this ADR closes it for
Rendly→Orchestrator, following the exact same pattern.

## Decision — resolved forks (mirrors ADR-0016's fork table shape)

| Fork | Decision |
|------|----------|
| **A** — how to obtain a "genuine" Rendly event without a live Rendly deployment | **A1**: drive Rendly's REAL, installed R-008 code in-process — `detect_pii` / `detect_injection` / `detect_secret` (`realtime/detectors.py`, regex + Shannon-entropy, no network/ML dependency) against category-shaped fixture content, then `safety_event_emitter._build_payload` (the exact, private-but-pure function `emit_block_events_best_effort` calls to build the wire body in production) — imported unmodified from the installed `rendly` package the `orchestrator-integration` CI lane now installs (`pip install -e ../Rendly[dev]`, `.github/workflows/orchestrator-ci.yml`). Nothing about the payload shape is hand-typed by the test. |
| **B** — which detector(s) to drive | **B1**: all three (`pii`, `injection`, `secret`), parametrized — unlike X-001's Fork B (which picked ONE detector to dodge an optional heavy dependency), Rendly's three R-008 detectors are ALL pure regex/entropy with zero optional-dependency risk (`detectors.py`'s own docstring: "regex + arithmetic only... NOTHING here makes a network call"), so there is no reason to under-cover the category enum the wire contract exposes. |
| **C** — importing a private-but-pure function | **C1**: import `_build_payload` directly, same precedent ADR-0016/X-001 already established for `HookContext._stamp_event` — a private (`_`-prefixed) but PURE function is the exact production logic the public entry point (`emit_block_events_best_effort`) calls before scheduling its fire-and-forget task; calling it directly is the only way to get the real payload shape without either duplicating that logic by hand in the test (drift risk) or driving the full async `asyncio.create_task` fire-and-forget path (which the emitter deliberately does not await, per Rendly ADR-0026 Fork C — awaiting it here would fight that design, not validate it). |
| **D** — auth | **D1**: real `safetySourceBearer` resolution — `ORCH_SAFETY_SOURCE_TOKENS` configured with a `rendly` entry, presented as `Authorization: Bearer <token>`, resolved server-side to `source_product: "rendly"` by Orchestrator's real `_resolve_source` (never accepted from the body — confirmed directly: the test asserts `_build_payload`'s own output never includes a `source_product` key). |
| **E** — scope boundary (what this does NOT re-prove) | **E1**: this suite does not re-drive Rendly's own WebSocket/pipeline/Postgres path (`Rendly/tests/realtime/test_chat_inspection_safety_events.py` already proves that in-product path against a local sink) or Orchestrator's own hash-chain/RLS/pagination depth beyond confirming one accept + one idempotent-duplicate round trip (`test_safety_e2e.py` already proves that in depth). Re-proving either here would duplicate coverage without validating anything new about the *wiring* — this ADR's actual subject, exactly as ADR-0016 §D reasons for X-001. |

## What this proves (and what it doesn't)

**Proves:** a genuinely Rendly-produced `SafetyEventIngestRequest` — real detector output (all
three R-008 categories), real `_build_payload` stamping, real `safetySourceBearer` auth — is
accepted end-to-end by Orchestrator's real `POST /v1/safety/events`, durably persisted with
`source_product` server-resolved to `"rendly"`, readable back byte-for-byte via the real `GET
/v1/safety/events` tenant-scoped seam, and correctly deduplicated (`disposition: duplicate`, no
second row) on a retried push carrying Rendly's own real `idempotency_key` derivation
(`rendly-inspection-{audit_id}-{category}`).

**Does not prove (honesty boundary, non-removable):** that Rendly's live deployment today
actually calls the Orchestrator in production (it does not — per Rendly ADR-0026,
`RENDLY_ORCHESTRATOR_SAFETY_URL`/`RENDLY_ORCHESTRATOR_SAFETY_TOKEN` are unconfigured in every
deployment as of this ADR, a deliberate, safe no-op default); that Rendly's own
`asyncio.create_task` fire-and-forget scheduling, timeout, or exception-swallowing behavior
works correctly (Rendly's own suite proves that — this test calls `_build_payload` directly,
never `emit_block_events_best_effort`); mTLS peer authentication (deferred across every X-family
wiring ADR to O-008, same as ADR-0016 §"Does not prove"); Orchestrator's own hash-chain/RLS/
pagination depth (proven in `test_safety_e2e.py`, not re-proven here).

## Testing

`Anoryx-AI-Orchestrator/tests/integration/test_rendly_wiring_e2e.py`
(`pytest.mark.integration`, gated by the EXISTING `safety_ready` fixture / `ORCH_REQUIRE_SAFETY_E2E`
env var — the same gate `test_safety_e2e.py` already uses; no new `ORCH_REQUIRE_*` flag, since
this proves an existing seam's cross-repo compatibility rather than gating a new autonomous
behavior, same reasoning as ADR-0016):

- `test_real_rendly_block_ingested_and_readable_back` (parametrized over `pii`/`injection`/
  `secret`) — accept, persist with server-resolved `source_product`, tenant-scoped readback.
- `test_real_rendly_retry_same_idempotency_key_is_duplicate_not_second_row` — a retried push of
  the SAME real Rendly-produced payload dedupes, no second row.

Verified locally against a real Postgres 16 instance (CI's exact `orchestrator-integration`
env/role/migration setup, with Sentinel's AND Rendly's `[dev]` extras installed): the new file
passes in isolation, and the full Orchestrator suite passes with it included. See this branch's
PR description / session log for the actual pass output captured at verification time.

## Out of scope (do not build here)

Rendly's live production wiring to a real Orchestrator deployment (deferred per Rendly
ADR-0026, unaffected by this ADR); Rendly's own fire-and-forget scheduling/timeout coverage
(Rendly's own suite); mTLS peer provisioning (O-008); any change to `Anoryx-Sentinel/contracts/`
or `policy.schema.json` (neither is touched); any change to Rendly's `realtime/` runtime code
(this ADR only imports already-shipped Rendly code).

## Consequences

- X-004 is proven, not merely asserted: the roadmap's Rendly↔Orchestrator oversight seam closes
  with a concrete, non-stubbed demonstration that Rendly's real emitted payload shape and real
  bearer auth are wire-compatible with Orchestrator's real ingestion — mirroring the X-001
  precedent for the sibling Sentinel↔Orchestrator seam.
- The `contracts/openapi.yaml` `safety` tag's and `SafetyEventIngestRequest`'s
  `(ADR — X-004)` placeholder strings now resolve to this file (Orchestrator ADR-0017) —
  the concrete home for the Orchestrator-side wiring-validation record, alongside Rendly's own
  ADR-0026 for the Rendly-side design rationale (Fork A-E: what triggers an emission, batching,
  delivery model, idempotency-key derivation, configuration posture).
