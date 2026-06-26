# O-002 Security Audit — Ecosystem Event Bus Contract

**Verdict: CLEAN** (no High/Critical findings; no human escalation required).

**Scope:** the O-002 contract-only change — the cross-product event envelope
(`Anoryx-AI-Orchestrator/contracts/event-envelope.schema.json`), the bus seams added to
`contracts/openapi.yaml` (bounded replay, dead-letter metadata, schema-version negotiation), the
O-001 ingest reconciliation, the extended `tests/test_contract.py`, and `docs/adr/0002-*.md`.
Branch `task/O-002-event-bus`. The review was independent and arms-length: the auditor did not
write or code-review the change, re-ran the full suite itself, and actively attempted to break each
threat the ADR claims to cover plus probed for missed vectors.

## Test results (re-run by the auditor, not reported)

- `python -m pytest Anoryx-AI-Orchestrator/tests -q` → **27 passed** (13 O-001 contract tests,
  two of them deliberately updated for the Fork-D reconciliation, + 14 new O-002 tests).
- `ruff check Anoryx-AI-Orchestrator` → clean (exit 0).
- `black --check Anoryx-AI-Orchestrator` → clean (exit 0).

After the audit, one Low finding (LOW-1, below) was remediated and the suite re-run green
(27 passed, ruff + black clean).

## Threat vectors actively tested — all adequately bounded

1. **Replay amplification — PASS.** `ReplayRequest` is a `oneOf` requiring exactly one selector.
   By live probe: no-selector (full) replay, over-limit (`limit: 1001`), negative limit, unknown
   `source_product`, and extra-property smuggling are all schema-rejected. `limit` is capped 1..1000;
   a value > 1000 is not expressible. The seam is behind mTLS + serviceToken and only 202-acknowledges
   — no replay runs (boundary a).
2. **`source_product` spoofing — PASS.** Stated as a binding obligation (not implied) in the envelope
   schema, `openapi.yaml` `info.description`, the `SourceProduct` schema, and ADR threat 2: the trusted
   value is the mTLS peer, the body value is never trusted, and disagreement routes to a
   `source_identity_mismatch` DLQ. No example treats a body-supplied `source_product` as authoritative.
3. **DLQ poisoning — PASS.** `attempt_count` is bounded 0..1000; `max_attempts_exceeded` is a terminal
   closed-enum reason; all DLQ shapes are `additionalProperties:false` + bounded. `GET /v1/bus/dlq`
   returns `DeadLetterMetadata` only — the full `DeadLetterEnvelope.original_envelope` is never wired to
   any response (grep-confirmed: component + stored shape only), preserving the O-001 read-only-metadata
   boundary.
4. **Version downgrade — PASS.** `schema_version` is `integer 1..1000` (not a `const`), so an unknown
   value structurally validates and routes to the DLQ (fail-closed reject-to-DLQ, boundary c) rather
   than 422. The supported set is an explicit allow-list via `GET /v1/bus/schema-versions`
   (`supported: [1]`). A `const` here would make reject-to-DLQ unreachable; the modelling is correct.
5. **Idempotency-key forgery → event suppression — PASS.** `idempotency_key` MUST equal the
   server-resolved `payload.event_id`, stated with tamper-evidence via the ingest HMAC over
   `"{timestamp}.{body}"` and the ±300s window. Charset forbids control characters/whitespace.
6. **Schema smuggling / DoS-via-inspection — PASS.** Every new object is `additionalProperties:false`
   and every field is bounded (`maxLength`/`maximum`/`maxItems`). No unbounded string/array/integer.

## Other checks

- **Payload `$ref` integrity — PASS.** The envelope `payload` `$ref`s
  `../../Anoryx-Sentinel/contracts/events.schema.json` (`$id sentinel:events:v1`, resolved on disk);
  nothing copies or widens F-002. `policy.schema.json` (`$id sentinel:policy:v1`, frozen F-008 `a9e2344`)
  is untouched and its `policy_type` stays closed. The branch diff is exactly four files.
- **Test false-green resistance — PASS.** A live probe confirmed that an unresolved payload `$ref`
  raises (referencing `Unresolvable`) rather than silently skipping, and that a garbage payload is
  genuinely rejected through the `$ref` — the registry-resolution harness enforces the wrapped-payload
  constraint for real.
- **Honesty boundaries verbatim — PASS.** O-002 (a)/(b)/(c) appear verbatim in `info.description` and
  ADR-0002, asserted by `test_o002_honesty_boundaries_present_verbatim`.
- **Contract-only integrity — PASS.** Replay returns `202 {state: pending}`; DLQ/schema-versions return
  metadata; nothing performs a replay or moves a message to a DLQ.
- **Secrets — PASS.** The example compact-JWS decodes to a fabricated placeholder (header `{alg: ES256}`,
  a `tenant_id` claim, and a signature segment that literally spells "example"); no key material. The
  `X-Sentinel-Timestamp` example is a fake epoch.
- **ADR consistency — PASS.** ADR-0002 builds on ADR-0001 (both contract-only); the Fork-D ingest
  reconciliation is the deliberate, ADR-permitted update of two O-001 tests; the read-only-metadata and
  mTLS-deferred boundaries are carried forward, not contradicted.

## Findings

| ID | Severity | Status | Summary |
|----|----------|--------|---------|
| LOW-1 | Low | **Remediated** | `limit` was optional on the replay branches, so the "always with a limit cap" guarantee relied on a consumer-applied default. Amplification stayed bounded regardless (> 1000 not expressible), but the schema did not match its own prose. Fixed: `limit` is now **required** on `ReplayFromSequence`/`ReplayFromTimestamp`/`ReplayFromDlq`, enforcing the cap at the schema gate. |
| LOW-2 | Low | **Accepted / deferred** | `GET /v1/bus/dlq` inherits the O-001 coarse-grained service token: a token holder reads DLQ metadata across tenants (per-tenant authz deferred to O-006, honesty boundary d). Materiality is low — `DeadLetterMetadata` exposes only `dlq_id`/`reason`/`attempt_count`/timestamps/`event_type`/`source_product`/`sequence`, carries **no** `tenant_id`/`team_id` and never `original_envelope`, so no tenant-attributed data or payload leaks cross-tenant. No O-002 change required; O-006 must land per-tenant read scoping before any DLQ metadata gains tenant-identifying fields. |

No High or Critical findings. No human escalation triggered.
