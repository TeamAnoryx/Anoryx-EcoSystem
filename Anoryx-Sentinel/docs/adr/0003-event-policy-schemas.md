# ADR-0003: Event and Policy Intake Schemas

**Date:** 2026-06-15  |  **Status:** Accepted

## Context
Sentinel is the data path for the whole Anoryx ecosystem (ADR-0001) and exposes an
OpenAI-compatible surface locked in `contracts/openapi.yaml` (ADR-0002). Two
integration boundaries remain to be locked in Phase 0:

1. **Events UP** — Sentinel emits security/usage/compliance events to
   Anoryx-AI-Orchestrator over the Redis Streams bus; those events flow onward to
   Delta, where they become the cost/risk record. `contracts/events.schema.json`
   is that contract.
2. **Policies DOWN** — Delta authors budget limits and model allow/deny lists,
   which Anoryx-AI-Orchestrator pushes into Sentinel for enforcement at the
   gateway. `contracts/policy.schema.json` is that contract.

Both files were Phase 0 stubs (an empty event_type enum; a generic rules array).
We need to complete them, decide their wire format, and apply the same security
discipline the F-001 audit forced onto `contracts/openapi.yaml`. These two files
are the integration boundary Delta and Anoryx-AI-Orchestrator depend on, so they
are treated as immutable once locked.

## Decision

### Wire format: JSON Schema Draft 2020-12
Both contracts are JSON Schema Draft 2020-12, matching the dialect already used by
`contracts/openapi.yaml`. We considered and rejected the alternatives for Phase 0:

- **Avro / Protobuf** — compact and fast, but they push a code-generation and
  schema-registry step onto three independently built products (Sentinel,
  Orchestrator, Delta) before any of them can exchange a single message. The
  events are low-volume control-plane records (security findings, usage rollups,
  policy pushes), not a high-throughput data plane, so binary compactness is not
  the constraint. Audit-readiness needs human-readable, hand-inspectable evidence
  on the bus; opaque binary frames work against that.
- **CloudEvents** — a reasonable envelope standard, but it would add an outer
  metadata layer whose attribution fields overlap and compete with our four stable
  IDs, creating two places to look for "who did this." We keep one flat, explicit
  attribution model anchored on `contracts/ids.md`.

JSON Schema lets the same documents validate in every language with off-the-shelf
validators, keeps the records readable for audit, and reuses the dialect, tooling,
and review muscle already established by ADR-0002.

**Pinned validator dialect (no parser-differential).** Sentinel,
Anoryx-AI-Orchestrator, and Delta MUST all validate these records with a **JSON
Schema Draft 2020-12** validator — the exact `$schema` declared in both files. This
is normative: a single pinned dialect across all three products means a record that
validates for the emitter validates identically for every consumer, so no
parser-differential exists where one component accepts a record another rejects.
Tooling that interprets OpenAPI-only keywords (see the `discriminator` note below)
MUST NOT be the validation authority.

### Seven event types mapped to enterprise security operations
The `event_type` enum is closed at seven variants, each mapping to a concrete
enterprise security-operations need rather than an arbitrary log line:

- `usage` — attribution and the client-side cost estimate that feeds Delta FinOps.
- `pii_blocked` — data-protection audit trail.
- `injection_detected` — prompt-injection defense evidence.
- `secret_leaked` — secret-exfiltration defense evidence.
- `policy_violated` — proof that a Delta-sourced policy was enforced at the gateway.
- `compliance_checked` — per-control audit-ready evidence for SOC2/GDPR/HIPAA/EU AI Act.
- `shadow_ai_detected` — unsanctioned-AI discovery.

Together these cover the audit trail, attribution, and compliance-reporting story
an enterprise buyer expects, and each is the natural producer of a row Delta and
the compliance console will query.

### Four stable IDs required on every event and every policy
Every event variant and every policy variant REQUIRES all four stable IDs from
`contracts/ids.md` — `tenant_id`, `team_id`, `project_id` (UUID v4, `maxLength:64`)
and `agent_id` (lowercase slug, `maxLength:64`). They are the cross-product join
key: without them an event cannot be attributed to a Delta record or an
Orchestrator context, and a policy cannot be scoped. The IDs are LOCKED/IMMUTABLE;
this ADR uses the exact formats from `contracts/ids.md` and does not redefine them.
Events additionally require `event_id`, `event_timestamp`, and `request_id` (the
correlation handle back to the originating gateway request, matching the
`X-Request-Id` of `contracts/openapi.yaml`). On events, the attribution carried is
the SERVER-RESOLVED value from the key-to-ID binding (ADR-0002), never a raw client
header, so attribution on the bus cannot be forged.

The four IDs and the three event-envelope fields are inlined directly into each of
the seven event variants. An earlier draft factored them into a shared `BaseEvent`
`$ref`, but no variant ever `allOf`-referenced it, so `BaseEvent` was dead — and
composing it via `allOf` would have collided with `additionalProperties: false`
(the inner subschema cannot see the base's properties, so base fields get rejected).
Rather than ship a definition that looks authoritative but governs nothing, we
DELETED `BaseEvent` and keep each variant a single self-contained closed object.
The cost is field duplication across variants; the benefit is that
`additionalProperties: false` provably holds on every variant and there is exactly
one place per variant that defines its shape.

**Event-bus provenance is backed by a control, not emitter good behavior.** The
claim that on-bus attribution "cannot be forged" rests on a transport control, not
on trusting whatever writes to the bus: the Redis Streams event bus is a trusted
internal boundary. `src/orchestration` is the ONLY writer, the bus is reached over
internal mTLS (per the Sentinel source layout), and external clients never address
it directly. So the IDs on an event are server-resolved at the gateway and then
carried across a mutually authenticated internal channel — an external party has no
write path to inject a forged event. This is risk reduction via a concrete control
(single authenticated writer + mTLS), not an assumption that emitters behave; the
schema cannot enforce who writes to the bus, so the deployment control does.

### Closed schemas (`additionalProperties: false`)
Every object in both files sets `additionalProperties: false`, directly applying
the F-001 HIGH finding from ADR-0002: an open schema is a smuggling channel. On
the event bus an unknown key could carry raw PII or attacker-controlled data
downstream into Delta; on policy intake it could carry an unrecognized directive
that one consumer honors and another ignores. Closing every object means a
consumer never silently forwards a field it did not expect.

### Bounded field sizes
Every string has `maxLength`, every array has `maxItems`, and every number has
`minimum`/`maximum`, applying the F-001 HIGH DoS-via-inspection finding. An
unbounded `detected_endpoint`, `allowed_model_ids`, or `signature` is a resource
exhaustion vector against whichever component validates or persists the record.
Bounds also serve PII safety, but description prose is not a control, so the PII and
log-injection guards are now STRUCTURAL, not just documented:

- `shadow_ai_detected.detected_endpoint` carries `pattern: ^[^?#@\s]+$`, which
  forbids `?`, `#`, `@`, and whitespace — query strings, fragments, and userinfo
  (the parts of a URL most likely to carry tokens/PII) cannot ride along even if an
  emitter forgets to strip them.
- `pii_blocked.sample_excerpt_redacted` REQUIRES a redaction marker via
  `pattern: (\[REDACTED\]|\*\*\*)`; an excerpt with no marker fails validation, so a
  raw-PII excerpt cannot pass as "redacted." The field stays optional — emitters
  that cannot guarantee redaction omit it.
- Free-form ID-like string fields that land in logs — `request_id`,
  `violation_type`, `control_id` — carry a conservative charset pattern
  (`^[A-Za-z0-9._-]{1,N}$`) forbidding control characters and whitespace, closing a
  log-injection vector against whichever component writes them to an audit log.

On policy intake, `BudgetLimitPolicy` carries an object-level
`anyOf: [{required:[max_tokens_per_period]}, {required:[max_cost_cents_per_period]}]`
so a "budget" that limits neither tokens nor cost fails validation rather than
silently being a no-op. This converts a former prose "should set one of" into a
schema-enforced "must set one of," and composes cleanly with
`additionalProperties: false` because each `anyOf` branch asserts only `required`,
not properties.

### `policy_version` + `signature` required on every policy
Policy intake is a privileged write into the security path, so it gets two
defenses beyond the closed/bounded baseline:

- **`signature` (presence + format required)** — a compact-JWS cryptographic
  signature over the record (`minLength: 16` plus a three-segment base64url
  `pattern`), so a degenerate value like `"a"` cannot validate. The body IDs are
  explicitly NOT authoritative: the gateway resolves the authoritative
  tenant/team/project scope from the VERIFIED signature SERVER-SIDE and rejects any
  record whose body IDs disagree with the signature-resolved scope, mirroring the
  `id_context_mismatch` rejection and virtual-API-key key-to-ID binding of
  `contracts/openapi.yaml`. This is the cross-tenant policy-poisoning defense:
  supplied IDs are a cross-check only and can never widen a scope the signature does
  not authorize. The schema enforces PRESENCE + FORMAT only; cryptographic
  verification of VALIDITY and the scope-resolve-and-reject obligation land in
  F-008, and **full lock of this contract is gated on F-008 landing**. A present,
  well-formed, but cryptographically invalid signature is a runtime rejection, not a
  schema pass.
- **`policy_version` (monotonic per `policy_id`)** — a counter whose monotonicity
  target key is `policy_id` (chosen as the stable per-policy identity). Intake MUST
  reject any record whose `policy_version` is `<=` the currently stored version for
  the **same `policy_id`**. Without this, an attacker who captured an older
  legitimately-signed policy could replay it to roll enforcement back to a weaker
  state. `policy_version` is bounded at `9007199254740991` (JS
  `Number.MAX_SAFE_INTEGER`) so JSON consumers do not lose precision via IEEE-754.
  The schema enforces only the integer bound and its presence; `policy_version` is
  a **hint until F-008** wires the monotonicity check against stored state and makes
  rejection authoritative.

## Consequences
- `contracts/events.schema.json` moves from an empty-enum stub to a closed
  `oneOf` over seven `event_type` variants; `contracts/policy.schema.json` moves
  from a generic `rules` array to a closed `oneOf` over three `policy_type`
  variants. Both are now binding integration contracts.
- Dispatch is machine-decidable via `oneOf` + the per-variant `event_type` /
  `policy_type` `const` — the SOLE normative dispatch mechanism. The `const` values
  are unique and the variants are mutually exclusive, so a Draft 2020-12 validator
  selects exactly one variant with no prose interpretation required. The
  `discriminator` keyword retained in each file is an OpenAPI-only construct: it is
  NOT a Draft 2020-12 keyword, has NO validation effect under this dialect, and is
  labelled in an adjacent `$comment` as a non-normative hint for OpenAPI tooling.
  We keep it (rather than delete it) only so OpenAPI-aware tooling renders the
  variants nicely; it must never be the validation authority, which would reopen a
  parser-differential between OpenAPI tooling and pure 2020-12 validators.
- Delta and Anoryx-AI-Orchestrator can join every event to a record by the four IDs
  and trust the attribution because it is server-resolved, not header-supplied.
- The policy path carries replay/rollback and cross-tenant-poisoning defenses by
  contract before F-008 implements signature verification, reducing the risk that a
  weak intake path becomes the soft underbelly of the security product.

## Trade-offs
- **Human-readability vs compactness** — JSON is larger on the wire than Avro or
  Protobuf. Accepted: these are control-plane records, not a hot data plane, and
  audit-readiness values inspectable evidence over bytes saved.
- **Schema evolution** — additive only within `v1`: new OPTIONAL fields and new
  event/policy variants may be added without a version bump. Any change to an
  EXISTING field, or removal of a variant, requires a new ADR, marks the old field
  deprecated with a sunset (per ADR-0002 change discipline), and on a breaking
  change introduces `:v2` `$id`s rather than mutating `:v1`. The four IDs cannot be
  renamed without an ADR plus a full migration plan.
- **Discriminator strictness** — `oneOf` over `const` discriminators means a record
  with an unknown `event_type`/`policy_type` fails validation outright. This is
  intentional fail-safe behavior, at the cost that consumers must ship a schema
  update before they can emit or accept a new variant.

## Intentionally deferred (out of Phase 0 scope)
- Avro/Protobuf IDL and a schema registry (revisit only if event volume becomes a
  data-plane concern).
- Code generation / typed client stubs from these schemas.
- Runtime cryptographic signature verification on policy intake — implemented in
  F-008. This ADR locks only the required PRESENCE of `signature` and the
  server-side resolve-and-reject obligation.
- Enforcement of the `policy_version` monotonicity check itself (the schema states
  the obligation; the gateway/persistence layer enforces it against stored state).
- The code->message and code->variant 1:1 runtime guarantees (schema enums are
  independent; the implementation guarantees pairing, covered by unit tests — same
  pattern as ADR-0002's error envelope).

## References
- `contracts/ids.md` — the four stable IDs (LOCKED/IMMUTABLE) and their formats.
- `contracts/openapi.yaml` — OpenAI-compatible surface; virtual-API-key key->ID
  binding and `id_context_mismatch` rejection pattern reused here.
- `contracts/events.schema.json`, `contracts/policy.schema.json` — the contracts
  this ADR locks.
- ADR-0002 — OpenAI-compatible API surface; source of the F-001 audit findings
  (closed schemas, bounded fields, fail-safe semantics, change discipline) applied
  here.

## Change discipline
Any change to an existing field requires a new ADR; the old field is marked
deprecated with a sunset before removal. New OPTIONAL fields and new event/policy
variants are additive within `v1`; breaking changes bump to a `:v2` `$id`. The four
IDs are immutable and cannot be renamed without an ADR plus a full migration plan.
Framing here is intentionally "audit-ready" and "risk reduction", never
"compliant", "certified", or "blocks all attacks".
