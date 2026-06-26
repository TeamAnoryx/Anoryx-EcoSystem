# ADR-0001: Orchestrator Internal API Contract (O-001)

## Status

Accepted (2026-06-26). First Anoryx-AI-Orchestrator ADR; opens this product's own ADR
sequence (Sentinel's ADRs 0001–0024 stay under `Anoryx-Sentinel/docs/adr/`).

Scope: **contract-only**. This ADR records the seam design and the architecture forks
for `Anoryx-AI-Orchestrator/contracts/openapi.yaml`. There is no runtime, persistence,
or enforcement code in O-001. O-002…O-008 and the X-001→X-003 loop bind to this seam.

## Context

The Orchestrator sits between **Sentinel** (zero-trust AI gateway — emits
governance/usage events UP) and **Delta** (FinOps/budget — submits policies DOWN for
distribution to Sentinels). O-001 defines the first inter-product seam and the
transport security posture so everything downstream has a stable contract to build to.

Inputs that constrain the design:

- **F-002 locked schemas.** `events.schema.json` (`$id sentinel:events:v1`) and
  `policy.schema.json` (`$id sentinel:policy:v1`, **frozen at F-008 commit `a9e2344`**),
  both JSON Schema **Draft 2020-12**. The `policy_type` enum
  (`budget_limit, model_allowlist, model_approval, model_denylist, code_scan, data_lock`)
  and both CHECK constraints are **closed**. Delta budgets ride the existing
  `BudgetLimitPolicy` variant.
- **Sentinel is OpenAPI 3.1.0.** Its `contracts/openapi.yaml` is `openapi: "3.1.0"`.
- **F-008 intake authority.** `Anoryx-Sentinel/src/policy/intake.py` verifies a policy's
  compact-JWS (ES256), and the **verified signature claims are the authoritative scope**
  — body IDs are a cross-check that can never widen scope. Sentinel rejects body-ID
  disagreement.
- **F-020 webhook pattern.** `src/orchestration/webhooks/signer.py` signs with
  HMAC-SHA256 over `"{timestamp}.{body}"`, headers `X-Sentinel-Signature: sha256=<hex>`
  + `X-Sentinel-Timestamp`, ±300s replay window.
- **F-012a admin surface.** Sentinel's contract exposes a read-only policy-status read
  (`GET /admin/tenants/{tenant_id}/policies`, `adminAuth` bearer). The policy *intake*
  itself is the internal `intake.py` path, not a public REST route.

## Decision

Three seams + a transport security scheme, in OpenAPI 3.1, referencing the locked F-002
schemas by `$ref`. Each STEP-0 fork below resolves to the lean / smaller-attack-surface
default (banked rule 13); none lacked a safe lean default, so none was escalated.

### Fork — OpenAPI version: **3.1.0**

3.1 aligns with JSON Schema 2020-12 (what F-002 uses), so the locked schemas are
`$ref`'d **directly with no translation**. Sentinel's contract is already 3.1.0, so there
is **no deliberate divergence to record** — the versions match.

### Fork — Event ingest transport: **HTTP webhook push (Sentinel → Orchestrator POST)**

`POST /v1/ingest/events`, mirroring F-020's HMAC-signed pattern. This keeps a clean
product boundary and does not couple the Orchestrator to Sentinel's internal Redis bus.
Pull-from-stream is an O-003 implementation detail, not a contract seam. The body is a
**single event**; batching and a cross-product envelope are deliberately left to O-002
(anticipated, not specified) so the contract is not painted into a corner.

### Fork — Request auth beyond mTLS: **HMAC body signature on ingest; service token on Delta seams**

- **mTLS** authenticates the **peer product** on every operation (see security fork).
- **HMAC** (`X-Sentinel-Signature` + `X-Sentinel-Timestamp`, F-020 reuse) gives the
  ingest seam **per-event tamper-evidence** and a replay window. It does not establish
  product identity (mTLS does).
- **Service token** (bearer) authorizes the Delta **distribution + query** caller. It is
  bearer-only and does not sign request bodies.

Stated plainly in the spec: each layer's coverage and non-coverage.

### Fork — Policy signing posture: **pass-through of already-signed policy (default); Orchestrator-signing gated off**

The primary path forwards an **already-signed F-008 compact-JWS** policy record
unchanged. The `policy` member of the distribution body validates against
`policy.schema.json` UNMODIFIED, including its embedded `signature`. `sign_on_behalf` is a
**documented but disabled** field — the Orchestrator holding Delta's signing key is the
larger trust surface, so the smaller surface is the default (rule 13). A future,
separately-approved capability may enable Orchestrator-signing; until then the later
implementation MUST reject `sign_on_behalf: true`.

### Fork — Versioning: **`/v1/` path prefix; reference F-002 `$id`s**

Base versioning only. Cross-product **envelope** version negotiation is O-002 and is not
specified here; this contract does not contradict it. Paths carry the explicit `/v1/`
prefix; servers carry no version segment.

### Fork — Transport security scheme: **`mutualTLS` declared + applied to all operations; provisioning deferred**

OpenAPI 3.1's `type: mutualTLS` security scheme is declared and applied to **every**
operation (a global default plus an operation-level requirement that pairs mTLS with the
seam's second factor). **Certificate provisioning and trust-store setup are deferred to
O-008 (F-034).** Until then the scheme is a contract declaration, not a live enforced
channel.

### Fork — ADR / file layout: **product-local mirror of Sentinel**

`Anoryx-AI-Orchestrator/{contracts/openapi.yaml, docs/adr/0001-*.md, tests/}`, mirroring
how `Anoryx-Sentinel/` is organized. The Orchestrator opens its own ADR sequence at
**0001** (Sentinel started at 0001 too); it does not continue Sentinel's numbering. The
security-audit artifact lives at the repo-root `docs/audit/O-001-security-audit.md`
(matching the existing root `docs/audit/` location).

## Honesty boundaries (verbatim, non-removable — rule 14)

These appear verbatim in `openapi.yaml` `info.description` and are repeated here:

- **(a)** mTLS is DECLARED in this contract; certificate PROVISIONING is DEFERRED to
  O-008 (F-034). Until then the mutualTLS scheme is a contract declaration, not a live,
  enforced channel.
- **(b)** Policy signing is PASS-THROUGH by default: the Orchestrator forwards an
  already-signed (F-008 compact-JWS) policy record and does NOT sign on Delta's behalf.
  Orchestrator-signing is an OPTIONAL, GATED capability that is NOT enabled in v1.
- **(c)** The query API is READ-ONLY METADATA at this stage. It exposes distribution
  status and event metadata; it does not mutate state and does not return full event
  payloads.
- **(d)** The Delta query service token is COARSE-GRAINED: per-tenant read
  authorization is NOT yet enforced (deferred to O-006). A token holder can read
  event/distribution metadata across tenants; the tenant_id/team_id filters are
  conveniences, not an authorization boundary. (Stated in the binding contract too, not
  only here.)

## Threat model (seam)

Design-level — there is no enforcement code yet, so each vector lists what the **contract**
asserts and what is **explicitly deferred**.

1. **Peer spoofing (a non-Sentinel/non-Delta caller hits a seam).** mTLS authenticates the
   peer product on every operation. **Gap:** mTLS provisioning is deferred to O-008
   (boundary a) — until provisioned, the interim peer-authenticators are the ingest HMAC
   (only the holder of the shared signing secret can produce a valid signature) and the
   Delta service token. This gap is stated, not hidden.

2. **Replay (a captured event POST is re-sent).** The ingest HMAC binds a `X-Sentinel-Timestamp`
   into the signed payload `"{timestamp}.{body}"`; receivers reject timestamps outside
   ±300s (F-020). **Deferred:** durable cross-product replay/dedup (an event seen twice
   inside the window, or envelope-level idempotency) is O-002 — the contract anticipates a
   dedup key (`event_id` is the bus dedup key, echoed on the 202) without specifying the
   O-002 envelope.

3. **Policy tampering / forged-signature pass-through.** The distribution `policy` member
   carries an embedded compact-JWS. **The Orchestrator does NOT cryptographically
   re-verify that signature at this seam** — Sentinel's `intake.py` is the verifying
   authority that resolves authoritative scope from the signature and rejects body-ID
   disagreement (cross-tenant poisoning defense). This is an intentional trust placement:
   verification lives at the enforcing boundary (Sentinel), not the relay (Orchestrator).
   The contract states this plainly so no reader assumes the Orchestrator validates policy
   signatures. The pass-through default (boundary b) keeps the Orchestrator out of the
   signing-key trust surface entirely.

4. **Unauthorized Delta read (event/policy-status data exfiltration).** The query seams
   require mTLS + service token and return **read-only metadata only** (boundary c) —
   join keys, type, time, and per-target delivery state, never full event payloads or
   policy bodies. This bounds the blast radius of a leaked service token to metadata.
   **Note:** O-001 does not yet specify per-tenant authorization scoping on the query seams
   (which Delta principal may read which tenant's metadata); that lands with O-006
   persistence + authorization. Until then the service token is coarse-grained — stated,
   not implied away, in BOTH this ADR and the binding contract (honesty boundary d in
   `info.description` plus a per-operation caveat on the two query seams).

5. **mTLS-not-yet-provisioned gap (boundary a).** The single largest honesty boundary: the
   transport-identity layer is declared but inert until O-008. The contract does not imply
   a live mTLS channel; the interim posture (HMAC + service token) is documented as the
   actual peer-auth until provisioning lands.

6. **Schema smuggling / oversize (DoS-via-inspection).** All Orchestrator-defined response
   and request wrapper schemas are closed (`additionalProperties: false`) and bounded
   (`maxLength` / `maxItems` / `maximum`), mirroring the F-001 audit posture; the referenced
   F-002 schemas are likewise closed/bounded. Unknown keys are rejected, not forwarded.

## Consequences

- O-003 (ingest pipeline), O-004 (distribution engine), O-005 (registry), O-006
  (persistence + query authorization), O-007 (UI), O-008 (deploy + mTLS provisioning) all
  bind to these paths, schemas, and security schemes. Changing a path or a security scheme
  later is a breaking change to a published cross-product contract — treat as such.
- The `sign_on_behalf` field reserves space for Orchestrator-signing without enabling it;
  a later ADR must approve flipping it on (it is a trust-surface expansion).
- Because the contract references the locked F-002 schemas by `$ref`, a change to those
  files can break Orchestrator example validation — the CI lane therefore also triggers on
  `Anoryx-Sentinel/contracts/**`.
- The Orchestrator never widens `policy.schema.json`; Delta budgets ride `BudgetLimitPolicy`.

## Rollback

The contract is additive and stands alone (no runtime depends on it yet). Rollback =
revert the O-001 commit (removes `Anoryx-AI-Orchestrator/contracts/`, `docs/adr/0001-*`,
`tests/`, the root audit doc, and the `orchestrator-ci.yml` lane). No data migration, no
deployed surface, nothing else depends on it at O-001 time.
