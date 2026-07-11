# ADR-0042 — Policy-Intake HTTP Endpoint (X-003 loop closure)

- **Status:** Proposed — REQUIRES HUMAN SECURITY SIGN-OFF BEFORE MERGE
- **Date:** 2026-07-11
- **Deciders:** api-architect (contract owner), security-auditor (gate — new ingress into the policy store), policy-engine (F-008 owner), orchestration-hooks (O-004 caller), Affu (solo founder & product owner)
- **Supersedes / amends:** **Reverses one specific decision in ADR-0009 §11 (R1)** — "internal-only (no new HTTP endpoint)". Everything else in ADR-0009 stands unchanged. Governed by `contracts/openapi.yaml`, `contracts/policy.schema.json` (`$id: sentinel:policy:v1`), and `contracts/events.schema.json`, which **win over this ADR on any conflict**.
- **Feature:** X-003 — close the budget-enforcement loop (the ecosystem killer feature) over the wire.

---

## 1. Context

ADR-0009 (F-008) shipped a fully-implemented, fail-closed `intake_policy()` pipeline
(`src/policy/intake.py`) that is the F-008 trust boundary. ADR-0009 §11 (decision **R1**)
deliberately made intake **internal-only**: the sole caller was `sentinel-cli policy push`,
which signs claims and calls `intake_policy()` **directly, in-process — no HTTP**. R1 was an
explicit attack-surface-reduction choice on a zero-trust security product, not an oversight;
F-009 was named as the future owner of any admin REST surface.

Since then, the ecosystem data-flow was wired end-to-end on both sides but never joined:

- **Delta D-005** (`Delta/src/delta/budget_engine/`) — on a budget-cap breach, queues a
  signed-outbox row and its drainer signs + `POST`s the record to Orchestrator.
- **Orchestrator O-004** (`Anoryx-AI-Orchestrator/src/orchestrator/distribution/engine.py`)
  — `drive_distribution()` forwards the **byte-identical** signed record via `httpx` to
  `settings.targets[sentinel_id] + settings.intake_path` (default `/admin/policies/intake`,
  env `ORCH_SENTINEL_INTAKE_PATH`), carrying `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>`.
- **Sentinel F-008** — `intake_policy()` is real and audited, but **no HTTP route is mounted
  at `/admin/policies/intake`** (or anywhere). F-012a's admin API (ADR-0014) added only a
  **read-only** `GET /admin/tenants/{tenant_id}/policies`.

**Net effect:** in a real deployment O-004's distribution `POST` gets a **404** on every
target. The X-003 three-hop proof (cap breach → distribute → real intake → enforcement on the
next request, ~1 s) **cannot close at all** — not because it closes insecurely, but because
there is no wire to close it over. See `docs/followups/x-003-policy-intake-http-endpoint.md`.

## 2. Decision

Add **`POST /admin/policies/intake`** (operationId `adminIntakePolicy`) to
`contracts/openapi.yaml` under the existing `/admin/*` surface, authenticated with the SAME
`adminAuth` bearer scheme (the deploy-injected `SENTINEL_ADMIN_TOKEN` operator secret) as the
rest of the F-012a admin API — the same bearer O-004 already sends. The route is a **thin
ingress wrapper**: it hands the request body UNCHANGED to the existing `intake_policy()`
pipeline and adds **no new business logic and no bypass** of any of its checks.

**This reverses ADR-0009 §11 R1 for this one function, and only this one.** WHY: X-003 requires
the enforcement loop to close **over the wire** between three separately-deployed products
(Delta, Orchestrator, Sentinel). The CLI-only path physically cannot do that — `sentinel-cli`
calls `intake_policy()` in-process on a Sentinel host and has no way for a remote Orchestrator
to reach it. Closing the loop is the entire point of the killer feature; an in-process-only
intake makes it unreachable by design. R1's attack-surface concern is addressed by the threat
model in §4 rather than by keeping the door welded shut.

### 2.1 Request / response mapping (in the spec)

- **Request body:** `SignedPolicyRecord` — the SAME signed record `sentinel-cli policy push`
  already feeds into `intake_policy()` and the SAME bytes O-004 already `POST`s. Not a new
  shape: the authoritative, closed definition remains `contracts/policy.schema.json`
  (`sentinel:policy:v1`, a Draft 2020-12 `oneOf` over the six closed variants). The OpenAPI
  schema documents the signed envelope (the eight signature-covered fields + the compact-JWS
  `signature`) and states that `intake_policy()` re-validates every record against the full
  closed schema — the route relaxes nothing.
- **Responses** map the five `IntakeResult` variants (`src/policy/intake.py` /
  `src/policy/results.py`) to HTTP statuses, each rejection carrying a distinct, stable,
  machine-readable `error_code` on the standard `Error` envelope so callers (O-004) can
  distinguish causes:

  | `IntakeResult`         | HTTP | `error_code`                      |
  |------------------------|------|-----------------------------------|
  | `Accepted`             | 200  | (body: `AdminPolicyIntakeAccepted`, `status: accepted`) |
  | `RejectedSchema`       | 422  | `policy_intake_schema_rejected`   |
  | `RejectedSignature`    | 403  | `policy_intake_signature_rejected`|
  | `RejectedScopeMismatch`| 409  | `policy_intake_scope_mismatch`    |
  | `RejectedReplay`       | 409  | `policy_intake_replay_rejected`   |

  Rationale: 422 for a well-formed-transport record whose policy shape fails Draft 2020-12
  validation; 403 for an absent/forged/unverifiable signature (an authorization failure on the
  content, distinct from the 401 transport-auth failure); 409 for both conflict-with-state
  cases (verified scope vs. body, and replay/rollback), separated by `error_code`. Standard
  admin envelope responses (`400`, `401` `AdminUnauthorized`, `429`, `500`) are reused as-is.

## 3. Consequences

- X-003 becomes a normal builder task: mount a route that calls `intake_policy()` and maps its
  typed result to the statuses above, then replace the in-test accepting shims in O-004's
  `test_o004_e2e.py` / `test_distribution_e2e.py` with the real Sentinel route.
- Sentinel gains its second cross-product write path after the CLI, but through the SAME
  fail-closed function — no second implementation of verification/scope/replay logic to keep in
  sync (single source of intake truth preserved).
- The admin surface grows by one authenticated route; the `Error` `error_code`/`message` enums
  grow by four stable entries. No existing field changes, so no deprecation/sunset is required.

## 4. Threat model

**Who can reach the route.** Only a caller presenting the `adminAuth` bearer — the single
deploy-injected `SENTINEL_ADMIN_TOKEN` operator secret (Vault/KMS-injected; never in
code/config/logs/tests), validated by constant-time compare, fail-closed if unset. A tenant
virtual key is rejected 401; there is no fall-through to tenant scope. This is the SAME
principal already trusted for every other `/admin/*` action, so the route adds **no new
authentication authority** — it reuses an existing one. Protect this secret like the F-008
signing key (ADR-0014).

**What the new ingress exposes.** A network entry point that reaches `intake_policy()`. It does
**not** expose a new trust primitive: `intake_policy()` is itself fail-closed and already
enforces, on EVERY record, in order — Draft 2020-12 schema validation, ES256 compact-JWS
signature verification (no verifying key configured ⇒ reject), the authoritative-scope
resolution from the VERIFIED signature (body IDs are a cross-check only and can never widen
scope; wildcard tenant forbidden), a full-record content-hash integrity check (post-signing
tamper of enforcement fields is rejected), and intake-time replay/rollback rejection
(`policy_version` must be strictly greater than the stored max). A hash-chained audit event is
emitted on every path, including every rejection (the F-004 audit-bypass anti-pattern stays
closed).

**Why this is acceptable (risk reduction, not risk elimination).** Possessing the admin bearer
lets a caller **submit** records for intake; it does **not** let them inject an unsigned,
forged, tampered, or replayed policy, because the bearer is not the F-008 signing key and the
pipeline verifies the signature independently of who delivered the record. An attacker holding
only `SENTINEL_ADMIN_TOKEN` still cannot forge enforcement: the worst they gain over the
prior CLI-only posture is the ability to (a) replay a **validly-signed** record (rejected by
the monotonic replay defense) or (b) submit malformed/forged records (rejected, and audited).
The route therefore adds **ingress, not trust**. Residual exposure is the usual cost of any
authenticated ingress: DoS pressure on the intake path (bounded by the coarse size guard, the
schema's `maxLength`/`maxItems`, and admin rate limits) and the blast radius of a compromised
`SENTINEL_ADMIN_TOKEN` (unchanged in kind — that secret already governs every `/admin/*`
mutation; a compromise there is a break-glass incident regardless of this route).

**This is a NEW ingress path into a zero-trust security product's policy store.** It reverses a
deliberate attack-surface-reduction decision (ADR-0009 §11 R1). Even though the analysis above
concludes the route adds no trust, that judgement warrants **human security sign-off before
merge** — this ADR does not self-approve the reversal.

## 5. Alternatives considered

- **Keep R1 (CLI-only), tunnel policies some other way — REJECTED.** Any alternative (shared
  DB write, message bus, sidecar) still creates a cross-product write path into the policy
  store, but *outside* the audited `intake_policy()` boundary — strictly worse than a thin HTTP
  wrapper around the exact fail-closed function.
- **A brand-new auth scheme for O-004 — REJECTED.** O-004 already sends the admin bearer and
  the path already lives under `/admin/*`; inventing a second admin credential adds a secret to
  manage and a validator to get wrong, for no gain.
- **`Accepted` → 201 Created — CONSIDERED, not chosen.** The neighbouring admin `POST`s
  (approve/deny) return 200; 200 keeps the admin surface uniform. 201 remains defensible if a
  future review prefers create-semantics, but that is a contract change requiring its own ADR.

## 6. Framing note (honest language, per CLAUDE.md)

This route supports **risk reduction** and an **audit-ready** intake trail; it does **not**
"block all attacks" and is not "compliant" or "certified". `intake_policy()` is fail-closed and
high-coverage against the modelled classes (schema/signature/scope/replay), not a guarantee
against every possible abuse.
