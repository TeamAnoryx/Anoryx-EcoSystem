# ADR-0009 — Policy Intake & Enforcement Layer (F-008)

- **Status:** Proposed
- **Date:** 2026-06-17
- **Deciders:** policy-engine (owner / implementer), api-architect (contract / events.schema.json), security-auditor (gate), Affu (solo founder & product owner — approved both scope decisions at the STEP-1 gate)
- **Supersedes / amends:** Extends ADR-0004 (persistence / hash-chain audit), ADR-0005 (tenant isolation / RLS Option α), ADR-0006 (gateway pipeline), ADR-0008 (F-006 router). Governed by `contracts/policy.schema.json` (`$id: sentinel:policy:v1`) and `contracts/events.schema.json`, which **win over this ADR on any conflict**.
- **Feature:** F-008 — verify, persist, and enforce Delta/Orchestrator-signed policies (budget limits, model allow/deny) inside Sentinel. The killer feature of the ecosystem: financial/governance policy enforced in the security path.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

Policies flow **DOWN** into Sentinel from Delta via Anoryx-AI-Orchestrator. F-003/F-003b already
shipped the storage: `policies` (current state, one row per `policy_id`) and `policy_versions`
(append-only history), both under F-003b RLS (migration `0006`), with a **monotonic-version**
guarantee enforced at two layers — `PolicyRepository.upsert_policy` (raises
`PolicyMonotonicityError`) and a `BEFORE INSERT` trigger (`0004`). The `signature` column stores a
compact-JWS string whose **format** is validated but whose **cryptographic validity is explicitly
deferred to F-008** (see `policy.py` docstring and `policy.schema.json` `signature` description).

The contract `contracts/policy.schema.json` defines three variants — `BudgetLimitPolicy`,
`ModelAllowlistPolicy`, `ModelDenylistPolicy` — and is emphatic on two security obligations that are
**runtime** (not schema) concerns and therefore land here in F-008:

1. **Body IDs are NOT authoritative.** The gateway MUST resolve the authoritative scope server-side
   from the **verified** `signature` and **reject** any record whose body IDs disagree (cross-tenant
   poisoning defense; mirrors the F-004 virtual-API-key `id_context_mismatch`, ADR-0002).
2. **Replay/rollback defense.** Intake MUST reject any record whose `policy_version <= the stored
   max` for the same `policy_id`.

F-006 (ADR-0008) built the router seam in `chat_completions.py` and the per-tenant routing policy
(`tenant_routing_policy`). ADR-0008 §4.1 explicitly notes that **Delta-sourced model/budget
constraints are consulted by the router** and are the F-008 responsibility. The placeholder cost
table in `cost.py` and the §7.4 stream-time cost ceiling are the enforcement primitives F-008
reuses for budget enforcement.

### 1.2 Decision (one paragraph)

We add an **internal-only** (no new HTTP endpoint — R1) policy intake function
`src/policy/intake.py::intake_policy(record_json)` that runs a fixed, fail-closed pipeline:
**Draft 2020-12 JSON-Schema validation → ES256 compact-JWS signature verification → scope-resolve-
and-reject (verified claims are authoritative) → intake-time replay/rollback rejection → atomic
persist+audit** on the privileged session. It returns one of five typed results
(`Accepted | RejectedSignature | RejectedScopeMismatch | RejectedReplay | RejectedSchema`) and emits
a hash-chained audit event on **every** path (closing the F-004 audit-bypass anti-pattern). Three
typed variant handlers live in `src/policy/variants/`. At request time, `src/policy/enforcement.py`
reads the active model and budget policies for the request scope (tenant-session, RLS) and the
F-006 router consults them **before** `tenant_routing_policy`: model **deny precedence over allow**,
budget ceilings pre-request and at stream chunk boundaries — all terminal on breach, fail-safe BLOCK
on any evaluation error (R8). Seven new event variants are added to `contracts/events.schema.json`
(api-architect) and wired through the existing single-table audit log using **only existing columns
and the existing `action_taken` enum**, so the **only** new migration is the `ck_eal_event_type`
enum expansion. A CLI (`sentinel-cli`) signs and pushes policies by calling `intake_policy()`
directly. The contract is **locked** as the final F-008 commit.

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-008) |
|---|---|
| `policy.schema.json` shape, `$id: sentinel:policy:v1` (locked at STEP 11) | New `src/policy/` package (intake, crypto, variants, enforcement, audit, CLI) |
| `policies` / `policy_versions` tables, monotonic trigger (`0004`), F-003b RLS (`0006`) | `PolicyRepository` gains 3 read/query methods (no schema change) |
| F-006 router selection **structure** (ADR-0008) | ONE new policy-check step inserted **before** `tenant_routing_policy` consultation |
| F-002 `events.schema.json` existing variants; `ids.md` four IDs | SEVEN new event variants added (api-architect); 4-site enum wiring |
| Hash-chain `CANONICAL_FIELDS`, audit columns (`0005`) | **Unchanged** — new variants reuse `policy_id`/`action_taken`/`violation_type`/`requested_model` |
| `ErrorResponse` envelope / `ERROR_TABLE` wire codes | Policy denials reuse existing `policy_blocked` (403) terminal |
| F-005 fail-safe BLOCK posture (ADR-0007) | Mirrored: any policy-eval error → BLOCK |

---

## 2. Decision: Crypto Primitives — ES256 Compact-JWS (`src/policy/crypto.py`)

- **Algorithm:** ECDSA P-256 (NIST SECP256R1 / prime256v1) over SHA-256 — JOSE `ES256`. Implemented
  directly on the `cryptography` library (added explicitly to `[project.dependencies]`); we do **NOT**
  use `python-jose` for verification (historically lax on `alg`).
- **Compact-JWS form:** `b64url(header) . b64url(payload) . b64url(signature)`, base64url **without
  padding**. Header is exactly `{"alg":"ES256","typ":"JWT"}`.
- **Signed claims payload**: the eight scope claims (`tenant_id, team_id, project_id, agent_id,
  policy_id, policy_version, effective_from, policy_type`) **plus `policy_hash`** — a SHA-256 of the
  canonical full record (every field except `signature`). The scope claims alone do NOT cover the
  enforcement-determining fields (`denied/allowed_model_ids`, `max_*_per_period`, `period`, `scope`,
  `reason`, `effective_until`); `policy_hash` binds the **entire** record to the signature so
  post-signing tampering of any field is detected at intake (`scope_mismatch.content_hash`). This
  makes the contract's "signature over the policy record" literal while keeping the signed payload
  within the `signature` maxLength (4096) — a hash, not the full body, is signed. All serialization
  is canonical (sorted keys, no whitespace) so signers (the CLI now; Delta later) agree byte-for-byte.
- **Signature encoding correctness:** JWS ES256 signatures are **raw 64-byte `R‖S`**, but
  `cryptography` produces/consumes **DER**. `crypto.py` converts with
  `utils.encode_dss_signature` / `decode_dss_signature` on both sign and verify. A signature whose
  raw form is not exactly 64 bytes is rejected before any curve math.
- **Algorithm-confusion defense (threat #3):** the decoded header is checked **first** — any
  `alg != "ES256"` (covering `alg:"none"` and `alg:"HS256"`) is rejected before a key is touched, so
  a symmetric-verify attempt against the public key is impossible.
- **Key loading (load-once, no TOCTOU):** the verifying public key (PEM `SubjectPublicKeyInfo`) is
  read **once** from `POLICY_SIGNING_PUBKEY_PATH` at module import / startup and cached; it is never
  re-read per request. Fail-closed posture:
  - **Env var set but file unreadable/not a P-256 public key** ⇒ **crash at startup** (R3 — a
    misconfigured signing key is a deployment error, not a runtime degrade).
  - **Env var unset** ⇒ no key is loaded; `intake_policy` returns `RejectedSignature` on **every**
    record and logs the misconfiguration. (No intake can ever succeed without a key — fail-closed.)
- **No secret material in logs:** no PEM bytes, no private key, no signature bytes, no raw payload
  appear in any log line (standing guarantee).

`keygen` (dev/test only) produces a PKCS#8 PEM P-256 keypair; production keys are HSM-managed (key
rotation / HSM / KMS are **deferred**, §12).

---

## 3. Decision: Intake Pipeline & Typed Results (`src/policy/intake.py`, `results.py`)

`intake_policy(record_json: str | bytes | dict) -> IntakeResult` runs this **fixed order**, failing
closed at the first gate that fails, and emitting exactly one hash-chained audit event:

1. **Schema (Draft 2020-12).** Validate against `policy.schema.json` via `schema_validator.py`
   (`jsonschema` with the explicit `Draft202012Validator`; **not** Pydantic — R6, parser-differential
   is a security bug per the contract). Failure ⇒ `RejectedSchema` + `policy_intake_rejected_schema`.
   This gate also bounds payload size (the schema's `maxLength`/`maxItems` close the oversized-payload
   vector #9) and rejects `additionalProperties` poisoning (vector #12) and `oneOf` variant confusion
   (vector #10).
2. **Signature.** Verify the compact-JWS over the canonical signed-claims payload with the loaded
   public key (§2). Failure (forged, wrong key, alg-confusion, truncated raw sig) ⇒ `RejectedSignature`
   + `policy_intake_rejected_signature`.
3. **Scope-resolve-and-reject (Decision A, §4).** Treat the **verified** claims as authoritative;
   compare each of the four IDs to the record body. Any disagreement, or a forbidden wildcard
   `tenant_id`, ⇒ `RejectedScopeMismatch` + `policy_intake_rejected_scope_mismatch`.
4. **Replay/rollback (R5).** `get_max_version(policy_id)`; if `policy_version <= max` ⇒ `RejectedReplay`
   + `policy_intake_rejected_replay`. (The `0004` trigger remains the last line of defense.)
5. **Persist + audit (atomic).** On the privileged session, in **one transaction**:
   `upsert_policy(...)` (persisting the **signature-resolved** scope, not the body IDs) **and**
   `AuditLogRepository.append(policy_intake_accepted)`. Both commit or both roll back — there is no
   window in which a policy is stored without its audit row, nor vice versa. Result: `Accepted`.

Typed results are frozen dataclasses carrying only non-sensitive metadata (e.g. `policy_id`,
`policy_version`; replay may carry the current max version for operator triage). **User-facing errors
never leak internal state** (no stored-version disclosure to the caller beyond the typed-result
object used internally); raw disputed body IDs go only to structured logs keyed by `request_id`.

---

## 4. Decision A: Scope Resolution & the Sentinel-ID Wildcard Convention

The contract gives `BudgetLimitPolicy` an explicit `scope` enum but gives the **model** variants
**no scope field** — yet every variant requires all four IDs. To support real-world "tenant-wide" or
"team-wide" model allow/deny while staying contract-faithful (no schema change), F-008 defines a
**documented wildcard convention** for model policies (Affu-approved):

- **Reserved wildcard UUID:** `WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"`.
  - `team_id` / `project_id` set to `WILDCARD_UUID` ⇒ that dimension matches **any** value.
  - `agent_id` is a lowercase **slug** in the contract (not a UUID) and therefore cannot use the
    zero-UUID; its wildcard token is the reserved slug **`all-agents`**. (This is the one asymmetric
    point in the convention; flagged to and accepted by Affu.)
- **`tenant_id` may NEVER be a wildcard.** A wildcard tenant means cross-tenant blast radius and is a
  privilege escalation if the signing key leaks. **Intake hard-rejects** any record whose
  **signature-resolved** `tenant_id == WILDCARD_UUID` → `RejectedScopeMismatch`, audited as
  `policy_intake_rejected_scope_mismatch` with `violation_type="scope_mismatch.wildcard_tenant"` and
  attributed to the system tenant (no real tenant exists). Proven by threat vector **#16**
  (`test_wildcard_tenant_id_rejected`).
- **Matching (model policies only):** policy `P` matches request `R` iff `P.tenant_id == R.tenant_id`
  **and** for each sub-tenant dimension `P.<id> == R.<id>` **or** `P.<id> == wildcard-token`.
- **Specificity** = count of non-wildcard sub-tenant IDs (0–3).
- **Resolution:** **DENY is absolute** — if **any** matching `ModelDenylistPolicy` lists `R.model`,
  the request is denied, overriding any allow (contract §ModelDenylistPolicy). Otherwise **ALLOW**
  uses the **highest-specificity** matching `ModelAllowlistPolicy` (ties → highest `policy_version`,
  a monotonic recency proxy, then `policy_id`); if that allowlist excludes `R.model` → deny. An
  allow-list past its optional `effective_until` is excluded (expired; deny-lists never expire). If
  **no** allowlist matches, the request is **not allow-constrained** (model policies are opt-in;
  absence ≠ deny — mirrors F-006's generous routing default).
- **BudgetLimitPolicy is unaffected** by the wildcard convention — it carries an explicit `scope`
  that selects the aggregation level (§10); its four IDs identify which tenant/team/project/agent.

The reserved UUID has a **dual documented purpose**: (a) the sub-tenant wildcard above, and (b) the
system-scoped audit owner for pre-verification rejections (§7).

---

## 5. Decision: Replay / Rollback Defense (defense-in-depth)

| Layer | Mechanism | F-008 role |
|---|---|---|
| Intake (NEW, first line) | `get_max_version(policy_id)`; reject `version <= max` → `RejectedReplay` + audit | added in F-008 (R5) |
| Repository | `upsert_policy` re-checks `version > current_max` → `PolicyMonotonicityError` | existing (F-003) |
| Database | `BEFORE INSERT` trigger on `policy_versions` (`0004`) | existing (last line) |

The intake-time check produces the **typed result + audit event** before any DB write; the
repository and trigger remain as belt-and-suspenders so a future caller that bypasses intake still
cannot roll a policy back. Replay rejection is audited as `policy_intake_rejected_replay` attributed
to the signature-resolved tenant (a replayed record still has a valid signature).

---

## 6. Decision: Three Variant Handlers & Request-Time Enforcement

`src/policy/variants/` holds typed (Pydantic) views over the validated record — **no `eval`/`exec`**;
variants are data, not code. `src/policy/enforcement.py` holds the request-time evaluators (DB reads
on the **tenant session**, RLS-scoped), keeping all F-008 logic **out** of the F-006 files (R7).

- **`ModelDenylistPolicy` / `ModelAllowlistPolicy`** → `evaluate_model_policies(scope, model)`:
  wildcard-aware match (§4), deny-precedence absolute, most-specific allow wins. Returns an
  `Allow | Deny(policy_id, reason)` decision.
- **`BudgetLimitPolicy`** → `evaluate_budget_pre_request(scope, est_tokens, est_cost)` and a
  stream-time ceiling check. Period bucketing per §10.

**Router integration (FILE:LINE, minimal insertions):**
- `router/selection.py`: a model-policy + budget check is inserted **before** `_resolve_policy` is
  consulted — `route_non_stream` (before `selection.py:171`) and `route_stream` (before
  `selection.py:323`). A deny is **terminal** (no fallback): emit `policy_decision_deny`, then
  `GatewayError("policy_blocked")` (non-stream) / `_error_frame("policy_blocked")` (stream), exactly
  mirroring the existing allow-list terminal at `selection.py:127-137`. A matched **allow** emits
  `policy_decision_allow`. No policy match ⇒ no policy_decision event (no noise).
- `StreamRouteResult` (`selection.py:47`) is extended with budget fields
  (`budget_max_tokens`, `budget_used_baseline_tokens`, `budget_max_cost_cents`,
  `budget_used_baseline_cents`, `budget_policy_id`), populated at commit alongside the existing
  `cost_ceiling_cents`.
- `routes/chat_completions.py:594`: a parallel budget check is added next to the existing §7.4
  stream cost-ceiling block in `_generate` — `baseline + running tokens/cost > ceiling` ⇒ emit
  `policy_decision_deny`, yield the `policy_blocked` SSE frame, close **without** `[DONE]`. This is
  the same chunk-boundary primitive that closed the F-006 stream-ceiling anti-pattern; proven by
  threat vector #14.
- `router/cost.py` stays **pure** (pricing only); reused via `estimate_pre_request` /
  `estimate_from_tokens`. Budget DB logic lives in `enforcement.py` (KISS; no DB in `cost.py`).

**Fail-safe (R8):** any exception during policy evaluation in the request path → fail-safe **BLOCK**
(`policy_blocked`/`internal_error`), never silent pass — mirrors the F-005 hook fail-safe.

---

## 7. Decision: Audit Events (7 new variants) + Decision B (attribution) + 4-site consistency

Seven new event variants are added to `contracts/events.schema.json` (api-architect, §13). They are
designed to be persistable with **only existing audit-log columns** and the **existing `action_taken`
enum**, so the F-006 4-site-drift risk collapses to a **single enum** change.

| event_type | action_taken | reused column(s) | emitted by |
|---|---|---|---|
| `policy_intake_accepted` | `logged` | `policy_id` | intake (atomic w/ persist) |
| `policy_intake_rejected_signature` | `blocked` | — | intake |
| `policy_intake_rejected_scope_mismatch` | `blocked` | `violation_type` (dimension slug) | intake |
| `policy_intake_rejected_replay` | `blocked` | `policy_id` | intake |
| `policy_intake_rejected_schema` | `blocked` | — | intake |
| `policy_decision_allow` | `logged` | `policy_id`, `requested_model` | enforcement (router) |
| `policy_decision_deny` | `blocked` | `policy_id`, `requested_model` | enforcement (router) |

The **outcome/reason is encoded in the `event_type` itself**; where a finer reason is useful, the
bounded existing `violation_type` slug carries it (e.g. `scope_mismatch.tenant`, `model_denied`,
`budget_exceeded`). Because only `logged`/`blocked` are used, `ck_eal_action_taken` is **unchanged**
and `CANONICAL_FIELDS` (hash chain) is **unchanged**.

**Decision B — audit-row `tenant_id` attribution (no new columns; raw disputed IDs never chained):**

1. **Schema rejection** (no signature parsed) → `WILDCARD_UUID` (system tenant).
2. **Signature verification failed** (no resolvable tenant) → `WILDCARD_UUID` (system tenant).
3. **Signature valid, body IDs disagree** (incl. forbidden wildcard tenant) → the
   **signature-resolved** tenant (the wildcard-tenant case has no real tenant ⇒ system tenant).

Replay and Accepted both have a valid signature ⇒ signature-resolved tenant. This reuses the
established `build_usage_event` precedent (all-zero IDs for pre-auth rejections,
`gateway/middleware/audit.py`). **Raw disputed body IDs are never written to the chain** (cross-tenant
hygiene); the full before/after diff goes to structured logs keyed by `request_id`.

**4-site consistency (mirror F-006 `routing_decision`):** (1) `events.schema.json` `oneOf` + 7
`$defs` (api-architect); (2) `VALID_EVENT_TYPES` (`events_audit_log.py:40`); (3)
`ACTION_TAKEN_BY_EVENT_TYPE` (`events_audit_log.py:57`); (4) `ck_eal_event_type` CHECK via migration
`0008_policy_event_variants.py` (DROP + ADD the named constraint with the expanded enum) — the
**only** new migration F-008 introduces.

**Audit-failure posture:** intake accept audit is **atomic** with persist (cannot diverge). Intake
**rejection** audit must succeed; if it fails it is logged ERROR and the rejection is still returned
(the security outcome — rejection — is preserved). Enforcement `policy_decision_*` events follow the
F-006 `routing_decision` best-effort precedent (emit, log ERROR on failure, never convert the
outcome); the terminal block is enforced independently and the request's terminal `usage` record
remains the fail-safe audit gate.

---

## 8. Threat Model — 16 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting the typed rejection / terminal block **and** the
correct audit event **and** that no state was poisoned — not merely "raises". Tests:
`Anoryx-Sentinel/tests/policy/test_threat_model.py` (intake + enforcement), with crypto/intake
specifics also in `test_crypto.py` / `test_intake_signature.py`.

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | Forged signature (random sig segment) | ES256 verify fails | `RejectedSignature` |
| 2 | Wrong signing key | verify against pinned pubkey fails | `RejectedSignature` |
| 3 | Algorithm confusion (`alg:none`, `alg:HS256`) | header `alg` checked first; only `ES256` allowed | `RejectedSignature` |
| 4 | Cross-tenant scope widening (sign A, body B) | scope-resolve-and-reject | `RejectedScopeMismatch` |
| 5 | Cross-team scope widening | scope-resolve-and-reject | `RejectedScopeMismatch` |
| 6 | Replay (same version) | intake `version <= max` | `RejectedReplay` |
| 7 | Rollback (older version after newer) | intake `version <= max` | `RejectedReplay` |
| 8 | Truncated signature (strip a segment) | schema compact-JWS pattern | `RejectedSchema` |
| 9 | Oversized payload (100 KB) | schema `maxLength`/`maxItems` bounds | `RejectedSchema` |
| 10 | Wrong `policy_type` for variant fields | schema `oneOf` | `RejectedSchema` |
| 11 | Missing required field (drop `effective_from`) | schema `required` | `RejectedSchema` |
| 12 | `additionalProperties` poisoning (`admin_override`) | schema `additionalProperties:false` | `RejectedSchema` |
| 13 | Allow+deny conflict (both list model X) | deny precedence absolute | DENY (`policy_decision_deny`) |
| 14 | Budget exhaustion mid-stream | chunk-boundary ceiling check | stream terminated, no `[DONE]` |
| 15 | Period boundary (23:59 → 00:01) | `date_trunc` bucket reset | new-bucket request allowed |
| 16 | **Wildcard `tenant_id`** (signature-resolved tenant == `WILDCARD_UUID`) | intake hard-reject | `RejectedScopeMismatch` + system-tenant audit |

---

## 9. Decision: Sessions / RLS Posture (verified against `0006`)

- **Intake writes + ALL audit appends → `get_privileged_session`** (owner / BYPASSRLS). Intake is
  privileged until the signature resolves the authoritative tenant; the resolved tenant goes into the
  policy row's `tenant_id` for RLS to enforce on subsequent reads (R10). The `0004` monotonic trigger
  is role-independent, so replay defense holds on privileged inserts. `AuditLogRepository.append`
  asserts a privileged session.
- **Request-time enforcement reads → `get_tenant_session(tenant_id)`** (sentinel_app / NOBYPASSRLS).
  `0006` grants `sentinel_app` `SELECT` on `policies`, `policy_versions`, and `events_audit_log`, all
  RLS-scoped by the strict `NULLIF` predicate — so active-policy reads and the budget `SUM` over
  usage rows are tenant-isolated by construction. `get_active_policies_for_scope` adds a
  defense-in-depth `WHERE tenant_id = caller_tenant_id` on top of RLS (mirrors
  `PolicyRepository.get_by_id` and `TenantRoutingPolicyRepository.get_for_tenant`).

---

## 10. Decision: Budget Period Bucketing (no new table)

`BudgetLimitPolicy` `scope ∈ {tenant,team,project,agent}` selects the aggregation level; `period ∈
{hourly,daily,monthly}` selects the window. "Used" is computed over the existing `events_audit_log`
`usage` rows — **no new table**:

```sql
SELECT COALESCE(SUM(tokens_in + tokens_out), 0), COALESCE(SUM(cost_estimate_cents), 0)
FROM events_audit_log
WHERE event_type = 'usage'
  AND tenant_id = :tenant_id              -- + team/project/agent per scope
  AND (event_timestamp)::timestamptz >= date_trunc(:period, now() AT TIME ZONE 'UTC');
```

`event_timestamp` is an RFC3339 `String(64)`; the `::timestamptz` cast parses it (the trailing `Z`
is valid). Pre-request: `used + estimate` vs `max_tokens_per_period` / `max_cost_cents_per_period`.
Stream-time: `baseline(used at entry) + running` vs the ceiling at each chunk boundary.

**Honest limit (CLAUDE.md):** "used" reflects only **persisted** usage, so concurrently in-flight
requests are not yet counted — this is a **client-side budget estimate**, not an authoritative bill,
consistent with the contract's own language on `max_cost_cents_per_period`.

---

## 11. Decision: CLI, Packaging & Dependencies

- **CLI (`src/policy/cli.py`, entry-point `sentinel-cli`):**
  `sentinel-cli policy keygen --out private.pem --pub-out public.pem` (dev/test P-256 PKCS#8 keypair);
  `sentinel-cli policy push --file policy.json --key private.pem` signs the claims and calls
  `intake_policy()` **directly** — no HTTP (R1; F-009 owns the admin REST API).
- **`pyproject.toml`:** add `cryptography>=42,<46` to `[project.dependencies]` (explicit, not
  transitive); move `jsonschema[format]>=4.22,<5` into `[project.dependencies]` (runtime need); add
  `[project.scripts] sentinel-cli = "policy.cli:main"`; ensure src-layout package discovery exposes
  the new `policy` package for `pip install -e .` (verify, add `package-dir`/`packages.find` only if
  absent, then re-run the full suite to confirm no import regression).

---

## 12. Alternatives Considered & Honest Deferrals

- **OPA / Rego / external policy DSL — REJECTED.** The contract defines exactly three closed,
  signed JSON variants; OPA would add a second policy language, a parser-differential surface, and a
  runtime dependency on a process the gateway must trust, for zero added expressiveness over the
  contract. Enforcement is a handful of typed comparisons — a DSL is unjustified complexity (KISS).
  The earlier charter framing around OPA is superseded.
- **Pydantic for the schema-validation step — REJECTED.** Pydantic does not honor JSON Schema Draft
  2020-12 exactly; a parser differential between Sentinel, Orchestrator, and Delta is a **security
  bug** per the contract (R6). We validate with `jsonschema`'s explicit `Draft202012Validator` and
  use Pydantic only as a typed **view** over already-validated records.
- **`python-jose` for JWS — REJECTED** in favor of building compact-JWS on `cryptography` directly,
  so the `alg` allow-list is ours and algorithm confusion is structurally impossible (§2).
- **New audit columns for scope detail — REJECTED** (Decision B): would require a second migration and
  would push cross-tenant IDs into the chain. Reason encoded in `event_type` + `violation_type`.
- **Hierarchical model-policy scope as a contract field — DEFERRED to v2.** The wildcard convention
  (§4) provides umbrella + override semantics today without a schema change.
- **Hot-reload caching — DEFERRED.** F-006 already reads per-request from the DB; caching is a perf
  optimization for later.
- **Key rotation / HSM / KMS — DEFERRED.** A single static verifying key from env path is v1 scope.

---

## 12.1 Known Limitations

**Canonicalization scheme is not JCS RFC 8785.** The full-record content hash (`policy_hash`,
`crypto.policy_content_hash`) canonicalizes with **sorted keys + compact separators + UTF-8** via
Python `json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")` — **not** JCS
RFC 8785. It is deterministic within the Python signer/verifier pair shipped in F-008 (the CLI signs
and intake verifies with the identical function, so the bytes match byte-for-byte). Cross-language
signers (the future Delta integration) MUST reproduce these exact bytes — including Python number
representation (e.g. `1.0` stays `1.0`, not JCS `1`) and `\uXXXX` non-ASCII escaping
(`ensure_ascii=True`) — OR the canonicalizer must be migrated to a JCS library before Delta
integrates. A mismatch fails closed (every policy is rejected on `content_hash`), so this is a
**documented coupling constraint, not an F-008 bug**. The next task that introduces a non-Python
signer owns the JCS migration decision.

**Audit-write-failure has no observable counter (shared with F-004).** On an audit append failure,
intake emits an ERROR-level structured log (`policy_intake_reject_audit_failed`) but does not
increment a Prometheus counter; F-004's terminal audit wrapper has the identical gap. Log-based
alerting works today; metric-based alerting is deferred to a cross-feature observability task
(`docs/followups/observability-audit-counters.md`).

---

## 13. Contract Changes

**`contracts/events.schema.json` (api-architect, STEP 4):** add seven closed, fully-bounded variants
to `oneOf` + `$defs` — `policy_intake_accepted`, `policy_intake_rejected_signature`,
`policy_intake_rejected_scope_mismatch`, `policy_intake_rejected_replay`,
`policy_intake_rejected_schema`, `policy_decision_allow`, `policy_decision_deny`. Each carries the
four stable IDs + `event_id`/`event_timestamp`/`request_id` + `policy_id` (where applicable, format
uuid) + `action_taken` (enum `{logged,blocked}` only) + optional `violation_type` (existing slug
pattern) + `requested_model` (decision variants). No existing variant changes.

> **Process note (mirrors ADR-0008 §14):** edits to `contracts/` are gated by
> `.claude/hooks/protect-paths-and-secrets.sh`, which authorizes the write only when the agent
> identity is `api-architect` (read from `ANORYX_ACTIVE_AGENT`). STEP 4 dispatches the **api-architect
> agent** to make this edit; if the env identity is not provisioned, the patch is recorded for verbatim
> re-apply under that identity. The protection logic is never modified or weakened.

**`contracts/policy.schema.json` (STEP 11, final commit):** prepend
`// LOCKED at F-008 commit <sha>. Any change requires a new $id (sentinel:policy:v2) and a migration
plan.`

---

## 14. Consequences

### 14.1 Positive
- The contract's two runtime obligations (scope-resolve-and-reject, replay defense) are now enforced;
  the contract can be **locked**.
- Atomic persist+audit structurally eliminates the F-004 audit-bypass class for intake accepts; every
  rejection path is independently proven to audit.
- Delta's downstream integration path is preserved: policies it signs are verified and enforced;
  events it consumes gain seven precise variants without disturbing existing ones.
- Only **one** new migration (an enum widen) and **no** new tables / columns / hash-chain changes —
  minimal blast radius on the most security-critical persistence in the system.

### 14.2 Negative / costs
- The wildcard convention is a documented convention layered on the contract, not a schema field; it
  must be honored consistently by Sentinel and (eventually) by Delta when authoring model policies.
  The `agent_id` slug-wildcard asymmetry is the sharp edge.
- "Used" budget is a persisted-usage estimate (in-flight not counted) — acceptable for a client-side
  estimate, documented as such.
- Seven coordinated edit sites for the event variants (mitigated by the 4-site discipline + tests).

### 14.3 Rollback
- **Pre-lock:** revert the `task/F-008-policy-engine` branch; migration `0008` downgrades by
  restoring the prior `ck_eal_event_type` enum (no data loss — it only widens an allowed set).
- **Post-lock (STEP 11):** the schema `$id` is frozen at `sentinel:policy:v1`; any change requires
  `sentinel:policy:v2` + a migration plan. This is intentional irreversibility — the lock is the
  point. Risk mitigation: the 16-vector adversarial suite + code-reviewer + security-auditor gates run
  **before** the lock; the contract is only locked after STEP 10 verification passes.
