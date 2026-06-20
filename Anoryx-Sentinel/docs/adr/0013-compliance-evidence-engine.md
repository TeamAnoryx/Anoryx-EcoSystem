# ADR-0013 — Compliance Evidence Engine (F-011)

- **Status:** Proposed
- **Date:** 2026-06-20
- **Deciders:** compliance-engine (owner / implementer), api-architect (contract / `openapi.yaml` + `events.schema.json`), persistence (migration `0012`, `events_audit_log` constants), security-auditor (extended-adversarial gate), Affu (solo founder & product owner — resolved the four STEP-0 forks during planning: F1 tenant self-service auth, F2 two-layer tamper-evidence, F3 signed-JSON-ZIP, F4 read-only live query; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0003 (persistence / hash-chain audit — F-011 **reads** `events_audit_log`, embeds its `row_hash`es as evidence, never mutates it), ADR-0005/0006 (tenant isolation / RLS Option α — F-011 **reuses** the `sentinel_app` RLS path for tenant-scoped reads), ADR-0009 (F-008 policy intake — F-011 **reuses** the ECDSA/JWS signing primitive from `src/policy/crypto.py`; intake logic unchanged), ADR-0010 (F-007 classifier — F-011 only **reads** its emitted events as evidence), ADR-0011 (F-009 observability — F-011 **reads** its metrics/events; rate limiting unchanged). Governed by `contracts/events.schema.json` and `contracts/openapi.yaml`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-011 — turn Sentinel's existing controls into auditor-presentable, tamper-evident compliance evidence for SOC 2 Type II and ISO 27001 Annex A. Read-only over the audit trail; no new auth primitive; honest gap reporting.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

Sentinel has the **controls** an auditor cares about but no way to **present them as
evidence**. `src/compliance/` is empty (`__init__.py` only). The raw material already
exists:

- **Hash-chained audit** (ADR-0003): `events_audit_log` is append-only with a SHA-256
  chain (`src/persistence/hash_chain.py`: `GENESIS_HASH`, `compute_row_hash`,
  `verify_row_hash`, canonical-JSON = `json.dumps(sort_keys=True, separators=(",",":"),
  ensure_ascii=False)`). The repository (`audit_log_repository.py:211`,
  `AuditLogRepository.append()`) is **append-only — it has no update or delete method**
  and requires a privileged session.
- **RLS tenant isolation** (ADR-0005/0006): app role `sentinel_app` (NOBYPASSRLS); GUC
  `app.current_tenant_id` with a `NULLIF(current_setting(...,true),'')` fail-closed
  predicate. A tenant-scoped read returns **zero** rows for any other tenant at the DB
  layer, not via application filtering.
- **ECDSA signing** (ADR-0009 / F-008): `src/policy/crypto.py` signs records as ES256
  compact-JWS with a **file-based** key (`POLICY_SIGNING_PUBKEY_PATH`), binding the full
  record via a content hash. **No Vault, no RSA** anywhere in `src/`.
- **Events 4-site discipline**: `VALID_EVENT_TYPES` (`events_audit_log.py:40`, 25 types),
  `ACTION_TAKEN_BY_EVENT_TYPE` (`:78`), `contracts/events.schema.json` (`oneOf` + per-
  variant `const`), and `ck_eal_event_type` (widened in lockstep `0005→0007→0008→0010→
  0011`; **`0011` is head**). A `ComplianceCheckedEvent` variant + `framework` /
  `control_id` / `status` columns **already exist** (framework enum
  `[SOC2,GDPR,HIPAA,EU_AI_ACT]`).
- **Auth**: Bearer **virtual-key only, tenant-scoped**. There is **no admin/role/scope
  mechanism**. `/metrics` is the only unauthenticated route (`_AUTH_EXEMPT_PATHS`).

### 1.2 Decision (one paragraph)

We add a **read-only** compliance evidence engine in `src/compliance/`. Framework→control
mappings live as **version-controlled YAML** (`frameworks/soc2.yaml`,
`frameworks/iso27001.yaml`) validated by a strict loader (`mapping.py`), never hardcoded
in Python (**F5**). Evidence generation (`evidence.py`) is a **tenant-scoped aggregate
read** over `events_audit_log` for a window `[t0,t1]` — event counts by type/control plus
the window chain-tip — issuing **zero writes** to that table (**F4**, **R1**). The read
runs under the **`sentinel_app` RLS role with GUC = the caller's tenant_id**; the caller
is the **authenticated tenant** acting on its **own** data via the existing Bearer
virtual key — F-011 introduces **no new auth primitive** (**F1**); operator/cross-tenant
generation is deferred to F-012. Gap analysis (`gap_analysis.py`) reports each framework
control as `passed` / `gap` / `not_covered` and a readiness score = `passed / applicable`
with **no weighting and no inflation**; an unmapped control is **always** reported
"not covered" (**R8**). Evidence packs (`pack.py`) are **two-layer tamper-evident**
(**F2**): they **embed** the source events' F-003 `row_hash`es + chain-tip (source-event
integrity, offline-verifiable) **and** are **ECDSA-signed as a whole** via the F-008
`crypto.py` ES256/JWS path over a canonical pack (full-record binding). Export is a
**deterministic, byte-reproducible ZIP** (canonical JSON + JWS signature + bundled public
key + manifest) — **F3**; PDF is deferred. Two new event variants
(`compliance_evidence_generated`, `compliance_pack_exported`, both `action_taken='logged'`,
carrying the caller's **real** four IDs) are added 4-site with one reversible migration
(`0012`). Two new tenant-Bearer-authenticated endpoints are added to `openapi.yaml`
(api-architect). Every artifact carries the mandatory disclaimer: *"Automated evidence for
audit preparation. Certification requires an accredited auditor."*

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-011) |
|---|---|
| `events_audit_log` rows, columns, hash chain, append-only writer — **R1/R3** | F-011 **reads** the table (new read path in `evidence.py`); embeds `row_hash`es as evidence |
| `AuditLogRepository` (append-only; no update/delete) — R3 | **Not modified.** Reused only to *append* the 2 new meta-audit events |
| F-003b RLS role/GUC, F-007 classifier, F-008 intake, F-009 limiter logic — R3 | **Read-only consumers.** No logic touched |
| `src/policy/crypto.py` ES256/JWS primitive | **Reused** (not modified) to sign packs; distinct key material |
| Existing `events.schema.json` variants (incl. `ComplianceCheckedEvent`) | **TWO new variants ADDED** (api-architect); no existing variant changed |
| `events_audit_log` columns | **No new columns.** The 2 variants use `action_taken='logged'`; forensic fields ride the Streams JSON only |
| Auth model (tenant Bearer, no admin scope) | **Unchanged.** Compliance endpoints reuse tenant Bearer auth; no new privilege primitive (F1) |
| `policy.schema.json` (LOCKED at F-008) | Untouched |
| `ck_eal_event_type` widen pattern (head `0011`) | Migration `0012` widens it with 2 variants (DROP+ADD, reversible) |

---

## 2. Decision D1 (F1): Tenant self-service auth + RLS-scoped read

The dispatch's R5 ("compliance endpoints require privileged/admin scope") assumed an
admin primitive that **does not exist** — Sentinel has only tenant-scoped Bearer virtual
keys. Rather than invent an auth primitive (its own threat model, its own audit surface —
that is F-012's job), F-011 makes compliance **tenant self-service**:

1. **Endpoints authenticate with the existing tenant Bearer virtual key**, through the
   same middleware as every tenant-scoped route. Unauthenticated → **401** (vector 13).
   These endpoints are **not** in `_AUTH_EXEMPT_PATHS` (they are not like `/metrics`).
2. **The tenant is server-resolved from the verified key**, never a client-supplied
   header or query parameter (`contracts/ids.md`: attribution is always the server-
   resolved value). There is **no `tenant_id` request parameter** a caller could set to
   another tenant.
3. **The evidence read runs under the `sentinel_app` RLS role with GUC =
   `app.current_tenant_id` set to the caller's tenant_id** — a tenant-A request returns
   **zero** tenant-B rows at the database layer even if the query body is manipulated
   (vectors 7, 10). This is the **same** privileged-app-role-with-RLS pattern F-003b
   established; F-011 adds no bypass path.

**Corrected R5 (recorded for the security-auditor and PR gates):** *compliance endpoints
require tenant Bearer auth; evidence is generated over the caller's own tenant data via
RLS; operator/cross-tenant generation is deferred to F-012.* This is a deliberate
constraint that keeps the compliance feature's trust model **identical** to the rest of
the tenant-scoped surface.

---

## 3. Decision D2 (F4): Read-only live query as the evidence source

Evidence generation is a **tenant-scoped aggregate read** over `events_audit_log` for the
window `[t0,t1]`:

- Per mapped Sentinel control, count the control's evidence events in `[t0,t1]`
  (e.g. `pii_blocked` for a PII-masking control, `policy_decision_*` for access control,
  `injection_detected` / `prompt_injection_detected_ml` for input-defense controls), plus
  read the window **chain-tip** `row_hash` (the highest-`sequence_number` row visible in
  the window) for embedding (D5).
- The query is issued through the RLS-scoped app-role session (D1). **No INSERT / UPDATE /
  DELETE appears anywhere in the projection path** — R1 holds by construction and is
  proven by a connection-level before-execute guard (vector 1), not merely "no error".

**No materialized projection table and no cache in v1.** A `compliance_evidence` rollup
table would add a write path, sync logic, staleness, and a second tamper surface —
weakening the R1 story for marginal benefit at design-partner scale (O(1–10) tenants).
Caching is worse in a compliance context: stale evidence = wrong evidence = the R8
over-claim risk. Both are documented future optimizations (§Scaling), to be designed with
their own threat model only when window-query cost is **empirically** a problem.
**Honest characteristic (documented, not hidden):** large-window generation is
O(events in window).

---

## 4. Decision D3 (F5): Control mapping as version-controlled YAML

Framework→control mappings live as **YAML in the repo** (`src/compliance/frameworks/
soc2.yaml`, `iso27001.yaml`), validated against `mapping.schema.json` by `mapping.py`.
YAML (not a DB table, not hardcoded Python) because the mapping is a **human-auditable
artifact** an auditor or Affu reviews in a PR diff, with comments explaining **why** each
Sentinel control maps to each framework control.

Each YAML entry (shape enforced by the loader):

```yaml
framework: SOC2
framework_version: "2017-TSC-rev2022"
controls:
  - control_id: CC7.2                       # framework-specific id
    title: "System monitoring for anomalies"
    sentinel_controls: [injection_detection, shadow_ai_egress]   # mapped capability ids
    evidence_event_types: [injection_detected, prompt_injection_detected_ml, shadow_ai_detected_outbound]
    rationale: "Gateway flags and audits injection + shadow-AI egress attempts."
  - control_id: CC9.9
    title: "Vendor risk — N/A for gateway"
    status_override: not_applicable          # explicit, never silent
  - control_id: A.5.30                        # ISO example with NO Sentinel mapping
    title: "ICT readiness for business continuity"
    sentinel_controls: []                    # -> not_covered (R8); never faked
```

The loader **fails closed** on a malformed mapping (unknown keys, missing `control_id`,
an `evidence_event_types` value not in `VALID_EVENT_TYPES`). `framework_version` is pinned
in the YAML and copied verbatim into every artifact.

---

## 5. Decision D4: Gap analysis + readiness score (honest, no inflation)

For each framework control, status is exactly one of:

- **`passed`** — mapped to ≥1 Sentinel control **and** evidence is present (≥1 mapped
  evidence event observed in `[t0,t1]`, and/or a config-state check is active);
- **`gap`** — mapped but **no** evidence in the window;
- **`not_applicable`** — explicit `status_override` in the YAML (never silent);
- **`not_covered`** — **no** Sentinel mapping in the YAML (`sentinel_controls: []`).
  This is reported as a gap **and never fabricated as coverage** (R8, vector 14).

`readiness = passed / applicable`, where `applicable = total − not_applicable`. It is a
**plain ratio** plus the **full** `passed` / `gap` / `not_covered` breakdown — **no
weighting, no rounding-up, no hiding `not_covered`**. The score is **recomputable** from
the gap analysis alone (vector 15). Every evidence summary and pack carries the
**mandatory disclaimer** verbatim: *"Automated evidence for audit preparation.
Certification requires an accredited auditor."* — and uses **"audit-ready", never
"compliant"** (CLAUDE.md honest-language rule).

---

## 6. Decision D5 (F2): Two-layer tamper-evidence

A detached evidence pack must be verifiable **offline** by an auditor with no access to
the live Sentinel system (R4). One signature alone is insufficient: it proves the pack
wasn't altered, but not that the underlying audit events are chain-intact. So the pack has
**two layers**:

1. **Layer A — embedded F-003 source-event integrity.** The pack embeds, for the window,
   the relevant `row_hash`es and the window **chain-tip** hash (plus the `GENESIS_HASH`
   reference). An auditor recomputes the chain offline with `verify_row_hash` semantics
   and confirms the embedded hashes form a valid F-003 chain — proving the **source
   events** are untampered, **without a live DB** (vector 5).
2. **Layer B — ECDSA pack signature.** The **canonical** pack record (including Layer A's
   embedded hashes) is signed **as a whole** via the **F-008 `crypto.py` ES256 compact-JWS
   path** — proving the **exported pack itself** is untampered post-export (vector 2).
   The signature covers the **full record** (the F-008 content-hash-binding lesson:
   altering any embedded chain hash invalidates the signature — vector 6).

**Canonicalization:** reuse the **same** canonical-JSON scheme F-008 uses for signature
binding (the `sort_keys=True, separators=(",",":"), ensure_ascii=False` UTF-8 scheme that
`hash_chain.py` also uses). There is **one** canonicalization path — `pack.py` calls the
existing primitive, it does **not** introduce a second canonicalizer.

**Keys (no Vault — F-008 precedent wins over the evidence-gen skill's RSA+Vault
suggestion):** the pack signing key is **file-based and deploy-injected**
(`COMPLIANCE_PACK_SIGNING_KEY_PATH` private, `COMPLIANCE_PACK_PUBKEY_PATH` public),
identical in model to F-008's `POLICY_SIGNING_*`. Distinct key material from policy
signing (different trust domain). The **public key is bundled into the ZIP** so an offline
auditor verifies Layer B with no live access. `pack.py` reuses the **low-level ES256
sign/verify primitives** from `crypto.py`, not the policy-claims wrapper.

---

## 7. Decision D6 (F3): Signed-JSON ZIP export, deterministic

The export artifact is a **ZIP** containing:

- `evidence.json` — the **canonical** evidence record (the signed payload): metadata
  (`tenant_id`, `framework`, `framework_version`, `window {t0,t1}`, `generated_at`,
  `sentinel_version`), per-control artifacts, the readiness block, the gap list, and
  Layer-A embedded chain hashes;
- `evidence.json.jws` — the Layer-B ES256 compact-JWS signature over the canonical bytes;
- `pubkey.pem` — the bundled public key for offline verification;
- `manifest.json` — file list + the **canonical content hash that was signed** (so the
  auditor knows exactly which bytes the signature covers) + the disclaimer.

**Deterministic build (vector 3):** every `ZipInfo` uses a **fixed `date_time`** (the ZIP
epoch `(1980,1,1,0,0,0)`, never "now"), a **stable file order**, and fixed compression, so
the same `[tenant, window, controls]` inputs produce a **byte-identical** archive — not
merely equivalent JSON. (`generated_at` inside `evidence.json` is derived from the window,
not wall-clock, to preserve reproducibility.)

**PDF is deferred** (documented extension point). PDF generation is non-deterministic
(breaks R4 byte-reproducibility), adds a heavy native dependency (reportlab/weasyprint —
against the F-010 slim-image effort), and a human-readable rendering belongs in F-012,
where a frontend renders the signed JSON on demand without being the tamper-evident
artifact.

---

## 8. Decision D7: Event variants (2) + tenant attribution + the R1 nuance

Two new variants, both `action_taken='logged'` (so `ck_eal_action_taken` is **unchanged**),
reusing existing columns (**no new event-table column**):

| event_type | emitted when | IDs | carries (Streams JSON only) |
|---|---|---|---|
| `compliance_evidence_generated` | after an evidence summary is generated | the caller's **real** four IDs (`agent_id='compliance-engine'`) | `framework`, `framework_version` |
| `compliance_pack_exported` | after a pack ZIP is exported | the caller's **real** four IDs (`agent_id='compliance-engine'`) | `framework`, `framework_version`, `pack_content_hash` (the signed canonical hash, for forensic linkage) |

**Attribution = real tenant_id (not `WILDCARD_UUID`).** These are **tenant-scoped actions**
(a tenant generating evidence over its own data), so they carry the caller's real four IDs
resolved from the Bearer key. The dispatch floated a "4th `WILDCARD_UUID` use" — it is
**considered and rejected**: F-011's events are tenant-attributed, unlike F-009's
system-health-loop events. `contracts/ids.md` needs **no** new reserved-value use.

**Forensic fields ride the Streams JSON, not an audit column** (the ADR-0011 §7
precedent): the audit **row** carries `event_type` + `action_taken='logged'` + four IDs +
timestamps (`framework` populated in the **existing** nullable `framework` column);
`framework_version` and `pack_content_hash` appear **only** in the
`contracts/events.schema.json` variant for the bus. `request_id` is the forensic join key.
No `events_audit_log` column is added.

**The R1 nuance (must be explicit to the security-auditor).** R1 = "never **mutate** the
audit trail." The evidence **read/projection** path issues **zero** writes (vector 1).
Recording `compliance_evidence_generated` / `compliance_pack_exported` is a **separate,
explicit append** through the existing append-only writer **after** generation —
appending a new row is the log's designed behavior, never a mutation of existing rows.
Vector 1 asserts on the **read/projection path** specifically; the meta-audit append is a
distinct, audited step.

---

## 9. Decision D8: Persistence (one reversible migration) + 4-site consistency

**`0012_compliance_event_variants`** (`down_revision="0011"`):

- Widen `ck_eal_event_type` via the established `_set_event_type_check()` DROP+ADD helper
  (the `0008`/`0010`/`0011` pattern) with the two new variants:
  `_WITH_F011 = _THROUGH_F009 + ",'compliance_evidence_generated','compliance_pack_exported'"`.
- **No new columns** (the variants reuse `action_taken='logged'` + the existing `framework`
  column).
- `down()`: narrow `ck_eal_event_type` back to `_THROUGH_F009`. Loss-free for pre-existing
  rows (a CHECK only **widens** an allowed set; narrowing back removes only the two new
  values, which no pre-F-011 row uses). Round-trip verified at STEP 9:
  `…→0011→0012→0011→0012`.

**4-site consistency** (the F-006 anti-pattern guard): the two variants land in lockstep
across `events_audit_log.VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`
(each → `{"logged"}`), the `ck_eal_event_type` CHECK (migration `0012`), and
`contracts/events.schema.json` (api-architect).

---

## 10. Threat Model — 16 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting correct behavior **and** the correct
audit/response **and** no state corruption — not merely "raises." Test files (as
implemented):
`tests/compliance/test_evidence_threat_model.py` (1, 4, 7, 10 — read-only,
window-bound, tenant-scoped read, RLS role),
`tests/compliance/test_pack_export_threat_model.py` (2, 3, 5, 6, 8, 11, 12 — pack
tamper/reproducibility/offline-chain/full-record-binding/export-scoping/disclosure),
`tests/compliance/test_honesty_threat_model.py` (14, 15 — gap honesty + readiness),
`tests/gateway/test_compliance_endpoints.py` (9, 13 — cross-tenant request handling
+ unauthenticated access, exercised against the live FastAPI app + auth middleware).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | Evidence generation mutates the audit log | read-only projection (D2); connection before-execute guard | **zero** writes to `events_audit_log` on the generation path |
| 2 | Tampered exported pack | Layer-B ES256/JWS (D5) | mutate any pack byte → signature verify **fails** |
| 3 | Non-reproducible pack | deterministic ZIP (D6) | same `[tenant,window,controls]` → **byte-identical** archive |
| 4 | Stale / out-of-window events | window-bounded query (D2) | pack states `[t0,t1]`; events outside excluded |
| 5 | Source events un-provable offline | Layer-A embedded chain hashes (D5) | embedded `row_hash`es + tip validate as a correct F-003 chain **without** a live DB |
| 6 | Embedded-hash forgery | full-record signature binding (D5) | altering an embedded chain hash invalidates the ES256 signature |
| 7 | Tenant A generates over tenant B | RLS-scoped read (D1) | tenant-A request → **zero** tenant-B rows even if query manipulated |
| 8 | Cross-tenant data in export | tenant-scoped pack (D1) | exported pack contains only the requester's data |
| 9 | Client-supplied tenant override | server-resolved tenant, no param (D1) | no override honored; explicit mismatch → **403** + audited |
| 10 | Evidence read via bypass role | `sentinel_app` + GUC (D1) | query runs under the RLS role with GUC set, **not** a BYPASSRLS role |
| 11 | PII in a pack | metadata-only evidence (R6) | no PII in any generated pack |
| 12 | Secrets / prompt content in a pack | metadata-only evidence (R6) | no API keys / virtual keys / prompt content in any pack |
| 13 | Unauthenticated evidence/export | tenant Bearer required (D1) | unauthenticated request → **401** (no admin-scope concept in v1) |
| 14 | Fabricated coverage | honest gap analysis (D4, R8) | a control with no Sentinel mapping → **`not_covered`**, never faked |
| 15 | Inflated readiness score | derivable ratio (D4) | score recomputable from gap analysis; no weighting/inflation |

(16 assertions across 15 numbered vectors: vector 1 is the read-only proof; vectors 5 and
6 together are the two-layer offline-verification proof — ≥12 required, exceeded.)

### 10.1 Test isolation strategy (cross-tenant proofs are empirical, not structural)

`generate_evidence` opens its **own** RLS-scoped connection (`get_tenant_session`), so a
test must cross a connection boundary to prove cross-tenant invisibility. The suite uses
**two deliberate patterns** (Affu-approved, F-011 STEP 9):

- **Single-tenant tests** (vectors 4, M-1, 5, disclosure, happy-paths, readiness) use a
  **no-commit savepoint**: rows are appended on one session, `get_tenant_session` is
  monkeypatched to yield that same session, and the outer SAVEPOINT rolls everything back
  at test end — **zero** writes survive. RLS enforcement is not their subject.
- **Cross-tenant RLS proofs** (vector 7 `test_evidence_tenant_scoped`, vector 8
  `test_export_tenant_scoped`, and `test_cross_tenant_pack_request_denied`) **commit real
  rows for tenant A and tenant B across a second, real RLS connection**, then assert
  tenant A's evidence returns **zero** tenant-B rows. This is **empirical, not
  structural** — chosen deliberately because cross-tenant evidence leakage is F-011's
  highest-severity threat (R2). These three tests **cannot** use a rolled-back savepoint
  (that would make the proof structural). They each request a **scoped, non-autouse**
  `truncate_audit_log_after` fixture that **`TRUNCATE`s `events_audit_log` in teardown** —
  `TRUNCATE` is used because the append-only `BEFORE DELETE` trigger (ADR-0003) blocks
  row-level `DELETE`; it bypasses the trigger and restores the empty-table precondition
  that `tests/persistence/test_audit_chain.py::test_single_event_first_row_uses_genesis_hash`
  relies on, regardless of test order. The fixture touches **local dev/CI Postgres only**
  (regenerated each run) and is never applied to single-tenant tests.

---

## 11. Alternatives Considered & Honest Deferrals

- **Introduce an admin/role scope for compliance — REJECTED (Affu, F1).** No admin
  primitive exists; inventing one (env admin token or role flag) widens the threat + audit
  surface and is properly F-012's job with its own threat model. Tenant self-service
  reuses the existing Bearer + RLS and adds no privilege surface.
- **RSA + Vault signing (evidence-gen skill) — REJECTED (Affu, F2).** Codebase precedent
  wins over generic skill guidance: reuse F-008's audited ES256/JWS path; avoid a second
  signing primitive and a hard Vault runtime dependency.
- **Hash-chain reference only / ECDSA only — REJECTED (F2).** A chain reference alone has
  no self-contained seal for a detached file; an ECDSA signature alone doesn't prove the
  source events are chain-intact. Offline auditor handoff (R4) needs **both** layers.
- **PDF export in v1 — DEFERRED (F3).** Non-deterministic (breaks R4), heavy dep (against
  F-010 slim image), human rendering belongs in F-012. v1 ships machine-verifiable signed
  JSON.
- **Materialized `compliance_evidence` table / pack cache — DEFERRED (F4).** Adds a write
  path + staleness + a second tamper surface for marginal benefit at design-partner scale.
  Revisit with its own threat model when window-query cost is empirically a problem.
- **Mapping in a DB table — REJECTED (F5).** The mapping is a human-auditable artifact; a
  PR-reviewable YAML diff with rationale comments is the honest home, not a DB row.
- **Widen `ComplianceCheckedEvent.framework` to add `ISO27001` — AVOIDED.** F-011 does not
  emit `compliance_checked`; it reads existing security events and emits its own
  meta-events. The two **new** variants carry their own `framework` enum `[SOC2,ISO27001]`,
  so **no existing variant is changed**. (Known minor enum-locality: `ISO27001` is valid on
  the new variants but not on `compliance_checked`; harmless because v1 emits no ISO27001
  `compliance_checked` rows. Widening the older enum is a future, additive change.)

---

## 12. Contract Changes

**`contracts/events.schema.json` (api-architect, STEP 6):** add two closed, fully-bounded
variants to `oneOf` — `compliance_evidence_generated`, `compliance_pack_exported`. Each
carries the four stable IDs + `event_id` / `event_timestamp` / `request_id` +
`action_taken` (enum `["logged"]`) + `framework` (enum `["SOC2","ISO27001"]`) +
`framework_version` (`maxLength`-bounded string); `compliance_pack_exported` additionally
carries `pack_content_hash` (a 64-hex `maxLength:64` string). **No existing variant
changes.** No `contracts/ids.md` change (real-tenant attribution, D7).

**`contracts/openapi.yaml` (api-architect, STEP 6):** add two tenant-Bearer-authenticated
paths under the existing security scheme (tenant server-resolved from the key; **no
`tenant_id` parameter**):

- `GET /v1/compliance/evidence` (query: `framework`, `t0`, `t1`) → `200` JSON evidence
  summary (per-control status, gap list, readiness score, disclaimer); `401` unauth.
- `POST /v1/compliance/export` (body: `framework`, `t0`, `t1`) → `200` `application/zip`
  signed pack; `401` unauth.

**`contracts/policy.schema.json`:** **not touched** (LOCKED at F-008).

> **Process note (mirrors ADR-0009 §13 / ADR-0011 §11):** edits to `contracts/` are gated
> by `.claude/hooks/protect-paths-and-secrets.sh`, which authorizes the write only when the
> agent identity is `api-architect`. STEP 6 dispatches the api-architect agent; if the env
> identity is not provisioned, the patch is recorded for verbatim re-apply under that
> identity. The protection logic is never modified or weakened.

---

## 13. Consequences

### 13.1 Positive
- Sentinel's existing controls become **auditor-presentable evidence** for SOC 2 + ISO
  27001 — the buyer-enablement wedge — with **offline-verifiable** tamper-evidence.
- **Read-only by construction**: the strongest possible R1 guarantee; no new write surface.
- **No new auth primitive**: the compliance trust model is identical to the rest of the
  tenant-scoped surface; cross-tenant leakage is structurally impossible at the DB layer.
- **Honest by design**: `not_covered` controls are reported, never faked; the readiness
  score is a transparent, recomputable ratio; the disclaimer is mandatory.
- Reuses audited primitives (F-003 chain, F-008 ES256/JWS, F-003b RLS) — no new crypto, no
  Vault dependency.

### 13.2 Negative / costs
- Large-window evidence generation is O(events in window) (no materialization in v1) —
  documented, acceptable at design-partner scale.
- The mapping YAMLs are **maintained artifacts**: framework/control accuracy is a human
  responsibility (mitigated by PR review + the loader's fail-closed validation).
- A new file-based signing key (`COMPLIANCE_PACK_SIGNING_KEY_PATH`) must be provisioned and
  protected like the F-008 policy key (deploy-injected, never in code/logs/tests — CLAUDE.md
  non-negotiable #4).
- One coordinated migration + two coordinated event sites (mitigated by 4-site discipline +
  round-trip and INSERT-per-variant tests).

### 13.3 Honest scope / known limitations (v1)
**NO** continuous monitoring · **NO** third-party auditor portal · **NO** automated
remediation · **NO** operator/cross-tenant evidence view (→ F-012) · **NO** PDF export
(→ F-012) · **HIPAA / GDPR / EU_AI_ACT** are documented extension points, **not** v1
(v1 = SOC 2 Type II + ISO 27001 Annex A). Evidence is **metadata** (control status +
event counts + hashes), **never** payloads. "audit-ready", never "compliant".

### 13.4 Rollback
- **Whole feature:** revert `task/F-011-compliance-engine-native`. F-011 is purely additive
  (new `src/compliance/` module + 2 endpoints + 2 event variants + 1 reversible migration);
  reverting restores the pre-F-011 state exactly. Nothing in F-003/F-003b/F-007/F-008/F-009
  is modified, so no inherited behavior changes on revert.
- **Migration:** `0012` downgrades by narrowing `ck_eal_event_type` back to the F-009 set
  (only narrows an allowed set — no pre-existing row violates it). Verified at STEP 9.
- **Endpoints:** additive and inert if unused; removing them affects no other route.
