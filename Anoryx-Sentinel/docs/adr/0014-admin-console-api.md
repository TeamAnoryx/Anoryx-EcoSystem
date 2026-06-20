# ADR-0014 — Admin Console API (F-012a)

- **Status:** Proposed
- **Date:** 2026-06-20
- **Deciders:** (admin-api owner / implementer), api-architect (contract / `openapi.yaml` + `events.schema.json` + `ids.md`), persistence (migration `0013`, `events_audit_log` constants, new `TenantRepository`), security-auditor (extended-adversarial gate — this is the highest-risk feature in Sentinel), Affu (solo founder & product owner — resolved the STEP-0 forks during planning: **admin-auth = (a) env token**, **config = view + guarded adjust**, **audit paging = keyset cursor**, **soft-delete = flip `is_active`**, **key rotation = immediate revoke**; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0003 (persistence / hash-chain audit — F-012 **reads** `events_audit_log` and **appends** admin meta-events via the existing append-only writer; never mutates rows), ADR-0005/0006 (tenant isolation / RLS Option α — F-012 **reuses** the `sentinel_app` RLS path for per-target tenant reads and the `get_privileged_session()` break-glass path for the global `tenants` registry; no new bypass), ADR-0009 (F-008 policy intake — F-012 only **reads** policy status), ADR-0010 (F-007 classifier — F-012 **reads**, and **adjusts** via a bounded update to `tenant_routing_policy`, governed by that table's existing CHECK constraints; classifier logic unchanged), ADR-0011 (F-009 observability/rate-limit — F-012 **reads**, and **adjusts** `team_rpm_limit` via the same bounded update; limiter logic unchanged), ADR-0013 (F-011 compliance — F-012 **enables the deferred operator path** by calling the existing `generate_evidence(..., tenant_id=TARGET)`; engine unchanged). Governed by `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/ids.md`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-012a — the **operator surface**: an admin API to manage tenants, mint/rotate/revoke virtual keys, read the audit log across tenants, and thinly control the F-007/F-008/F-009/F-011 engines. This is the **API layer only**; the Next.js frontend is F-012 proper, deferred. It introduces Sentinel's **first cross-tenant principal** — designed so isolation is preserved and every cross-tenant act is explicit and audited.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

Every Sentinel feature to date assumes the caller acts **only on its own tenant**. The
RLS GUC `app.current_tenant_id` is always set to the caller; there is **no principal that
acts across tenants**. The raw material F-012 builds on:

- **Tenant auth** (ADR-0006): `src/gateway/middleware/auth.py` `AuthMiddleware` — Bearer
  virtual key, fingerprint lookup via `VirtualApiKeyRepository.lookup_by_plaintext`
  (HMAC-SHA256 under `SENTINEL_KEY_SECRET`, plaintext never stored), attaches
  `request.state.virtual_key_row`; `tenant_context` middleware builds the immutable
  `TenantContext`. Exempt paths are an **exact-match** `frozenset` (`_AUTH_EXEMPT_PATHS`)
  + the configured metrics path. **No admin/role/scope mechanism exists** (ADR-0013 §1.1
  confirmed this and deferred the operator path here).
- **RLS isolation** (ADR-0005/0006): `get_tenant_session(tenant_id)` on `sentinel_app`
  (**NOBYPASSRLS**) sets the GUC transaction-local; `NULLIF(current_setting(...),'')`
  fail-closes to zero rows. `get_privileged_session()` (owner, **BYPASSRLS**, no GUC) is
  the sanctioned path for hash-chain ops, migrations, and — per its own docstring —
  **"admin/break-glass maintenance."** The privilege gate is a load-bearing
  `SELECT current_user` role check.
- **`tenants`** (migration 0001): a **global registry** — `tenant_id`, `name`,
  `display_name`, **`is_active BOOL NOT NULL DEFAULT true`**, `created_at`, `updated_at`.
  It has **no `tenant_id` RLS column** (ADR-0005: intentionally not tenant-scoped).
  Soft-deactivate is already representable.
- **Virtual keys** (F-004): `VirtualApiKeyRepository` has `create` (returns row, plaintext
  discarded — surfaced once), `lookup_by_plaintext`, `deactivate(key_id, caller_tenant_id)`,
  `get_by_id(key_id, caller_tenant_id)`. **No `list` and no `rotate`.** Gateway rejects a
  revoked key via the `is_active=False` filter in lookup.
- **Audit log** (ADR-0003): `events_audit_log` append-only, SHA-256 chain
  (`hash_chain.py`); `AuditLogRepository.append()` + `validate_chain()` require the
  privileged session. Append-only enforced by DB triggers + RLS `USING(false)`.
- **Engines to reuse**: `PolicyRepository.list_for_tenant`,
  `TenantRoutingPolicyRepository.get_for_tenant` (READ only — **no UPDATE method exists**),
  `generate_evidence(framework_map, t0, t1, *, tenant_id)` (already parameterized by
  tenant — the operator path ADR-0013 deferred).
- **Events 4-site discipline**: `VALID_EVENT_TYPES` (`events_audit_log.py:40`, 27 types),
  `ACTION_TAKEN_BY_EVENT_TYPE` (`:81`), `contracts/events.schema.json` (`oneOf` + per-
  variant `const`), `ck_eal_event_type` (widened in lockstep `0005→0007→0008→0010→0011→
  0012`; **`0012` is head**).
- **Attribution** (`contracts/ids.md`): `WILDCARD_UUID` = **system** attribution (3
  documented uses); reserved `agent_id` slugs (`all-agents`, `rate-limiter`). An admin
  action must be attributed honestly — not as the system, not as the target tenant.

### 1.2 Decision (one paragraph)

We add an **admin API** under `src/admin/` (new package) exposing `/admin/*` routes,
authenticated by a **single deploy-injected env secret** `SENTINEL_ADMIN_TOKEN`
(**D1**, Affu fork (a)) — distinct from tenant Bearer, validated by a `require_admin`
FastAPI dependency with constant-time compare, **fail-closed** (unset or mismatched →
`401`, never a fall-back to tenant scope). Cross-tenant access uses **no new RLS bypass**
(**D2**): per-tenant data is read/written inside `get_tenant_session(TARGET_tenant_id)`
(RLS still enforces, one explicitly-named tenant at a time, exactly as
`generate_evidence` already works); the **global, non-RLS `tenants` registry** is managed
via the existing `get_privileged_session()` break-glass path. The API provides **tenant
lifecycle** (create / list / get / **soft-deactivate via `is_active`**, no hard delete —
**D3/R3**), **virtual-key management** (mint / list / rotate / revoke — secret returned
**once**, stored only as a hash, list returns metadata only — **D4/R4**; rotation is
**immediate-revoke**, Affu's fork), a **read-only audit-log API** (keyset cursor on
`sequence_number`, serving query writes **zero** rows, F-003 chain-status surfaced —
**D5/R5**), and a **thin operator control surface** over the existing engines (**D6/R7**):
policy-status read, classifier/RPM **view + guarded adjust** (Affu's fork — a bounded
UPDATE validated by `tenant_routing_policy`'s existing CHECK constraints), and the F-011
operator evidence path. Every admin **mutating** action and every admin **cross-tenant
read** emits an audit event attributing the action to the **admin principal + target
tenant** (**D7/R1/R6**): `agent_id="admin-console"` (new reserved slug),
`tenant_id=TARGET`, with `team_id=project_id=WILDCARD_UUID` for tenant-level events (new
documented 4th reserved-UUID use) or the key's real team/project for key events. Six new
event variants are added **4-site** with one reversible migration (**0013** — **D9**).
The admin meta-audit append is a **separate, explicit write** distinct from any read's
serving query, reconciling R1 and R5 (**D8**). No frontend, no SSO/SAML, no multi-admin,
no fine-grained RBAC in v1 (honest scope §13.3).

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-012) |
|---|---|
| `events_audit_log` rows, columns, hash chain, append-only writer — **R1/R3** | F-012 **reads** the table (admin + tenant audit read path) and **appends** 6 admin meta-event types via the existing append-only writer; embeds nothing, mutates nothing |
| `AuditLogRepository` (append-only; no update/delete) | **Not modified.** Reused to `append()` admin events and to `validate_chain()` for surfaced status |
| F-003b RLS role/GUC model | **Reused unchanged.** Per-target `get_tenant_session`; privileged session only for the global `tenants` table. **No GUC override, no new BYPASSRLS path** |
| Tenant Bearer auth (`AuthMiddleware`, `tenant_context`) | **Not weakened.** `/admin/*` is added to the exempt-prefix check so tenant auth/context skip it; the admin principal is **additive**, governed by `require_admin` |
| F-007 classifier / F-008 intake / F-009 limiter **logic** | **Read-only consumers**, except a **bounded UPDATE** to the `tenant_routing_policy` config row (classifier_model_id / audit_mode / team_rpm_limit) gated by that table's existing CHECK constraints — no engine logic touched |
| F-011 `generate_evidence` | **Reused** with `tenant_id=TARGET` (the deferred operator path); engine unchanged |
| `VirtualApiKeyRepository` create/lookup/deactivate/get_by_id | **Not modified.** Two additive methods: `list_for_tenant` (metadata only) + `rotate` (deactivate-old + create-new, one txn) |
| `tenants` table columns | **No new columns** for soft-delete (reuse `is_active`). Deactivate = `UPDATE is_active=false` |
| Existing `events.schema.json` variants | **SIX new variants ADDED** (api-architect); no existing variant changed |
| `policy.schema.json` (LOCKED at F-008) | Untouched |
| `ck_eal_event_type` widen pattern (head `0012`) | Migration `0013` widens it with 6 variants (DROP+ADD, reversible) |
| `contracts/ids.md` reserved values | **Additive:** new `admin-console` slug + a documented 4th `WILDCARD_UUID` use (admin tenant-level attribution) |

---

## 2. Decision D1 — Admin auth = env token (`SENTINEL_ADMIN_TOKEN`), fail-closed

Affu chose fork **(a)** at the STEP-0 gate: a single deploy-injected operator secret,
mirroring the F-008 `POLICY_SIGNING_*` / `SENTINEL_KEY_SECRET` env-secret model. The
admin principal is **distinct from tenant Bearer** and governs `/admin/*` only.

1. **Secret source.** `SENTINEL_ADMIN_TOKEN` is read at runtime from the environment
   (Vault/KMS-injected at deploy; never in code/config/logs/tests — CLAUDE.md
   non-negotiable #4). A loader resolves it once per request; **if unset/empty, every
   `/admin/*` route returns `401`** (fail-closed, R2 — never a fall-back to tenant scope,
   never tenant data).
2. **Validation.** `src/admin/auth.py` exposes a `require_admin` FastAPI dependency. It
   reads `Authorization: Bearer <token>` on `/admin/*` and compares to the configured
   secret with `hmac.compare_digest` (constant-time). Missing header / wrong format /
   mismatch → `401`. The dependency validates **only** against `SENTINEL_ADMIN_TOKEN`; it
   **never** falls through to the virtual-key lookup. A tenant virtual key presented on
   `/admin/*` therefore fails the compare and is rejected (vectors 1, 2).
3. **Wiring (the necessary, minimal middleware touch).** `AuthMiddleware` and
   `tenant_context` currently run on every non-exempt path; `_AUTH_EXEMPT_PATHS` is an
   **exact-match** set. F-012 adds a **prefix** check (`/admin` and `/admin/...`) so both
   middlewares skip `/admin/*`, leaving `require_admin` as the sole authority there. This
   reuses the existing exempt mechanism (the health/ready/metrics category) — it is
   **wiring, not engine logic** (R7-safe). The admin token is never accepted on a tenant
   route (lookup fails) and a tenant key is never accepted on `/admin` (compare fails):
   the two principals are mutually exclusive by path **and** validator.
4. **What (a) forecloses (recorded honestly):** no multi-admin, no per-operator audit
   attribution (all admin actions attribute to the single `admin-console` principal), no
   revoke-without-redeploy. These are explicitly deferred; (b)/(c) remain open upgrades.

---

## 3. Decision D2 — Cross-tenant access uses the existing RLS paths (no new bypass)

R1's hardest requirement: admin cross-tenant access must be **explicit and audited**,
never an implicit RLS disable. Two sanctioned paths, both pre-existing:

1. **Per-target tenant data** (audit read, key ops, config, compliance): the admin
   service opens `get_tenant_session(TARGET_tenant_id)` and calls the **existing** repo
   methods. RLS is **fully in force** — just scoped to the explicitly-named target, one
   tenant per request. There is **no GUC override** and **no BYPASSRLS** on this path; if
   the target id is wrong/empty the fail-closed predicate returns zero rows. This is
   byte-for-byte the model `generate_evidence(..., tenant_id=TARGET)` already uses
   (ADR-0013 D1/D2).
2. **Global registry** (`tenants` — no `tenant_id`, not RLS-scoped): list/create/
   deactivate via `get_privileged_session()` — the owner role's documented
   "admin/break-glass" purpose. This is the **only** place F-012 touches the privileged
   session for data, and it touches **only** the non-tenant-scoped registry table; it
   **never** reads tenant-scoped rows through it. Recorded as the single RLS-bypass caveat
   in the PR checklist.

A tenant principal can reach **neither** path: `/admin/*` is governed by `require_admin`
(D1), so a tenant key gets `401` before any session opens (vectors 1, 3, 14).

---

## 4. Decision D3 — Tenant lifecycle (soft-deactivate, no hard delete)

Routes (admin-only): `POST /admin/tenants` (create), `GET /admin/tenants` (list),
`GET /admin/tenants/{tenant_id}` (get), `POST /admin/tenants/{tenant_id}/deactivate`
(soft). A new `src/persistence/repositories/tenant_repository.py` provides
create/list/get/deactivate over the global table via the privileged session. **No DELETE
verb and no hard-delete method exists** (R3): deactivate is `UPDATE is_active=false`
(Affu's fork). The audit log and its chain are untouched by any tenant op and remain
verifiable afterward (vector 12). Emits `admin_tenant_created` / `admin_tenant_deactivated`.

---

## 5. Decision D4 — Virtual-key management (secret once, hash only, immediate rotate)

Routes: `POST /admin/tenants/{tenant_id}/keys` (mint),
`GET /admin/tenants/{tenant_id}/keys` (list), `POST .../keys/{key_id}/rotate`,
`POST .../keys/{key_id}/revoke` — all inside `get_tenant_session(TARGET)` (RLS to target).

- **Mint.** The service generates the plaintext server-side
  (`secrets.token_urlsafe`), calls the existing `VirtualApiKeyRepository.create` (which
  stores only the HMAC fingerprint), and **returns the plaintext exactly once** in the
  response body. No endpoint ever re-reads it (R4). team/project/agent are supplied in the
  body and validated to belong to the target tenant.
- **List.** A new `list_for_tenant(tenant_id, caller_tenant_id)` returns **metadata only**
  — `key_id`, `label`, `is_active`, `created_at`, `expires_at`, `last_used_at`. **Never**
  the fingerprint or any secret (R4, vector 6).
- **Rotate.** A new `rotate` helper, one transaction: `deactivate` the old key + `create`
  a new one, returning the new plaintext once. **Immediate revoke** (Affu's fork) — the
  old key is dead the instant the new one mints (smallest exposure window).
- **Revoke.** `deactivate(key_id, caller_tenant_id)`. The gateway rejects the key on the
  next request via the existing `is_active=False` lookup filter (vector 7).
- A key minted for tenant A carries A's IDs and is rejected if presented as tenant B
  (existing binding + RLS; vector 8). Emits `admin_key_minted` / `admin_key_revoked`.

---

## 6. Decision D5 — Audit-log read API (keyset cursor, read-only, chain status)

- **Admin:** `GET /admin/tenants/{tenant_id}/audit` — reads the target tenant's events
  inside `get_tenant_session(TARGET)`. **Tenant self:** `GET /audit` (tenant Bearer) —
  reads the caller's own events. Both are RLS-scoped at the DB layer (vector 10).
- **Pagination:** keyset cursor on the monotonic `sequence_number` (`after_sequence` +
  bounded `limit`) — Affu's fork. Stable under concurrent appends, no offset drift, no
  deep-scan cost.
- **Read-only (R5).** The data-serving SELECT issues **zero** writes to `events_audit_log`
  (vector 9), proven by a connection-level before-execute guard on the serving path
  (ADR-0013 vector-1 precedent).
- **Chain status (vector 11).** The response honestly surfaces `validate_chain()`'s result
  (`is_valid`, `rows_checked`) — computed on the privileged session — so an operator sees
  the F-003 integrity state, never a fabricated "valid".

---

## 7. Decision D6 — Operator control surface (reuse engines; view + guarded adjust)

Thin control over existing engines (R7 — reuse, never reimplement):

- `GET /admin/tenants/{id}/policies` → `PolicyRepository.list_for_tenant` (policy intake
  status view).
- `GET /admin/tenants/{id}/config` → `TenantRoutingPolicyRepository.get_for_tenant`
  (classifier_model_id / audit_mode / team_rpm_limit view).
- `PATCH /admin/tenants/{id}/config` → a **new bounded update** method on
  `TenantRoutingPolicyRepository` (Affu's fork = adjust). The update is validated against
  the table's **existing** CHECK constraints (`ck_trp_classifier_model_id` allow-list,
  `ck_trp_audit_mode ∈ {full,redacted}`, `ck_trp_team_rpm_limit > 0`); it changes config
  **data**, not classifier/limiter **logic** (R7). Emits `admin_config_updated`.
- `POST /admin/tenants/{id}/compliance/evidence` → existing
  `generate_evidence(framework_map, t0, t1, tenant_id=TARGET)` (ADR-0013's deferred
  operator path; no engine change).

All cross-tenant **reads** here emit `admin_audit_accessed` (R1, D8); the **write** emits
`admin_config_updated`. Vectors 3, 5, 13, 14.

---

## 8. Decision D7 — Event variants (6) + honest admin attribution

Six new variants (extends the dispatch's 4 examples — `e.g.` is non-exhaustive — adding
`*_deactivated` because soft-delete must be audited (R3) and `*_config_updated` because
Affu chose adjust):

| event_type | emitted when | `tenant_id` | `team_id`/`project_id` | `agent_id` | `action_taken` |
|---|---|---|---|---|---|
| `admin_tenant_created` | tenant created | TARGET | `WILDCARD_UUID` | `admin-console` | `logged` |
| `admin_tenant_deactivated` | tenant soft-deactivated | TARGET | `WILDCARD_UUID` | `admin-console` | `logged` |
| `admin_key_minted` | key minted / rotated-new | TARGET | key's real team/project | `admin-console` | `logged` |
| `admin_key_revoked` | key revoked / rotated-old | TARGET | key's real team/project | `admin-console` | `logged` |
| `admin_config_updated` | classifier/RPM config adjusted | TARGET | `WILDCARD_UUID` | `admin-console` | `logged` |
| `admin_audit_accessed` | operator cross-tenant read (audit/policies/config/evidence) | TARGET | `WILDCARD_UUID` | `admin-console` | `logged` |

**Attribution is honest (R6).** `tenant_id = TARGET` (the tenant acted upon),
`agent_id = "admin-console"` (the operator principal — a **new reserved slug**, joining
`all-agents`/`rate-limiter`). It is **never** `WILDCARD_UUID` for `tenant_id` (that would
falsely claim "the system did it") and **never** the target tenant's own `agent_id` (that
would falsely claim "the tenant did it to itself"). Tenant-level admin events have no
specific team/project, so `team_id = project_id = WILDCARD_UUID` — a **new, documented 4th
reserved-UUID use** (admin tenant-level attribution) added to `contracts/ids.md` by the
api-architect. Key events carry the key's real team/project (known at mint/revoke).

---

## 9. Decision D8 — The R1 ⇄ R5 reconciliation (explicit for the security-auditor)

R5 = the audit **read** API writes zero rows. R1 = every admin cross-tenant access is
audited. These meet, not collide:

- The **data-serving SELECT** of the audit read endpoint issues **zero** writes — vector 9
  asserts this on the serving path specifically (before-execute guard), and the tenant
  self-read writes zero rows, period.
- `admin_audit_accessed` is appended by the **admin-operation wrapper** (a separate,
  explicit `AuditLogRepository.append()` on the privileged session, **before** the read is
  served) — appending a new row is the log's designed behavior, never a mutation of
  existing rows. One access event per cross-tenant read.

So an admin audit read performs exactly **one** intentional append (the access event) and
**zero** writes from the serving query; a tenant self-read performs zero writes entirely.
This is documented here and re-verified by the STEP-9 auditor (it is the subtlest point in
F-012's threat model).

---

## 10. Decision D9 — Persistence (one reversible migration) + 4-site consistency

**`0013_admin_event_variants`** (`down_revision="0012"`):

- Widen `ck_eal_event_type` via the established DROP+ADD helper (the `0008`/`0010`/`0011`/
  `0012` pattern) adding the six admin variants:
  `admin_tenant_created`, `admin_tenant_deactivated`, `admin_key_minted`,
  `admin_key_revoked`, `admin_config_updated`, `admin_audit_accessed`.
- **No new columns** (variants use `action_taken='logged'` + the four IDs).
- `down()`: narrow `ck_eal_event_type` back to the F-011 set — loss-free (a CHECK only
  widens an allowed set; narrowing removes only the six new values, which no pre-F-012 row
  uses). Round-trip verified at STEP 10: `…→0012→0013→0012→0013`.

**4-site consistency** (the F-006 anti-pattern guard): the six variants land in lockstep
across `events_audit_log.VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`
(each → `{"logged"}`), the `ck_eal_event_type` CHECK (migration `0013`), and
`contracts/events.schema.json` (api-architect).

---

## 11. Threat Model — 14 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting correct behavior **and** the correct
audit/response **and** no state corruption — not merely "raises". Test files (as
implemented):
`tests/admin/test_admin_auth_threat_model.py` (1, 2, 4),
`tests/admin/test_admin_key_threat_model.py` (6, 7, 8),
`tests/admin/test_admin_audit_threat_model.py` (9, 10, 11),
`tests/admin/test_admin_lifecycle_threat_model.py` (12),
`tests/admin/test_admin_control_threat_model.py` (3, 5, 13, 14).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | Tenant principal reaches an admin endpoint | `require_admin` on `/admin/*`; tenant auth skips the prefix (D1) | a valid tenant Bearer key → **401/403** on **every** admin route |
| 2 | Admin forged from tenant creds | env-token compare only; no fall-through to key lookup (D1) | no token/scope/header manipulation elevates a tenant to admin |
| 3 | Admin cross-tenant op not audited | operation wrapper appends an admin event (D7/D8) | every admin cross-tenant read/write emits an `admin_*` event attributing admin + target |
| 4 | No admin creds → fail-open | fail-closed loader (D1/R2) | `SENTINEL_ADMIN_TOKEN` unset → admin routes **401**, never tenant data |
| 5 | Dishonest attribution | `admin-console` slug + TARGET tenant (D7/R6) | audit event names the admin principal + target — **not** nil-UUID `tenant_id`, **not** the tenant's own identity |
| 6 | Key secret re-readable after creation | secret once; list = metadata only (D4/R4) | mint/rotate returns the secret once; list/get **never** return it or the fingerprint |
| 7 | Revoked key still accepted | gateway `is_active=False` lookup filter (D4) | a revoked key is denied at the gateway immediately |
| 8 | Key authenticates as another tenant | key→tenant binding + RLS (D4) | a key minted for A cannot authenticate as B |
| 9 | Audit read mutates the log | read-only serving query; before-execute guard (D5/D8/R5) | the serving SELECT issues **zero** writes to `events_audit_log` |
| 10 | Tenant reads another tenant's events | RLS-scoped read (D5) | tenant principal reads only its own; admin reads a named target (audited); cross-tenant rows never visible |
| 11 | Chain status faked | surfaced `validate_chain()` (D5) | the read API reports the real F-003 verification status honestly |
| 12 | Hard delete / chain破坏 on deactivate | soft `is_active` flip; no delete path (D3/R3) | deactivation is soft; audit rows + chain survive and re-verify |
| 13 | Deactivated tenant's keys still work | gateway lookup (D3/D4) | keys of a deactivated tenant are denied at the gateway |
| 14 | Cross-tenant key listing by a tenant | admin-only, explicit-target, audited (D4) | admin key listing is explicit-tenant-scoped + audited; a tenant principal cannot list another tenant's keys |

(14 vectors ≥ the 14-vector requirement; the 5 privilege-boundary, 3 key, 3 audit, 3
lifecycle grouping from the dispatch is preserved 1:1.)

### 11.1 Test isolation strategy (cross-tenant proofs are empirical, not structural)

Following ADR-0013 §10.1: cross-tenant proofs (vectors 8, 10, 14) **commit real rows for
two tenants across a second real RLS connection** and assert zero cross-tenant visibility
— empirical, because cross-tenant leakage is F-012's highest-severity threat. They use a
scoped, non-autouse `truncate_audit_log_after` teardown (TRUNCATE bypasses the append-only
`BEFORE DELETE` trigger; local dev/CI Postgres only). Single-tenant / fail-closed tests
(vectors 1, 2, 4, 5, 6, 9, 11, 12, 13) use no-commit savepoints. The `tests/admin/`
package ships a **self-provisioning conftest** (ADR-0013 / F-011 CI lesson: a new test
package runs before `persistence` alphabetically, so it must `alembic upgrade head` +
SCRAM-provision `sentinel_app` itself, and **skip-not-fail** when no DB).

---

## 12. Alternatives Considered & Honest Deferrals

- **(b) DB-backed admin principal — DEFERRED (Affu chose (a)).** Supports multi-admin,
  per-operator attribution, revoke-without-redeploy; costs a new table/flag + more audit
  surface. A clean future upgrade from (a) (the `admin-console` slug becomes a real
  per-operator identity).
- **(c) mTLS client cert — DEFERRED (Affu chose (a)).** Strongest network isolation, zero
  app-config secret; heaviest ops (CA, rotation, separate listener) and painful for the
  later browser frontend.
- **Config view-only — REJECTED (Affu chose adjust).** Adjust is implemented as a bounded
  UPDATE constrained by the existing CHECK constraints, so it adds no new validation
  surface beyond the table's own invariants.
- **Offset/limit audit pagination — REJECTED (Affu chose keyset).** Offset drifts under
  concurrent appends and degrades on deep pages; keyset on the monotonic PK is stable.
- **Grace-overlap key rotation — REJECTED (Affu chose immediate).** A grace window widens
  the exposure surface; immediate revoke is the zero-trust default.
- **Hard delete of tenants — REJECTED (R3).** Append-only audit + chain must survive;
  only soft-deactivate is offered.
- **Frontend, SSO/SAML, multi-admin, fine-grained RBAC — OUT OF SCOPE (v1).** §13.3.

---

## 13. Contract Changes & Consequences

### 13.1 Contract changes (api-architect, STEP 7)

- **`contracts/events.schema.json`:** add six closed, fully-bounded variants to `oneOf`
  (`admin_tenant_created`, `admin_tenant_deactivated`, `admin_key_minted`,
  `admin_key_revoked`, `admin_config_updated`, `admin_audit_accessed`), each with the four
  stable IDs + `event_id`/`event_timestamp`/`request_id` + `action_taken` enum `["logged"]`.
  No existing variant changes.
- **`contracts/ids.md`:** add the `admin-console` reserved slug + a documented 4th
  `WILDCARD_UUID` use (admin tenant-level `team_id`/`project_id` attribution).
- **`contracts/openapi.yaml`:** add an `adminAuth` security scheme (http bearer,
  `SENTINEL_ADMIN_TOKEN`) and the `/admin/*` paths under it (tenant lifecycle, keys, audit
  read, config view/adjust, compliance evidence), plus the tenant-self `GET /audit` under
  the existing tenant bearer scheme. **No existing path changes.**

> **Process note (mirrors ADR-0013 §12):** `contracts/` edits are gated by the
> protect-paths hook authorizing only the `api-architect` identity. STEP 7 dispatches that
> agent; if its identity is not provisioned in the env, the patch is recorded for verbatim
> re-apply under that identity. The protection logic is never modified or weakened.

### 13.2 Positive consequences
- Sentinel gains an operator surface **without weakening tenant isolation**: the admin
  principal is additive, cross-tenant access is explicit + audited, and there is **no new
  RLS bypass** — per-target reads run under full RLS, the privileged session touches only
  the global registry.
- Fail-closed by construction: no admin secret → no admin access, never tenant data.
- Honest, complete audit trail of operator actions (6 variants, truthful attribution).
- Reuses every existing primitive (RLS, key repo, audit writer, the four engines) — no new
  crypto, no new auth framework, one reversible migration.

### 13.3 Honest scope / known limitations (v1)
**NO** frontend (→ F-012 proper) · **NO** SSO/SAML (future) · **single-operator only** —
fork (a) means **no multi-admin, no per-operator attribution** (all admin actions
attribute to `admin-console`), **no revoke-without-redeploy** · **NO** fine-grained RBAC ·
**NO** multi-admin delegation. The admin token is a single deploy-injected secret; protect
it like the F-008 signing key. The one RLS-bypass caveat: `get_privileged_session()` is
used **only** for the global, non-tenant-scoped `tenants` registry, never for tenant rows.
"audit-ready", never "compliant".

### 13.4 Rollback
- **Whole feature:** revert `task/F-012-admin-api-native`. F-012 is purely additive (new
  `src/admin/` package + `/admin` routes + tenant `/audit` + 2 key-repo methods + 1
  config-repo method + 1 new `TenantRepository` + 6 event variants + 1 reversible
  migration). Reverting restores the pre-F-012 state exactly; nothing in
  F-003/F-003b/F-005/F-006/F-007/F-008/F-009/F-011 is modified.
- **Migration:** `0013` downgrades by narrowing `ck_eal_event_type` back to the F-011 set
  (only narrows an allowed set — no pre-existing row violates it). Verified at STEP 10.
- **Auth wiring:** removing the `/admin` exempt-prefix check and the admin router restores
  the exact prior middleware behavior; tenant auth is untouched.
