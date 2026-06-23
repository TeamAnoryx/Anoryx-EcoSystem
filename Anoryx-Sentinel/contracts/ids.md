# Sentinel — Stable Identifier Schema (Phase 0 — LOCKED)

These four IDs travel on every request, event, and log entry across the entire
Anoryx ecosystem. They are the join key between Sentinel events and Delta records.
DO NOT rename these fields without an ADR and a full migration plan.

| Field      | Type   | Format          | Example                                  |
|------------|--------|-----------------|------------------------------------------|
| tenant_id  | string | UUID v4         | "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6" |
| team_id    | string | UUID v4         | "7d9e2f3a-1234-5c6b-8def-0123456789ab" |
| project_id | string | UUID v4         | "b3c4d5e6-abcd-1234-ef01-234567890abc" |
| agent_id   | string | slug, lowercase | "gateway-core", "data-protection"       |

Rules:
- All four REQUIRED on every inbound request. Missing any = 400 Bad Request.
- All four propagated onto every outbound event on the Redis Streams bus.
- agent_id = internal Sentinel component name, not the end-user's AI model name.
- These IDs are set in Phase 0 and treated as IMMUTABLE across the Anoryx ecosystem.

## Reserved IDs

The reserved values below let system-scoped records carry the four required IDs
without inventing an optional-scope field. The ID fields stay LOCKED/IMMUTABLE;
only specific RESERVED VALUES gain documented meaning. These are a join-key
convention for Delta records — never a privilege or cross-tenant grant.

- **`WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"`** — the reserved
  zero-UUID. Valid in `tenant_id`, `team_id`, and `project_id` (it is a UUID v4
  shape). It has FOUR documented purposes:
  1. **Sub-tenant wildcard for model policies** — `team_id` / `project_id` set to
     `WILDCARD_UUID` means "matches any value" for policy scoping. `tenant_id` may
     NEVER be a wildcard in policy intake (cross-tenant blast radius). See
     ADR-0009 §4.
  2. **System-scoped audit owner for pre-verification rejections** — when no tenant
     is resolvable (e.g. signature/schema failure in F-008 policy intake), the four
     IDs become the reserved system-sentinel values. See ADR-0009 §7.
  3. **System-scoped audit owner for system-emitted events with no request context**
     (F-009 / ADR-0011 §7) — `rate_limit_recovered`, and `rate_limit_degraded` /
     `rate_limit_redis_error` when emitted by the background health loop (not by an
     in-request admission failure). Here `tenant_id = WILDCARD_UUID` denotes
     "the Sentinel system itself" — it is a SYSTEM ATTRIBUTION, never a cross-tenant
     grant. (In-request `rate_limit_degraded` / `rate_limit_redis_error` instead
     carry the triggering request's REAL four IDs.)
  4. **Admin tenant-level attribution for F-012a operator events** (F-012a /
     ADR-0014 §8) — on the tenant-level admin meta-events `admin_tenant_created`,
     `admin_tenant_deactivated`, `admin_config_updated`, and `admin_audit_accessed`,
     `team_id = project_id = WILDCARD_UUID` because the operator action is NOT scoped
     to a team/project. Here the wildcard denotes "no team/project scope" for the
     admin act. CRITICAL: `tenant_id` is the TARGET tenant acted upon and is NEVER
     `WILDCARD_UUID` — an admin action against a tenant must be attributed to that
     tenant, never to the system. (The key-level admin events `admin_key_minted` /
     `admin_key_revoked` instead carry the key's REAL team/project, known at
     mint/revoke.) The admin principal is `agent_id = "admin-console"` (below).
  5. **System-scoped admin auth event for F-014 break-glass** (F-014 / ADR-0017 §10) —
     on `admin_breakglass_used`, `tenant_id = WILDCARD_UUID` because the env-token
     break-glass authentication is a SYSTEM-scoped auth event with NO single target
     tenant (break-glass is cross-tenant by purpose). The same applies to
     `operator_sso_denied` when the denial is PRE-BINDING — i.e. no tenant resolves from
     the assertion (the documented system-scoped-audit-owner use, purpose 2 generalized
     to SSO). Here `tenant_id = WILDCARD_UUID` denotes "the Sentinel system itself" / "no
     resolvable target tenant" — it is a SYSTEM ATTRIBUTION, NEVER a cross-tenant grant.
     CRITICAL contrast: the tenant-bound SSO events (`operator_sso_login`, and
     `operator_sso_denied` once a tenant resolves, and `idp_config_changed`) carry the
     operator's/target tenant's REAL `tenant_id` and are NEVER `WILDCARD_UUID` — an
     operator's tenant action must be attributed to that tenant. On all of these
     `team_id = project_id = WILDCARD_UUID` (no team/project scope). The acting human
     operator is named by `actor_id` (below), never by `tenant_id`.

- **`agent_id` reserved slugs.** `agent_id` is a lowercase SLUG, not a UUID, so it
  cannot use the zero-UUID; system attribution uses a reserved slug instead. This
  is the one asymmetric point in the convention (flagged to and accepted by Affu).
  Reserved slugs:
  - **`all-agents`** — the agent-dimension wildcard for model policies (mirrors the
    `WILDCARD_UUID` sub-tenant wildcard). See ADR-0009 §4.
  - **`rate-limiter`** — the emitting component for F-009 system-emitted rate-limit
    events from the background health loop. See ADR-0011 §7.
  - **`admin-console`** — the F-012a admin/operator principal: the cross-tenant
    operator that manages tenants, mints/rotates/revokes virtual keys, reads the
    audit log across tenants, and thinly controls the engines. It is Sentinel's first
    cross-tenant principal. Carried as `agent_id` on every `admin_*` meta-event so the
    action is attributed honestly to the OPERATOR — never to the system
    (`WILDCARD_UUID`) and never to the target tenant's own identity. v1 is
    single-operator (one deploy-injected `SENTINEL_ADMIN_TOKEN`), so all admin actions
    share this one slug; per-operator attribution is a documented future upgrade. See
    ADR-0014 §8. (F-014 / ADR-0017: `admin-console` is also the principal on the
    `admin_breakglass_used` and break-glass-path `idp_config_changed` events.)
  - **`operator-sso`** — the F-014 SSO subsystem principal (ADR-0017 §10, D9). Carried as
    `agent_id` on `operator_sso_login` and `operator_sso_denied` (and on `idp_config_changed`
    when an SSO-authenticated operator changes config). It names the SSO subsystem as the
    EMITTING principal; the SPECIFIC human operator is named by the `actor_id` field (below),
    not by this slug. This is the F-014 realization of the per-operator-attribution upgrade
    that `admin-console` deferred: `operator-sso` + `actor_id` together attribute an SSO
    operator action honestly — never to the system (`WILDCARD_UUID`) and never to the
    target tenant's own identity. See ADR-0017 §10 (vector 16).
  - **`bulk-worker`** — the F-015 async bulk-pipeline worker principal; carried as `agent_id`
    on every `batch_*` lifecycle/outcome event (`batch_submitted`, `batch_file_processed`,
    `batch_file_blocked`, `batch_file_dead_lettered`, `batch_completed`). The `tenant_id` on
    these events is ALWAYS the real submitting tenant — NEVER `WILDCARD_UUID` (a batch belongs
    to a real tenant). See ADR-0018 §8.
  - **`code-scan`** — the F-016 post-response code-scanning detector principal (ADR-0019 §10).
    It is the detector's `detector_slug` and is carried as `agent_id` on every code-scan event
    (`code_scan_passed`, `code_scan_warned`, `code_scan_blocked`, `code_scan_error`). It names
    the EMITTING subsystem — the detector that scans fenced code blocks extracted from an LLM
    response (Semgrep / Bandit, static analysis only). The `tenant_id` on these events is ALWAYS
    the caller's real tenant — NEVER `WILDCARD_UUID` (a scan is always attributed to the real
    caller whose response was inspected); `team_id` / `project_id` are the caller's REAL IDs.
    These events carry metadata only — NEVER the scanned code content and NEVER a scanner stack
    trace. See ADR-0019 §10.
  - **`data-lock`** — the F-017 post-response data-lock detector principal (ADR-0020 §10).
    It is the detector's `detector_slug` and is carried as `agent_id` on every data-lock event
    (`field_locked`, `field_unlocked`, `lock_condition_denied`, `data_lock_error`). It names the
    EMITTING subsystem — the detector that evaluates JSON data-lock rules over fields in an LLM
    response (time / permission conditions, fail-closed on unevaluable rulesets). The `tenant_id`
    on these events is ALWAYS the caller's real tenant — NEVER `WILDCARD_UUID` (a lock evaluation
    is always attributed to the real caller whose response was inspected); `team_id` / `project_id`
    are the caller's REAL IDs. These events carry metadata only — NEVER a locked field VALUE and
    NEVER a response payload. See ADR-0020 §10.

## The `actor_id` attribution field (F-014 / ADR-0017 §10)

`actor_id` is an OPTIONAL event field (it is NOT one of the four LOCKED stable IDs and is
NOT a reserved-value of them). It is the honest per-operator attribution carrier added for
F-014 SSO (ADR-0017 §10, threat vector 16): the four stable IDs plus the LOCKED `agent_id`
slug leave no field that can name a specific HUMAN operator, so a new bounded field carries
it.

- **What it holds.** The INTERNAL `admin_users.id` — an opaque UUID string, VARCHAR(64)-
  bounded (same shape as `event_id` in `contracts/events.schema.json`). It is joinable
  (RLS-scoped) to the operator identity row.
- **Never PII.** `actor_id` is NEVER the raw IdP subject, email, NameID, or any credential
  (Sentinel non-negotiable: no PII in events; ADR-0017 R6). It is the surrogate internal id
  only.
- **The only field that names a human.** `agent_id` names the emitting SUBSYSTEM
  (`operator-sso` / `admin-console`); `actor_id` names the SPECIFIC OPERATOR. They are
  complementary: subsystem + operator = honest attribution.
- **Presence per variant** (normative shape lives in `events.schema.json`):
  - `operator_sso_login` — `actor_id` REQUIRED (a successful login always has a provisioned
    `admin_users` row).
  - `operator_sso_denied` — `actor_id` ABSENT (the subject was denied and not provisioned).
  - `admin_breakglass_used` — `actor_id` ABSENT (the env-token break-glass has no operator
    identity).
  - `idp_config_changed` — `actor_id` OPTIONAL (the operator's `admin_users.id`; ABSENT when
    the change is performed via break-glass).

Cross-reference: ADR-0009 §4 / §7 (reserved-UUID convention, purposes 1 and 2),
ADR-0011 §7 (purpose 3 + the `rate-limiter` slug), ADR-0014 §8 (purpose 4 +
the `admin-console` slug), and ADR-0017 §10 (purpose 5 + the `operator-sso` slug +
the `actor_id` attribution field). The `contracts/events.schema.json` variants are the
normative shape; this file documents the reserved-value semantics.
