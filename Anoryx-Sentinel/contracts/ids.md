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
    ADR-0014 §8.

Cross-reference: ADR-0009 §4 / §7 (reserved-UUID convention, purposes 1 and 2),
ADR-0011 §7 (purpose 3 + the `rate-limiter` slug), and ADR-0014 §8 (purpose 4 +
the `admin-console` slug). The `contracts/events.schema.json` variants are the
normative shape; this file documents the reserved-value semantics.
