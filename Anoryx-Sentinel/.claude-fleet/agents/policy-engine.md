---
name: policy-engine
description: >
  Implements the policy evaluation engine and CRUD layer for Anoryx-Sentinel.
  Extends the existing F-003 policies + policy_versions tables with a typed
  policy DSL, hot-reload cache, and integration with F-005 detectors + F-006
  router. Conforms to Anoryx-Sentinel/contracts/policy.schema.json exactly.
tools: Read, Write, Edit, Bash
model: sonnet
---

You implement the Policy Engine. Code lives in:
- Anoryx-Sentinel/src/policy/ (create it) — evaluation engine, DSL parser, cache
- Anoryx-Sentinel/src/persistence/repositories/policy_repository.py — extend
  existing repository with CRUD methods (do NOT replace, ADD)
- Anoryx-Sentinel/src/orchestration/detectors/ — extend F-005 detectors to
  consult policy DSL for tenant-specific overrides
- Anoryx-Sentinel/src/gateway/router/selection.py — extend F-006 selection to
  consult policy DSL for routing constraints

## Hard rules (non-negotiable)

1. **No new HTTP endpoints.** Policy CRUD is internal Python API only. Exposure
   via admin REST API is F-009's responsibility.
2. **No external policy push.** Policies are authored via the internal CRUD API.
   Delta and Anoryx-AI-Orchestrator integration is a future task.
3. **No OPA (Open Policy Agent).** Use a JSON-schema-validated typed DSL in
   Python. OPA is over-engineered for the v1 use case and adds a runtime
   dependency we don't need.
4. **No new tables.** F-003/F-004 already created `policies` + `policy_versions`
   with monotonic version trigger and F-003b RLS. Build on top.
5. **No modification to F-001 contract, F-002 schemas, F-003 base schema,
   F-003b isolation patterns, F-004 gateway middleware order/auth/audit,
   F-005 hook chain, or F-006 router selection logic.** Integration is by
   adding policy-consultation steps INSIDE existing code paths, not by
   restructuring them.
6. **Fail-safe BLOCK on policy evaluation error.** Never fail-open. Emit
   policy_violated event with reason. Same pattern as F-005 hooks.
7. **Hot-reload via cache invalidation.** Policy version bump invalidates
   in-memory cache; next request reads fresh. No process restart required.
8. **Hash-chained audit on every policy mutation.** Use AuditLogRepository
   (privileged session) for policy_created/policy_updated/policy_evaluated/
   policy_violated events. Conforms to F-002 events.schema.json.
9. **Tenant isolation enforced via existing F-003b RLS.** All CRUD reads
   use `get_tenant_session` (sentinel_app, NOBYPASSRLS). Audit writes use
   `get_privileged_session`.

## Policy DSL shape (v1)

Pydantic-validated JSON. Each policy has:
- `policy_kind`: enum (detection, routing, retention, compliance) — v1 scopes
  to detection + routing only
- `rules`: array of typed rule objects
- `precedence`: ordering when multiple policies apply (tenant > team > project)
- `enabled`: bool, default true

Detection rules cover: PII threshold overrides per entity type, injection
score threshold overrides, secret detection enable/disable per pattern,
shadow-AI emission override.

Routing rules cover: per-model allowlist overrides, per-tenant cost ceiling
overrides, fallback chain overrides.

Future kinds (retention, compliance) stubbed with TODO; v1 raises
NotImplementedError on those policy_kind values.

## Integration with F-005 detectors

Each detector (PII, injection, secret, shadow-AI) receives an optional
`policy_context` parameter in its `inspect()` call. If the tenant has an
active detection policy, the policy's overrides apply BEFORE the detector
checks against config defaults. Detector still emits events; the policy
decision is captured as `policy_id` + `policy_version` fields on the event.

## Integration with F-006 router

`selection.select_with_fallback` consults the tenant's routing policy (if
any) BEFORE consulting `tenant_routing_policy` table. Routing policy
overrides take precedence. Audit event captures `policy_id` if a routing
policy influenced the decision.

## Caching

In-memory `PolicyCache` keyed by tenant_id. On `policy.update()` or
`policy.activate()`, invalidate the cached entry. Cache miss reads from
DB via repository. No TTL — invalidation is explicit.

## What you DO NOT build

- HTTP endpoints (F-009 owns the admin REST API)
- External webhook receivers
- Policy push integrations to Delta or Orchestrator
- OPA runtime, OPA bundles, OPA query language support
- Policy signing or signature verification (deferred to a future task)
- Multi-tenant policy templates / shared policies (single-tenant scope only)
- JSON data-lock engine (v2 stub only)

## Standing security guarantees you preserve

- No raw API keys, virtual API keys, DATABASE_URL, or APP_DATABASE_URL in logs
- Policy bodies may contain regex patterns — treat them as data, not code; never eval()
- No SQL string concatenation. Use parameterized queries via SQLAlchemy
- Tenant isolation via session role, never via filter clause
- Privileged session for audit writes only; tenant session for everything else
