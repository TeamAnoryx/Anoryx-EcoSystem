# Anoryx Ecosystem — Complete Build Roadmap (v2)

**Owner:** Affu (TeamAnoryx)
**Last updated:** 2026-06-18
**Status:** Sentinel Phase 1 in progress — F-001 through F-008 shipped, F-009 next
**Replaces:** anoryx-ecosystem-roadmap.md (2026-06-15)

---

## What changed in v2

The v1 roadmap (2026-06-15) was written before F-002 through F-008 shipped. Significant scope drift occurred as the build progressed. v2 reconciles plan with reality and re-sequences remaining work.

### Verified shipped state (from git history on main as of 2026-06-18)

| ID | v1 description | What actually shipped | Notes |
|----|---|---|---|
| F-001 | OpenAPI contract | OpenAPI contract | ✅ Matches plan |
| F-002 | Event + policy schemas | Event + policy schemas | ✅ Matches plan |
| F-003 | Persistence layer | Persistence + hash-chained audit log | ✅ Matches plan |
| **F-003b** | (not in v1) | **Tenant isolation RLS** | ➕ Added — wasn't planned |
| F-004 | Gateway core w/ multi-provider routing via LiteLLM | Gateway core (auth + rate limit + audit) | 🔀 Router split out to F-006 |
| F-005 | Orchestration hooks (event emitter only) | Orchestration hooks + 4 detectors (PII/injection/secret/shadow-AI emission) | 🔀 Absorbed PII (was F-006), injection+secret (was F-007), shadow-AI seam (was F-018) |
| F-006 | Data protection (PII detection) | Multi-provider model router (native — no LiteLLM) | 🔀 PII landed in F-005; F-006 became router |
| F-007 | Defense (injection + secret leak) | ✅ SHIPPED 2026-06-18 — ML classifier + shadow-AI egress monitor (Path Y bundled) | ✅ Done |
| F-008 | Policy engine (OPA) | Policy engine (ECDSA-signed intake, no OPA) | 🔀 Implementation completely different from plan |

### Drift summary

- **5 tasks absorbed into F-005** (PII, injection regex, secret detection, shadow-AI emission primitive)
- **1 task added** (F-003b — RLS tenant isolation surfaced as critical during F-003 development)
- **2 tasks fundamentally re-scoped** (F-006 became router; F-008 became cryptographic intake)
- **1 task scope-expanded mid-build** (F-007 — Path Y bundled ML classifier + shadow-AI egress per 2026-06-18 strategic decision; F-018 folded in)

### Strategic decisions baked into v2

1. **F-007 = ML classifier + shadow-AI egress (Path Y, locked 2026-06-18 mid-dispatch)**. Original plan was Option A (ML classifier only with shadow-AI deferred to F-018), but during F-007 STEP 0 the bundled scope was confirmed and F-018 was folded in. F-007 estimate revised from 12-16h → 20-28h (actual: ~28h fleet). Secret leak detection already shipped in F-005, no separate task needed.

2. **Sequence after F-008 = demo-readiness first** (Option β from 2026-06-18 strategy review):
   - F-009 (rate limit + observability) → unblocks ops visibility
   - F-010 (deployment) → unblocks first design partner
   - F-007 (ML classifier + shadow-AI egress) → depth feature ✅ SHIPPED
   - F-011 (compliance engine) → buyer enablement
   
   Rationale: getting to "a buyer can run Sentinel themselves and see what it's doing" is more valuable than depth features when there's no buyer yet.

3. **Velocity calibration.** v1 estimated F-008 at 2.5 days realistic. Actual was ~22h fleet work spread across 3-4 days of Affu gate decisions. Adjusting v2 estimates upward by ~30-50% for security-critical tasks based on this actual throughput.

---

## How to read this document

**Task IDs.** Each task has a unique prefix-numbered ID so they stay distinct across products and can be referenced in commits, PRs, and tasks.yaml:

| Prefix | Product                    |
|--------|----------------------------|
| F-     | Anoryx Sentinel            |
| O-     | Anoryx AI Orchestrator     |
| D-     | Delta                      |
| R-     | Rendly                     |
| X-     | Cross-product integration  |

**Status labels:**

- **✅ SHIPPED** — Merged to main, CI green, security-auditor verdict CLEAN
- **🔄 NEXT** — Recommended next task per β sequencing
- **📋 PLANNED** — Original roadmap, will be addressed in sequence
- **❓ RE-SCOPED** — In original roadmap but redefined based on shipped reality
- **🔮 SPECULATIVE** — Phase 3+ tasks; scope may need refinement when reached
- **➕ NEW** — Added to v2, wasn't in v1

**Estimates** are *fleet dispatch time including your review and merge*, not raw coding time. Based on actual F-001-F-008 throughput:
- **Easy** = 4-6h
- **Tricky** = 8-12h
- **Complex** = 16-28h
- **Heavy** = 28h+ (anything involving cryptography, contracts, or cross-product coordination)

**"Done" means:**
1. PR merged to main
2. CI green on the merge commit
3. Security-auditor verdict CLEAN (no overrides on High/Critical)
4. ADR written for non-obvious design decisions
5. Tests exist for new behavior, including adversarial threat model where security-relevant
6. Persistent audit artifact at `docs/audit/<task-id>-security-audit.md` for any task with security implications
7. You can demo the feature working end-to-end

If any of those is missing, the task is not done. Mark in progress instead.

**Risk flag:**
- **Low** — straightforward CRUD or config
- **Medium** — non-trivial logic, expect one security-audit finding
- **High** — sensitive trust boundary, integration with external system, or complex async behavior; budget 2x estimate

---

## Roadmap summary

| Product            | Tasks | Shipped | Remaining | Realistic remaining |
|--------------------|-------|---------|-----------|---------------------|
| Anoryx Sentinel    | 37    | 9       | 28        | ~70 days            |
| AI Orchestrator    | 10    | 0       | 10        | ~16 days            |
| Delta              | 16    | 0       | 16        | ~30 days            |
| Rendly             | 22    | 0       | 22        | ~42 days            |
| Cross-integration  | 6     | 0       | 6         | ~7 days             |
| **Total**          | **91**| **9**   | **82**    | **~165 days**       |

**Honest read at current velocity:** At 6 working days/week with 6-8 productive hours/day, the remaining ~165 fleet days is **~7-8 months solo** to ship the full ecosystem to v1.

**Demo-readiness milestone (β path):** F-001 through F-011 = ~3-4 weeks more work from where you are now. After F-011, Sentinel is genuinely demoable to a first design partner.

**MVP-complete milestone:** F-001 through F-015 + key Phase 5 tasks (F-026 MCP, F-029 HIPAA, F-030 EU AI Act) = ~3-4 months total from where you are now.

---

# PRODUCT 1: ANORYX SENTINEL

The zero-trust AI gateway. Foundation for the entire ecosystem.

## Phase 0 — Contract lock ✅ COMPLETE

### F-001 — OpenAI-compatible API contract ✅ SHIPPED
**Status:** Merged at commit `59bc234`
**What shipped:** Full `openapi.yaml` defining `/v1/chat/completions`, `/v1/completions`, `/v1/models` with VirtualApiKey auth, four stable IDs, SSE streaming contract. ADR-0002 documents the key-binding decision (closes the CRITICAL audit finding from contract design).

### F-002 — Event + policy JSON schemas ✅ SHIPPED
**Status:** Merged
**What shipped:** `events.schema.json` (event types Sentinel emits) and `policy.schema.json` (BudgetLimitPolicy, ModelAllowlistPolicy, ModelDenylistPolicy). JSON Schema Draft 2020-12. Note: `policy.schema.json` was LOCKED at F-008 commit `a9e2344`.

---

## Phase 1 — Sentinel MVP backend

### F-003 — Persistence layer ✅ SHIPPED
**Status:** Merged
**What shipped:** Postgres schema for tenants, teams, users, virtual_api_keys, model_policies, plus the hash-chained `events_audit_log`. Alembic migrations 0001-0005. ADR-0004 documents the chain design with monotonic version triggers on policy_versions.

### F-003b — Runtime tenant isolation (RLS) ✅ SHIPPED ➕ NEW
**Status:** Merged
**What shipped:** Row-level security policies on every tenant-scoped table. `sentinel_app` role (NOBYPASSRLS) for tenant sessions; privileged role for chain operations. ADR-0005 documents the role architecture and threat model. Added during F-003 development when cross-tenant leakage was identified as a real risk; the original roadmap didn't anticipate this gap.

### F-004 — Gateway core ✅ SHIPPED
**Status:** Merged
**What shipped:** FastAPI app implementing `openapi.yaml`. Virtual API key auth resolving server-side to tenant/team/project IDs. Non-bypassable ASGI terminal-audit middleware (every rejection path fires audit). Request validation, rate limiting (in-memory; Redis backend deferred to F-009). ADR-0006. **Multi-provider routing was split out to F-006.**

### F-005 — Orchestration hooks + 4 detectors ✅ SHIPPED ❓ RE-SCOPED
**Status:** Merged
**What shipped (much larger than v1 plan):**
- Hook framework (pre-request + post-response)
- PII detector (Presidio-based) — was v1's F-006
- Injection detector (regex-based) — was v1's F-007 partial
- Secret detector — was v1's F-007 partial
- Shadow-AI emission primitive (no detection logic, just the event seam) — was v1's F-018 partial
- Parsed-structure outbound secret redaction (JSON tree walking)
- ADR-0007

**Note for v2:** Original F-005 was just "event emitter to Redis Streams." Redis Streams emission was deferred (caller can implement via a webhook config in F-009). The event emission is to the local audit log via hash chain for now.

### F-006 — Multi-provider model router ✅ SHIPPED ❓ RE-SCOPED
**Status:** Merged
**What shipped:** Native router (no LiteLLM — see ADR-0008 for the decision rationale). Three provider adapters: OpenAI, Anthropic, Bedrock. Per-tenant `tenant_routing_policy` table with RLS. Security-aware fallback (auth/content-policy terminal, no billing leak). Stream-time cost enforcement. New `routing_decision` event variant.

**v1 vs v2:** v1 placed multi-provider routing inside F-004 with LiteLLM. v2 reflects the actual decision to build native and ship as its own F-006.

### F-007 — ML injection classifier + shadow-AI egress ✅ SHIPPED 2026-06-18 (Path Y bundled)
**Status:** Planned, slim scope per Option A
**Description:** Add LLM-as-judge classification step to the existing F-005 injection detector. Two preset adapters (Anthropic Haiku, OpenAI gpt-4o-mini), tenant-configurable via routing_policy field. Regex pre-filter (skip judge if obvious attack) + structured output forcing + system prompt hardening + advisory threshold (low confidence falls back to regex). Final score = max(regex_score, judge_score).

**Out of scope (deferred):**
- Shadow-AI detection (folded into F-007 per Path Y decision 2026-06-18; was separate F-018 in v2.0)
- Secret leak detection (already shipped in F-005)
- B2C multi-tenant inheritance abstractions (deferred until first B2C customer)

**What v1 had that v2 doesn't ship:**
- Hot-reloadable rules (the F-005 regex rules are already DB-loaded; classifier model selection via routing_policy gives equivalent reconfigurability)

**Realistic:** 12-16h (Tricky-Complex) · **Optimistic:** 8h
**Depends on:** F-006 (router for judge invocation), F-008 (policy structure for classifier_model_id config)
**Builder agent:** orchestration-hooks (extends F-005 detector)
**Risk:** Medium — recursive injection attack is the novel threat; structured output + regex pre-filter mitigate

### F-008 — Policy intake + enforcement ✅ SHIPPED ❓ RE-SCOPED
**Status:** Merged at PR #11
**What shipped (completely different implementation from v1 plan):**
- ECDSA P-256 (ES256) compact-JWS signature verification
- Scope-resolve-and-reject (signature payload authoritative; body IDs cross-check only)
- Replay/rollback defense (intake-time check + DB monotonic trigger)
- 3 variant handlers: BudgetLimitPolicy, ModelAllowlistPolicy, ModelDenylistPolicy
- Content-hash signature binding (covers full record, not just scope claims — CRITICAL remediation)
- Hash-chained audit on every intake decision (5 outcomes)
- F-006 router integration (deny precedence; pre-tenant_routing_policy)
- F-006 cost integration (stream-time budget enforcement)
- `sentinel-cli policy push` + `policy keygen`
- ADR-0009 + 16-vector adversarial threat model
- Contract `policy.schema.json` LOCKED at commit `a9e2344`

**v1 vs v2:** v1 specified OPA + POST `/v1/internal/policies` HTTP endpoint + Delta push. v2 ships cryptographically-signed records intake via internal Python API, CLI-driven for now. Delta push integration becomes a future task. No OPA dependency.

### F-009 — Rate limiting + observability 🔄 NEXT
**Status:** Recommended next task per β sequencing
**Description:** Move rate limiting from in-memory (current F-004 state) to Redis-backed. Add Prometheus metrics endpoint exposing: requests/sec, error rate, p95 latency, PII blocks/min, policy violations/min, classifier latency, audit-write failures (closes the gap flagged in F-008 follow-up). OpenTelemetry traces propagated end-to-end. Grafana dashboard JSON committed.

**Includes the F-008 follow-up:** `sentinel_audit_write_failures_total` counter for both F-004 and F-008 audit emit paths.

**Realistic:** 12-16h (Tricky-Complex) · **Optimistic:** 8h
**Depends on:** F-004, F-005, F-006, F-008
**Builder agent:** platform-infra
**Risk:** Medium — Redis state migration has subtle correctness requirements (race conditions on counter resets)

### F-010 — Deployment (Docker + Helm + self-host) 🔄 NEXT (after F-009)
**Status:** Demo-readiness blocker
**Description:** Multi-stage Dockerfile. K8s manifests. Helm chart supporting both managed-cloud and self-hosted VPC deployment. Secrets via Vault or KMS env vars. `docker-compose.yml` for local dev (this is what a design partner runs first). SECURITY.md documenting attack surface. POLICY_SIGNING_PUBKEY_PATH and POSTGRES/REDIS connection env vars documented.

**Specifically scoped for demo-readiness:**
- `docker compose up` works end-to-end
- Default tenant + default routing policy seeded
- `sentinel-cli` available in the container
- README walkthrough: install → first API call → see audit chain → push first policy

**Realistic:** 16-20h (Complex) · **Optimistic:** 12h
**Depends on:** F-004, F-005, F-006, F-008
**Builder agent:** platform-infra
**Risk:** Medium — deployment surfaces always reveal environmental assumptions

### F-011 — Compliance engine 📋 PLANNED
**Status:** Phase 2 entry
**Description:** SOC 2 (Trust Services Criteria) and GDPR control mappings as versioned Postgres data. Automated checks (encryption_at_rest verification, audit_logging_active, rbac_enforced, pii_masking_active, signature_verification_active). Readiness score endpoint. Gap report with remediation hints. Evidence pack export (signed ZIP).

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-003, F-005, F-006, F-008
**Builder agent:** compliance-engine
**Risk:** Medium — honest-language discipline must be enforced throughout

**Phase 1 totals remaining: F-011 = ~2-3 days. (F-007, F-009, F-010 shipped 2026-06-18.)**

---

## Phase 2 — Enterprise readiness

### F-012 — Admin console frontend 📋 PLANNED
**Description:** Next.js 14 + TypeScript + Tailwind. Screens: virtual API key management, team/user RBAC, model policies, PII policies, classifier config, policy intake status. Dark-mode-first, monospace accents (Datadog-like). All API calls conform to `openapi.yaml`. WCAG 2.1 AA. **Requires F-009's admin API endpoints — see scope note below.**

**Scope note:** F-009 in v2 ships rate limit + observability. F-012 also requires admin REST API endpoints for tenant CRUD, policy CRUD, key issuance. This is the original v1 F-009's "admin API" scope. Add an admin-api section to F-009, OR split into F-012a (admin API endpoints) preceding F-012 (frontend). Recommend F-012a as a thin addition since it shares persistence layer with F-008 CLI.

**Realistic:** 20-28h (Complex) · **Optimistic:** 16h
**Depends on:** F-009 (admin API), F-008
**Builder agent:** frontend
**Risk:** Low — but frontends always run longer than expected

### F-013 — Dashboards (security + compliance + governance) 📋 PLANNED
**Description:** Three dashboards in the admin frontend. Security: real-time event feed via WebSocket, per-team/per-model breakdowns, signature verification status. Compliance: readiness score, gap report, evidence pack download. Governance: model inventory, classifier model selection per tenant, shadow-AI detection feed (live via F-007 egress monitor).

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-005, F-011, F-012
**Builder agent:** frontend
**Risk:** Low

### F-014 — SSO (OIDC + SAML) 📋 PLANNED
**Description:** OIDC and SAML middleware for the admin console and API. Tested with at least one provider each. Group claim → role mapping configurable per tenant.

**Realistic:** 12-18h (Complex) · **Optimistic:** 8h
**Depends on:** F-003, F-012
**Builder agent:** platform-infra
**Risk:** Medium — SAML in particular has lots of quirks

### F-015 — Bulk processing pipeline 📋 PLANNED
**Description:** Async batch processing. Presigned S3/MinIO uploads. Sub-batches enqueued to Redis Streams (now relevant since F-009 introduces Redis), Arq worker pool, KEDA autoscaling. DLQ, checkpointing, per-file outcome manifest, idempotency keys. Target: 5000 files in under 5 minutes with 10-20 workers.

**Realistic:** 22-30h (Complex) · **Optimistic:** 16h
**Depends on:** F-003, F-005, F-009, F-010
**Builder agent:** bulk-pipeline
**Risk:** High — async pipelines have many failure modes

**Phase 2 totals: 4 tasks, ~12-14 days realistic.**

---

## Phase 3 — Differentiated features

### F-016 — Code scanning on LLM outputs 📋 PLANNED
**Description:** Extract code blocks from LLM responses. Run Semgrep (p/python + p/security-audit + p/secrets) and Bandit. Optional gVisor sandbox. Return verdict PASS|WARN|BLOCK. Fail-safe: scanner error → WARN.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-005, F-006
**Builder agent:** code-scanning
**Risk:** Medium

### F-017 — JSON data-lock engine 📋 PLANNED
**Description:** Per-field locking in JSON payloads. Fields can be locked-until-condition (time, permission grant, approval). Schema-driven; tenant-configurable.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-005, F-008
**Builder agent:** policy-engine
**Risk:** Medium

### F-018 — Shadow-AI detection ✅ MERGED INTO F-007 (Path Y, 2026-06-18)
**Description:** Real shadow-AI detection on top of F-005's emission primitive. Approach: outbound egress monitoring via httpx middleware (detects models that route through Sentinel but to disallowed endpoints) + DNS-based detection (optional, requires running Sentinel as DNS resolver in the corporate network). Heuristic + traffic-pattern analysis. Admin UI shows attributed teams.

**Honest scope statement:** Detects traffic that flows THROUGH Sentinel to disallowed endpoints. Does NOT detect traffic that bypasses Sentinel entirely (that's a network-layer problem requiring CASB or firewall integration; out of scope).

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-005 (emission seam already exists), F-013
**Builder agent:** defense
**Risk:** Medium — detection accuracy will need iteration with real data

### F-019 — Custom model + fine-tune policies 📋 PLANNED
**Description:** Approval workflow for new model adoption and custom fine-tunes. Inventory tracking. Approval audit trail. Allow/deny enforcement at gateway level. Builds on F-008's ModelAllowlistPolicy variant.

**Realistic:** 8-12h (Tricky) · **Optimistic:** 6h
**Depends on:** F-008, F-012
**Builder agent:** policy-engine
**Risk:** Low

### F-020 — Integration suite (Slack, Jira, Splunk webhooks) 📋 PLANNED
**Description:** Outbound webhooks for security events. Pre-built integrations: Slack channel notifications for HIGH/CRITICAL events, Jira ticket creation for policy violations, Splunk HEC for SIEM forwarding. Configurable per tenant.

**Realistic:** 8-12h (Tricky) · **Optimistic:** 6h
**Depends on:** F-005, F-009
**Builder agent:** orchestration-hooks
**Risk:** Low

### F-021 — Advanced governance UI 📋 PLANNED
**Description:** Model inventory dashboard. Approval workflows in UI. Model retirement workflow with grace periods.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-019, F-013
**Builder agent:** frontend
**Risk:** Low

**Phase 3 totals: 6 tasks, ~10-12 days realistic.**

---

## Phase 4 — Scale and polish

### F-022 — Multi-region deployment 🔮 SPECULATIVE
**Description:** Helm chart supports multi-region active-active or active-passive. Regional data residency. Geo-routing at ingress. Cross-region replication for policies and audit log.

**Realistic:** 22-30h (Complex/Heavy) · **Optimistic:** 16h
**Depends on:** F-010, F-003
**Builder agent:** platform-infra
**Risk:** High

### F-023 — Performance hardening 🔮 SPECULATIVE
**Description:** Real load testing against p95 < 200ms target. Profile-guided optimization. Connection pooling audit. Cache layer for policy evaluation. Per-module perf budgets.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-010
**Builder agent:** perf-load-engineer
**Risk:** Medium

### F-024 — Disaster recovery 🔮 SPECULATIVE
**Description:** Backup/restore procedures. Failover runbook. RPO/RTO targets validated. Cross-region failover drill in helm chart.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-022
**Builder agent:** platform-infra
**Risk:** Low

### F-025 — Self-serve onboarding 🔮 SPECULATIVE
**Description:** Trial signup flow. Guided setup wizard. Sample policies pre-loaded. Sample API calls in docs against sandbox tenant.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-012, F-013
**Builder agent:** frontend
**Risk:** Low

**Phase 4 totals: 4 tasks, ~8-10 days realistic.**

---

## Phase 5 — Blueprint additions

### F-026 — MCP & Third-Party Integration Layer 🔮 SPECULATIVE
**Description:** Secure proxy and governance framework for external MCP servers, AI tools, and third-party APIs. Per-tenant allow-lists. Inspection of MCP traffic (PII, injection, secret leak) applied uniformly. Audit logs for MCP interactions.

**Realistic:** 22-30h (Complex) · **Optimistic:** 16h
**Depends on:** F-005, F-006, F-008
**Builder agent:** gateway-core + integrations
**Risk:** High

### F-027 — Provider Key Vaulting 🔮 SPECULATIVE
**Description:** Vault or KMS integration for upstream provider API keys. Currently in F-004 they're env-var-loaded; this hardens to runtime fetch + rotation support.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-004
**Builder agent:** platform-infra
**Risk:** Medium

### F-028 — Custom Client-Defined PII Engine 🔮 SPECULATIVE
**Description:** Per-tenant custom PII patterns (regex + ML hooks). Currently F-005 ships fixed Presidio patterns; this lets enterprise customers define proprietary patterns (e.g., internal account number formats).

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-005, F-008
**Builder agent:** data-protection
**Risk:** Medium

### F-029 — HIPAA Compliance Module 🔮 SPECULATIVE
**Description:** HIPAA-specific control mappings on top of F-011. PHI detection patterns. BAA-ready audit trail format. Encryption requirements verification.

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-011, F-028
**Builder agent:** compliance-engine
**Risk:** Medium

### F-030 — EU AI Act Compliance Module 🔮 SPECULATIVE
**Description:** EU AI Act-specific control mappings. High-risk system classification helpers. Transparency report generation. Article 13 disclosure templates.

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-011
**Builder agent:** compliance-engine
**Risk:** Medium

### F-031 — Production Due-Diligence Gate 🔮 SPECULATIVE
**Description:** Pre-launch checklist tool. Automated verification of: secrets vaulted, audit chain valid, all migrations applied, all CRITICAL+HIGH security findings closed, performance SLOs validated.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-011, F-027
**Builder agent:** compliance-engine
**Risk:** Low

### F-032 — Practical Zero-Knowledge Storage SDK 🔮 SPECULATIVE
**Description:** Client-side encryption SDK. Keys never leave client. Server stores ciphertext-only. Search via encrypted indexes (deterministic encryption for equality, order-preserving optional).

**Realistic:** 22-30h (Heavy) · **Optimistic:** 16h
**Depends on:** F-004
**Builder agent:** data-protection
**Risk:** High

### F-033 — Multi-Layer Tokenization Architecture 🔮 SPECULATIVE
**Description:** Reversible tokenization for PII via encrypted Postgres token store. Format-preserving encryption. Token vault separate from main data.

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** F-005, F-027
**Builder agent:** data-protection
**Risk:** Medium

### F-034 — Internal Service Mesh Auth (mTLS) 🔮 SPECULATIVE
**Description:** mTLS between Sentinel components and between Sentinel and other ecosystem products (Orchestrator, Delta). Certificate provisioning via cert-manager. Auto-rotation.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** F-010
**Builder agent:** platform-infra
**Risk:** Medium

### F-035 — External Pen-Test Pass 🔮 SPECULATIVE
**Description:** Third-party penetration test of the production deployment. Findings cycle.

**Realistic:** 5-15 days calendar (external firm + findings remediation)
**Depends on:** F-010, F-011, F-027 merged
**Builder agent:** human + security-auditor (Sentinel-side remediation)
**Risk:** High — findings cycle could extend timeline

### F-036 — Self-Hosted / Air-Gapped Enterprise Deployment 🔮 SPECULATIVE
**Description:** Different from F-022's multi-region. Air-gapped = no internet. Offline installation packages. Internal mirror support. Offline license validation. Documentation for ops teams without external connectivity.

**Realistic:** 22-30h (Complex) · **Optimistic:** 16h
**Depends on:** F-010, F-027
**Builder agent:** platform-infra
**Risk:** Medium

**Phase 5 totals: 11 tasks, ~30 days realistic + external pen-test cycle.**

---

**Sentinel grand total v2: 37 tasks (9 shipped + 28 remaining), ~70 days realistic remaining.**

---

# PRODUCT 2: ANORYX AI ORCHESTRATOR

The ecosystem broker. Sentinel emits events up, Delta pushes policies down, this routes between them. Build after Sentinel Phase 1 ships (i.e., after F-011 lands).

## Phase 0 — Orchestrator contracts

### O-001 — Internal API contract 📋 PLANNED
**Description:** OpenAPI spec for Orchestrator's APIs: event ingest from Sentinel, policy distribution to Sentinel, query API for Delta. mTLS authentication between products.

**Realistic:** 6-8h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** F-002
**Builder agent:** api-architect
**Risk:** Medium

### O-002 — Ecosystem event bus contract 📋 PLANNED
**Description:** Standardized event envelope for cross-product events. Replay semantics. Dead-letter handling. Schema versioning policy.

**Realistic:** 6-8h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** O-001, F-002
**Builder agent:** api-architect
**Risk:** Medium

## Phase 1 — Orchestrator MVP

### O-003 — Event ingest pipeline 📋 PLANNED
**Description:** Consumer for Sentinel's event stream (via Redis Streams or webhook, depending on F-009 implementation). Validates against `events.schema.json`. Persists with full audit. Forwards to Delta and other subscribers.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** O-001, F-005, F-009
**Builder agent:** orchestration-hooks
**Risk:** Medium

### O-004 — Policy distribution engine 📋 PLANNED
**Description:** Receives policies from Delta. Validates against `policy.schema.json` (LOCKED at F-008). Signs records on behalf of Delta if Delta isn't signing yet. Distributes to target Sentinel instances via authenticated push to the F-008 intake API. Tracks distribution status, retries failures, alerts on persistent failures.

**Note:** Original v1 had Sentinel exposing a POST `/v1/internal/policies` endpoint. v2 reality: F-008 ships internal Python API only. Orchestrator → Sentinel push requires either (a) Orchestrator running CLI commands against Sentinel, or (b) Sentinel exposing a thin admin endpoint (would be added in F-012's admin API surface). Recommend (b) when O-004 ships.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** O-001, F-008, F-012 (admin API)
**Builder agent:** orchestration-hooks
**Risk:** High

### O-005 — Multi-Sentinel coordination 📋 PLANNED
**Description:** Registry of all Sentinel instances across the org. Health checks. Coordinated policy push. Capability discovery.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** O-003, O-004
**Builder agent:** platform-infra
**Risk:** Medium

### O-006 — Persistence + audit 📋 PLANNED
**Description:** Postgres schema for events, policies (versioned), distribution status, Sentinel registry. Same hash-chained audit pattern as Sentinel F-003.

**Realistic:** 6-10h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** O-001
**Builder agent:** persistence
**Risk:** Low (reuses Sentinel patterns)

### O-007 — Admin API + minimal UI 📋 PLANNED
**Description:** REST API for Orchestrator administration. Minimal Next.js UI for viewing Sentinel registry, recent events, policy distribution status.

**Realistic:** 16-20h (Tricky) · **Optimistic:** 12h
**Depends on:** O-003, O-004, O-005
**Builder agent:** frontend
**Risk:** Low

### O-008 — Deployment 📋 PLANNED
**Description:** Helm chart, K8s manifests, mTLS certificate provisioning, integration with Vault.

**Realistic:** 6-10h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** O-001, F-010
**Builder agent:** platform-infra
**Risk:** Medium

## Phase 2 — Production hardening

### O-009 — Predictive scaling 🔮 SPECULATIVE
**Description:** Analyze telemetry from Sentinel registry. Predict traffic spikes. The "Algorithmic CFO" features from the product spec.

**Realistic:** 16-22h (Complex) · **Optimistic:** 12h
**Depends on:** O-003, D-005
**Builder agent:** orchestration-hooks
**Risk:** Medium

### O-010 — Cross-product workflow engine 🔮 SPECULATIVE
**Description:** The "if X then Y across products" automation engine.

**Realistic:** 20-28h (Complex) · **Optimistic:** 16h
**Depends on:** O-003, O-004, D-006, R-008
**Builder agent:** orchestration-hooks
**Risk:** High

**Orchestrator total: 10 tasks, ~16-20 days realistic.**

---

# PRODUCT 3: DELTA

FinOps + ERP + budget policy for AI economics. Consumes Sentinel events through the Orchestrator, pushes budget policies back as signed records to Sentinel's F-008 intake.

## Phase 0 — Delta contracts

### D-001 — Financial domain model 📋 PLANNED
**Description:** Tokens, budgets, allocations, ledger entries, departments, projects, cost centers. Double-entry accounting schema. Reconciliation rules. Time-series schema for burn rate.

**Realistic:** 10-14h (Tricky) · **Optimistic:** 8h
**Depends on:** F-001
**Builder agent:** api-architect
**Risk:** Medium

### D-002 — Budget policy schema 📋 PLANNED
**Description:** Hard limits, soft warnings, escalation rules, time windows, scopes. Format must round-trip through `policy.schema.json` (LOCKED at F-008) so Sentinel can enforce them — specifically as BudgetLimitPolicy variants.

**Realistic:** 6-10h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** D-001, F-002, O-001
**Builder agent:** api-architect
**Risk:** Medium

## Phase 1 — Delta MVP

### D-003 — Sub-second double-entry ledger 📋 PLANNED
**Description:** High-throughput ledger persisting to Postgres + Redis. Atomic transactions, reversible entries. Sub-second commit latency under load. Append-only for audit.

**Realistic:** 20-28h (Complex) · **Optimistic:** 12h
**Depends on:** D-001
**Builder agent:** persistence
**Risk:** High — ledger correctness is non-negotiable

### D-004 — Event ingest from Orchestrator 📋 PLANNED
**Description:** Consumer for Sentinel usage events (via Orchestrator). Converts to ledger debits. Idempotent.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** D-003, O-003
**Builder agent:** orchestration-hooks
**Risk:** Medium

### D-005 — Budget engine 📋 PLANNED
**Description:** Evaluates spend against budgets in real time. Triggers alerts at thresholds. Sub-second enforcement: when budget hits cap, immediately publish a deny policy via Orchestrator → Sentinel blocks further requests via F-008 enforcement layer.

**Realistic:** 16-22h (Complex) · **Optimistic:** 8h
**Depends on:** D-002, D-003, D-004, O-004, F-008
**Builder agent:** policy-engine
**Risk:** High — this is the killer-feature loop

### D-006 — Budget allocation UI 📋 PLANNED
**Description:** Admin console for distributing budgets. Approval workflows. History of changes.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** D-002, D-005
**Builder agent:** frontend
**Risk:** Low

### D-007 — Live cost-to-value dashboards 📋 PLANNED
**Description:** Real-time spend visualization. Burn rate over time. Top spenders. Cost per request, cost per outcome.

**Realistic:** 12-16h (Tricky) · **Optimistic:** 8h
**Depends on:** D-003, D-006
**Builder agent:** frontend
**Risk:** Low

### D-008 — Deployment 📋 PLANNED
**Description:** Helm chart. mTLS to Orchestrator. Shared Vault. Postgres + Redis as managed dependencies.

**Realistic:** 6-10h (Easy-Tricky) · **Optimistic:** 4h
**Depends on:** D-005
**Builder agent:** platform-infra
**Risk:** Low

## Phase 2 — Analytics + forecasting

### D-009 — Burn rate forecasting 🔮 SPECULATIVE
**Realistic:** 8-12h · **Depends on:** D-003, D-007

### D-010 — Cost optimization recommendations 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** D-007, D-009

### D-011 — Chargeback and showback reports 🔮 SPECULATIVE
**Realistic:** 8-12h · **Depends on:** D-003

### D-012 — Anomaly detection 🔮 SPECULATIVE
**Realistic:** 8-12h · **Depends on:** D-003, D-007

## Phase 3 — ERP integrations

### D-013 — Cloud cost sync (AWS/GCP/Azure) 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** D-003

### D-014 — Generic ERP integration (NetSuite, SAP) 🔮 SPECULATIVE
**Realistic:** 22-30h · **Depends on:** D-011, D-013

### D-015 — Procurement integration (Coupa, Ariba) 🔮 SPECULATIVE
**Realistic:** 16-22h · **Depends on:** D-014

### D-016 — Executive financial dashboard 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** D-007, D-009, D-011, F-011

**Delta total: 16 tasks, ~28-32 days realistic.**

---

# PRODUCT 4: RENDLY

Real-time intent-based video matching platform. Both B2C (consumer social) and B2B (enterprise team matching). Both surfaces run on the same underlying matching + WebRTC + chat PaaS, which integrates with Sentinel for security, Delta for billing/budgets, Orchestrator for cross-product workflows.

## Phase 0 — Rendly contracts

### R-001 — Core platform API contract 📋 PLANNED
**Realistic:** 10-14h · **Depends on:** F-001

### R-002 — Intent + matching domain model 📋 PLANNED
**Realistic:** 6-10h · **Depends on:** R-001

## Phase 1 — Rendly platform MVP

### R-003 — Authentication (OAuth + JWT) 📋 PLANNED
**Realistic:** 10-14h · **Depends on:** R-001

### R-004 — User profiles + persistence 📋 PLANNED
**Realistic:** 10-14h · **Depends on:** R-002, R-003

### R-005 — Matching algorithm 📋 PLANNED
**Realistic:** 16-22h · **Depends on:** R-002, R-004

### R-006 — Real-time chat (WebSocket) 📋 PLANNED
**Realistic:** 12-16h · **Depends on:** R-004

### R-007 — WebRTC video calling (1-on-1) 📋 PLANNED
**Realistic:** 22-30h · **Depends on:** R-006

### R-008 — Sentinel integration for safety 📋 PLANNED
**Realistic:** 10-14h · **Depends on:** R-006, F-005, F-007

### R-009 — Group huddles 🔮 SPECULATIVE
**Realistic:** 16-22h · **Depends on:** R-007

### R-010 — Safety + moderation 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-004, R-008

### R-011 — Deployment 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-007, F-010

## Phase 2 — B2C consumer features

### R-012 — Consumer onboarding 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** R-005, R-007

### R-013 — Discovery feed (B2C) 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-005

### R-014 — Premium features + monetization (B2C) 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-013, D-003

### R-015 — Creator economy features 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-014

## Phase 3 — B2B enterprise features

### R-016 — Tenant + RBAC for B2B 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** R-004, F-008

### R-017 — Intent-driven talent routing (B2B) 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-005, R-016

### R-018 — Skills inventory 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** R-004, R-016

### R-019 — Project + sprint workspaces 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-009, R-016

### R-020 — B2B analytics dashboard 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-017, D-007

## Phase 4 — Platform-as-a-Service

### R-021 — Public API for embedding Rendly 🔮 SPECULATIVE
**Realistic:** 16-22h · **Depends on:** R-007, R-005, F-004, D-003

### R-022 — Developer portal + docs 🔮 SPECULATIVE
**Realistic:** 12-16h · **Depends on:** R-021

**Rendly total: 22 tasks, ~42-50 days realistic.**

---

# CROSS-PRODUCT INTEGRATION

Tasks that explicitly wire products together and prove the ecosystem story end-to-end.

### X-001 — Sentinel ↔ Orchestrator wiring validated 📋 PLANNED
**Realistic:** 6-10h · **Depends on:** F-005, O-003

### X-002 — Orchestrator ↔ Delta wiring validated 📋 PLANNED
**Realistic:** 6-10h · **Depends on:** O-003, D-004

### X-003 — Budget enforcement loop (the killer feature) 📋 PLANNED
**Description:** Delta budget hits cap → policy pushed via Orchestrator → Sentinel blocks team's next request within 1 second. End-to-end test from budget-set to enforcement-active. Demonstrates the F-008 policy enforcement layer + Orchestrator distribution + Delta budget engine working as a unit.

**Realistic:** 10-14h · **Depends on:** D-005, O-004, F-008

### X-004 — Rendly ↔ Sentinel safety integration 🔮 SPECULATIVE
**Realistic:** 6-10h · **Depends on:** R-008

### X-005 — Rendly ↔ Delta monetization wiring 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** R-014, D-003

### X-006 — End-to-end ecosystem demo 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** All major component tasks

**Cross-product total: 6 tasks, ~7-10 days realistic.**

---

# RECOMMENDED SEQUENCE (β path)

This is the recommended dispatch order for the next 6-12 months, optimizing for **demo-readiness, then depth, then breadth.**

## Next 4 weeks (demo-readiness sprint)

1. **F-009** Rate limiting + observability — unblocks ops visibility
2. **F-010** Deployment (Docker compose + Helm) — unblocks first design partner
3. **F-007** ML injection classifier — adds depth to security story before demos
4. **F-011** Compliance engine — buyer enablement (SOC 2 evidence pack)

After this 4-week block, you have a demoable, deployable, monitorable Sentinel with a credible compliance story. **This is the natural moment to start design-partner outreach** (regardless of the broader "build everything first" strategy — having something to show makes every outreach conversation 10x better).

## Next 4-8 weeks (Sentinel Phase 2)

5. **F-012** Admin console (includes the admin REST API endpoints)
6. **F-013** Dashboards
7. **F-014** SSO
8. **F-015** Bulk processing pipeline

After Phase 2, Sentinel is "enterprise procurement will buy this."

## Next 8-16 weeks (Sentinel Phase 3 + selected Phase 5)

9-14. **F-016 through F-021** Differentiated features (code scanning, JSON lock, shadow-AI, governance UI)
15. **F-026** MCP integration layer (blueprint differentiator)
16. **F-029** HIPAA compliance module (vertical-specific differentiator)
17. **F-030** EU AI Act compliance module (vertical-specific differentiator)

## Next 16-26 weeks (Orchestrator + Delta MVP)

18. **O-001 through O-008** Orchestrator MVP
19. **D-001 through D-008** Delta MVP
20. **X-001, X-002, X-003** Cross-product wiring (proves the killer feature)

## Next 26+ weeks (Rendly + remaining)

21. **R-001 through R-011** Rendly platform MVP
22. **R-012 through R-022** Rendly B2C + B2B features
23. Remaining Sentinel Phase 4 + 5 tasks
24. **F-035** External pen-test (scheduled when production-ready)

---

# CHECKLIST

## Sentinel — 37 tasks (9 shipped + 28 remaining)

- [x] F-001 OpenAPI contract — SHIPPED
- [x] F-002 Event + policy schemas — SHIPPED
- [x] F-003 Persistence + hash-chained audit — SHIPPED
- [x] F-003b Tenant isolation RLS — SHIPPED ➕
- [x] F-004 Gateway core — SHIPPED
- [x] F-005 Orchestration hooks + 4 detectors — SHIPPED
- [x] F-006 Multi-provider router — SHIPPED
- [ ] F-007 ML injection classifier — Tricky-Complex (12-16h) 🔄 NEXT after F-009+F-010
- [x] F-008 Policy intake + ECDSA-signed enforcement — SHIPPED
- [ ] F-009 Rate limiting + observability — Tricky-Complex (12-16h) 🔄 NEXT
- [ ] F-010 Deployment (Docker + Helm) — Complex (16-20h) 🔄 NEXT after F-009
- [ ] F-011 Compliance engine (SOC 2 + GDPR) — Complex (16-22h)
- [ ] F-012 Admin console (incl. admin API) — Complex (20-28h)
- [ ] F-013 Dashboards — Tricky (12-16h)
- [ ] F-014 SSO (OIDC + SAML) — Complex (12-18h)
- [ ] F-015 Bulk processing pipeline — Complex (22-30h)
- [ ] F-016 Code scanning on LLM outputs — Tricky (12-16h)
- [ ] F-017 JSON data-lock engine — Tricky (12-16h)
- [x] F-018 Shadow-AI detection — MERGED INTO F-007 on 2026-06-18 (Path Y)
- [ ] F-019 Custom model + fine-tune policies — Tricky (8-12h)
- [ ] F-020 Integration suite (Slack/Jira/Splunk) — Tricky (8-12h)
- [ ] F-021 Advanced governance UI — Tricky (12-16h)
- [ ] F-022 Multi-region deployment — Complex (22-30h)
- [ ] F-023 Performance hardening — Tricky (12-16h)
- [ ] F-024 Disaster recovery — Tricky (12-16h)
- [ ] F-025 Self-serve onboarding — Tricky (12-16h)
- [ ] F-026 MCP & Third-Party Integration Layer — Complex (22-30h)
- [ ] F-027 Provider Key Vaulting — Tricky (12-16h)
- [ ] F-028 Custom Client-Defined PII Engine — Complex (16-22h)
- [ ] F-029 HIPAA Compliance Module — Complex (16-22h)
- [ ] F-030 EU AI Act Compliance Module — Complex (16-22h)
- [ ] F-031 Production Due-Diligence Gate — Tricky (12-16h)
- [ ] F-032 Practical Zero-Knowledge Storage SDK — Heavy (22-30h)
- [ ] F-033 Multi-Layer Tokenization Architecture — Complex (16-22h)
- [ ] F-034 Internal Service Mesh Auth (mTLS) — Tricky (12-16h)
- [ ] F-035 External Pen-Test Pass — External (1-3 weeks)
- [ ] F-036 Self-Hosted / Air-Gapped Deployment — Complex (22-30h)

**Sentinel remaining target: ~70-80 days fleet work + external pen-test cycle.**

## Orchestrator — 10 tasks

- [ ] O-001 Internal API contract — Easy-Tricky (6-8h)
- [ ] O-002 Ecosystem event bus contract — Easy-Tricky (6-8h)
- [ ] O-003 Event ingest pipeline — Tricky (12-16h)
- [ ] O-004 Policy distribution engine — Tricky (12-16h)
- [ ] O-005 Multi-Sentinel coordination — Tricky (12-16h)
- [ ] O-006 Persistence + audit — Easy-Tricky (6-10h)
- [ ] O-007 Admin API + minimal UI — Tricky (16-20h)
- [ ] O-008 Deployment — Easy-Tricky (6-10h)
- [ ] O-009 Predictive scaling — Complex (16-22h)
- [ ] O-010 Cross-product workflow engine — Complex (20-28h)

**Orchestrator total: ~16-20 days fleet work.**

## Delta — 16 tasks

- [ ] D-001 Financial domain model — Tricky (10-14h)
- [ ] D-002 Budget policy schema — Easy-Tricky (6-10h)
- [ ] D-003 Sub-second double-entry ledger — Complex (20-28h)
- [ ] D-004 Event ingest from Orchestrator — Tricky (12-16h)
- [ ] D-005 Budget engine — Complex (16-22h)
- [ ] D-006 Budget allocation UI — Tricky (12-16h)
- [ ] D-007 Live cost-to-value dashboards — Tricky (12-16h)
- [ ] D-008 Deployment — Easy-Tricky (6-10h)
- [ ] D-009 Burn rate forecasting — Tricky (8-12h)
- [ ] D-010 Cost optimization recommendations — Tricky (12-16h)
- [ ] D-011 Chargeback and showback reports — Tricky (8-12h)
- [ ] D-012 Anomaly detection — Tricky (8-12h)
- [ ] D-013 Cloud cost sync — Tricky (12-16h)
- [ ] D-014 Generic ERP integration — Complex (22-30h)
- [ ] D-015 Procurement integration — Complex (16-22h)
- [ ] D-016 Executive financial dashboard — Tricky (12-16h)

**Delta total: ~28-32 days fleet work.**

## Rendly — 22 tasks

- [ ] R-001 Core platform API contract — Tricky (10-14h)
- [ ] R-002 Intent + matching domain model — Easy-Tricky (6-10h)
- [ ] R-003 Authentication — Tricky (10-14h)
- [ ] R-004 User profiles + persistence — Tricky (10-14h)
- [ ] R-005 Matching algorithm — Complex (16-22h)
- [ ] R-006 Real-time chat — Tricky (12-16h)
- [ ] R-007 1-on-1 video (WebRTC) — Complex (22-30h)
- [ ] R-008 Sentinel integration for safety — Tricky (10-14h)
- [ ] R-009 Group huddles — Complex (16-22h)
- [ ] R-010 Safety + moderation — Tricky (12-16h)
- [ ] R-011 Deployment — Tricky (12-16h)
- [ ] R-012 Consumer onboarding — Tricky (10-14h)
- [ ] R-013 Discovery feed (B2C) — Tricky (12-16h)
- [ ] R-014 Premium features (B2C monetization) — Tricky (12-16h)
- [ ] R-015 Creator economy — Tricky (12-16h)
- [ ] R-016 B2B tenant + RBAC — Tricky (10-14h)
- [ ] R-017 Intent-driven talent routing (B2B) — Tricky (12-16h)
- [ ] R-018 Skills inventory — Tricky (10-14h)
- [ ] R-019 Project + sprint workspaces — Tricky (12-16h)
- [ ] R-020 B2B analytics — Tricky (12-16h)
- [ ] R-021 Public PaaS API — Complex (16-22h)
- [ ] R-022 Developer portal — Tricky (12-16h)

**Rendly total: ~42-50 days fleet work.**

## Cross-product — 6 tasks

- [ ] X-001 Sentinel ↔ Orchestrator wiring — Easy-Tricky (6-10h)
- [ ] X-002 Orchestrator ↔ Delta wiring — Easy-Tricky (6-10h)
- [ ] X-003 Budget enforcement loop — Tricky (10-14h)
- [ ] X-004 Rendly ↔ Sentinel safety — Easy-Tricky (6-10h)
- [ ] X-005 Rendly ↔ Delta monetization — Tricky (10-14h)
- [ ] X-006 End-to-end ecosystem demo — Tricky (10-14h)

**Cross-product total: ~7-10 days fleet work.**

---

# Ecosystem totals (remaining)

| Category | Sentinel | Orchestrator | Delta | Rendly | Cross | **Total** |
|----------|----------|--------------|-------|--------|-------|-----------|
| **Tasks remaining** | 28 | 10 | 16 | 22 | 6 | **82** |
| **Realistic days** | ~70-80 | ~16-20 | ~28-32 | ~42-50 | ~7-10 | **~165-190** |

**~165-190 fleet days plus external pen-test.** At 6 productive days/week with 6-8 productive hours/day, that's **~7-9 months solo** to ship the full ecosystem to v1.

---

# Strategic notes (carry-over from prior sessions)

## Velocity calibration (based on F-001-F-008 actual throughput)

- **Easy tasks** (F-002 type): 4-6h fleet + 30-45 min Affu gate decisions
- **Tricky tasks** (F-003b type): 8-12h fleet + 1-2h Affu gate decisions
- **Complex tasks** (F-004, F-005, F-006 type): 16-28h fleet + 2-4h Affu gate decisions spread over 1-2 days
- **Heavy tasks** (F-008 type — cryptographic/contractual): 22-30h fleet + 4-6h Affu gate decisions spread over 2-3 days

These ranges assume the established discipline: STEP gates with security-auditor verdict at penultimate gate, ADR for non-obvious decisions, persistent audit artifact for security tasks.

## Market window context

The AI infrastructure market window was assessed at 12-18 months from June 2026 before consolidation. At current pace (~3 weeks for the Sentinel-Phase-1-demo-ready milestone), getting in front of design partners by month 2-3 is realistic and preserves enough of the window for a seed pitch by month 6-9.

## Sequencing flexibility

The β sequence above is a recommendation, not a constraint. Real product decisions may bump priorities:

- **A buyer asks for X** → bump X to next
- **A blocker is discovered** → fix the blocker before continuing
- **Outreach starts and a design partner requests Y** → Y becomes the next task

The roadmap is a guide, not a contract. Update it when reality changes.

---

**End of roadmap v2. Keep this open on a second monitor. Check off as you ship. Reassess monthly.**
