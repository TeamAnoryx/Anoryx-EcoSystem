# Anoryx Ecosystem — Complete Build Roadmap (v3)

**Owner:** Affu (TeamAnoryx)
**Last updated:** 2026-07-07
**Status:** Sentinel MVP complete — F-001 through F-021 merged incl. F-007 (ML classifier) + F-010 (deployment, both parts). Downstream MVPs underway: Orchestrator O-001→O-006 shipped (O-007/O-008 remain); Delta D-001→D-005 shipped; Rendly R-001→R-006 shipped. Cross-product (X-) not yet started.
**Replaces:** anoryx-ecosystem-roadmap-v2.md (2026-06-18)

---

## What changed in v3

v2 (2026-06-18) was accurate as of F-008. Between then and 2026-06-25, the Sentinel build sprinted through **F-011 → F-021** (eleven more features) plus the earlier F-009/F-012a/F-014/F-015. v3 reconciles plan with reality again and — at the owner's direction — **expands the scope of Delta, Rendly, and the Orchestrator** to reflect their true product vision, splitting each into a committed MVP track and a post-investment vision track.

### Two things v3 does

1. **Reconciles Sentinel shipped state** — F-009 through F-021 are now ✅ SHIPPED (merged, CI green, security-audited). Counts, totals, sequence, and checklist updated accordingly. F-010 (deployment) — stepped over for 13 features as the design-partner unlock — has since shipped (Part 1 compose #27 + Part 2 Helm #38); the first unshipped Sentinel task is now F-022 (Phase 4).

2. **Expands Delta / Rendly / Orchestrator scope.** The original task lists captured only a slice of each product. v3 keeps the **near-term MVP** as the committed, next-buildable path and adds the **full product vision** as a clearly-marked later tier (see new status label below). The MVP is what you build now; the vision is funded-future.

### New status label in v3

- **🏦 POST-INVESTMENT** — In scope for the product vision, but **scheduled for after a funding round.** These are real, intended features, not speculation — but they are explicitly *not* the next-buildable work and should not be dispatched before the MVP tracks ship and capital is in. Distinct from 🔮 SPECULATIVE (which means "scope may need refinement when reached").

---

## Verified shipped state (Sentinel, on main as of 2026-07-07)

| ID | Feature | Status | Merge / PR |
|----|---------|--------|-----------|
| F-001 | OpenAI-compatible API contract | ✅ SHIPPED | `59bc234` |
| F-002 | Event + policy JSON schemas | ✅ SHIPPED | locked at F-008 `a9e2344` |
| F-003 | Persistence + hash-chained audit | ✅ SHIPPED | — |
| F-003b | Runtime tenant isolation (RLS) ➕ | ✅ SHIPPED | — |
| F-004 | Gateway core | ✅ SHIPPED | — |
| F-005 | Orchestration hooks + 4 detectors | ✅ SHIPPED | — |
| F-006 | Multi-provider model router (native) | ✅ SHIPPED | — |
| F-007 | ML injection classifier (LLM-as-judge) | ✅ SHIPPED | PR #12 `6a386c3` (+#31 thresholds, +#34 FU `d7f1505`) |
| F-008 | Policy intake + ECDSA-signed enforcement | ✅ SHIPPED | PR #11 |
| F-009 | Rate limiting + observability | ✅ SHIPPED | — |
| F-010 | Deployment (Docker compose + Helm) | ✅ SHIPPED | PR #27 `6907b9a` (Part 1) + PR #38 `743ee52` (Part 2) |
| F-011 | Compliance engine (SOC 2 + GDPR) | ✅ SHIPPED | PR #15 `ff46ea9` |
| F-012a | Admin console API | ✅ SHIPPED | PR #16 `2226bb2` |
| F-012 | Admin console frontend | ✅ SHIPPED | PR #17 `a987a89` |
| F-013 | Dashboards (security/compliance/governance) | ✅ SHIPPED | PR #18 `07847d7` |
| F-014 | SSO (OIDC + SAML) | ✅ SHIPPED | PR #19 `185654b` |
| F-015 | Bulk processing pipeline | ✅ SHIPPED | PR #20 `bbeba12` |
| F-016 | Code scanning on LLM outputs | ✅ SHIPPED | PR #21 `dcd58dd` |
| F-017 | JSON data-lock engine | ✅ SHIPPED | PR #22 `6c30088` |
| F-018 | Shadow-AI detection | ✅ SHIPPED | PR #23 `6057518` |
| F-019 | Custom model + fine-tune approval policies | ✅ SHIPPED | PR #24 `1a823bf` |
| F-020 | Integration suite (Slack/Jira/Splunk) | ✅ SHIPPED | PR #25 `eb281a8` |
| F-021 | Advanced governance UI | ✅ SHIPPED | PR #26 `d044ed6` |

**Not yet shipped (Sentinel):** F-022–F-036 only (Phase 4/5 scale/polish — all 🔮 SPECULATIVE). Every Phase 0–3 feature F-001→F-021 (incl. F-007 + F-010 both parts) is shipped.

---

## Verified shipped state (Orchestrator / Delta / Rendly, on main as of 2026-07-07)

v3's original "Orchestrator / Delta / Rendly not yet started" is obsolete — all three MVP tracks are underway and partly shipped.

| ID | Task | Status | Merge / PR |
|----|------|--------|-----------|
| O-001 | Internal API contract | ✅ SHIPPED | PR #28 `7d5986d` |
| O-002 | Ecosystem event bus contract | ✅ SHIPPED | PR #35 `3fe98a3` |
| O-003 | Event ingest pipeline | ✅ SHIPPED | PR #37 `156c554` |
| O-004 | Policy distribution engine | ✅ SHIPPED | PR #42 `9f101b0` |
| O-005 | Multi-Sentinel coordination | ✅ SHIPPED | PR #43 `e9762db` |
| O-006 | Persistence consolidation + tenant-scoped read seams | ✅ SHIPPED | PR #47 `10f58c8` |
| D-001 | Financial domain model | ✅ SHIPPED | PR #30 `19bd41b` |
| D-002 | Budget policy schema | ✅ SHIPPED | PR #33 `c327b7e` |
| D-003 | Double-entry ledger persistence | ✅ SHIPPED | PR #39 `41848a2` |
| D-004 | Event ingest from Orchestrator | ✅ SHIPPED | PR #41 `49d7175` |
| D-005 | Budget engine (spend-vs-budget enforcement) | ✅ SHIPPED | PR #45 `04b893b` |
| R-001 | Core platform API contract | ✅ SHIPPED | PR #29 `309d6fc` |
| R-002 | Internal domain model | ✅ SHIPPED | PR #32 `182298c` |
| R-003 | Authentication (OAuth2 + JWT ES256) | ✅ SHIPPED | PR #36 `57b883f` |
| R-004 | User profiles + persistence | ✅ SHIPPED | PR #40 `382bcd1` |
| R-005 | Real-time chat (WebSocket) | ✅ SHIPPED | PR #44 `8351955` |
| R-006 | Role-based secure channels + manual team map | ✅ SHIPPED | PR #46 `a86f30b` |

**Remaining MVP:** Orchestrator O-007/O-008 · Delta D-006→D-012 · Rendly R-007→R-010 · all Cross-product X-001→X-006. Post-investment (🏦) tier unchanged. (D-006 kill-switch is in a worktree, ADR gate pending — NOT yet merged.)

---

## Banked process rules (carry into every build session)

These are hard-won from the F-001→F-021 sprint. A fresh session should treat them as standing law.

1. **CRIT-2 countermeasure (new policy_type).** Any feature adding a new `policy_type` to F-008's closed enum MUST: register it in `_VALID_POLICY_TYPES` + widen BOTH CHECK constraints (`ck_policies_policy_type` + `ck_pv_policy_type`) + a reversible migration + a NON-STUBBED persist→load test — done FIRST, before enforcement code. (F-016 nearly shipped completely inert because this was skipped.)
2. **Non-stubbed e2e is mandatory** at final verification for any enforcement feature. A test that stubs the path it claims to prove proves nothing. Prove the real allow AND the real deny on the real path.
3. **Independent / arms-length security audit.** The penultimate gate is an independent auditor that re-runs if the subagent return drops; never implementer-self-verified.
4. **CI is authoritative.** The local no-`.env` "CI-parity" check is masked by `load_dotenv` repopulating env — never trust a green local parity check. The GitHub Actions run on a fresh DB is the only authority. (Cost real cycles on F-017, F-019, F-020.)
5. **Fresh DB ≠ local DB.** Migrations can behave differently on a fresh CI DB vs. a persistent local one. Reprovision the local dev DB by dropping the schema and rebuilding (not `downgrade base`). Diagnose CI failures on a fresh DB before fixing.
6. **`get_tenant_session` autobegins** — do NOT wrap reads in `async with session.begin()` (raises "transaction already begun").
7. **Module-singleton engines must reset at setup, not just teardown** — a cached engine with a stale host/DSN pollutes later test packages (the F-019 root cause: a `_app_engine` singleton cached a fake host across packages).
8. **New audit columns follow the opt-in-when-present hash rule** (hashed iff not None → backward-compatible, tamper-evident when set). Touches `hash_chain.py` + `audit_log_repository`.
9. **Migration head-pin bumps touch prior-feature tests** — when you bump the head, update the reversibility tests in earlier feature packages that hardcode the old head.
10. **BFF-only frontend** — the admin UI consumes the API through the BFF proxy; never add silent backend endpoints from the frontend.
11. **Gate new test lanes in CI** — a separate vitest render/config lane must be invoked by the CI workflow, verified to execute (not skip). (F-018 lesson.)
12. **GitHub squash-merge is a manual action, separate from local git.** After clicking merge, run `git pull && git log --oneline -2` and SEE the merge commit on top BEFORE deleting any branch.
13. **Lean STEP-0 forks = smaller attack surface = more secure for absent demand.** Default to the minimal option (static-over-sandbox, dotted-path-over-JSONPath, defer approval/DNS, metadata-only egress). "More secure" usually means "less surface," not "more workflow."
14. **Honesty boundaries are non-removable.** When a feature's real scope is narrower than its name implies (F-018 detects only disallowed-known-provider egress, NOT bypass traffic; F-020 is metadata-only, NOT content egress), that limitation is stated verbatim in the ADR + UI + API and must not be implied away.

---

## How to read this document

**Task IDs.**

| Prefix | Product                    |
|--------|----------------------------|
| F-     | Anoryx Sentinel            |
| O-     | Anoryx AI Orchestrator     |
| D-     | Delta                      |
| R-     | Rendly                     |
| X-     | Cross-product integration  |

**Status labels:**

- **✅ SHIPPED** — Merged to main, CI green, security-auditor verdict CLEAN
- **🔄 NEXT** — Recommended next task per sequencing
- **📋 PLANNED** — Committed MVP scope, will be addressed in sequence
- **❓ RE-SCOPED** — In original roadmap but redefined based on shipped reality
- **🏦 POST-INVESTMENT** — In the product vision but scheduled for *after* a funding round; not next-buildable
- **🔮 SPECULATIVE** — Later-phase; scope may need refinement when reached
- **➕ NEW** — Added in this revision

**Estimates** are *fleet dispatch time including review and merge*, not raw coding time:
- **Easy** = 4-6h · **Tricky** = 8-12h · **Complex** = 16-28h · **Heavy** = 28h+ (cryptography, contracts, cross-product coordination)

**"Done" means:** (1) PR merged to main, (2) CI green on the merge commit, (3) security-auditor verdict CLEAN, (4) ADR for non-obvious decisions, (5) tests incl. adversarial threat model where security-relevant, (6) persistent `docs/audit/<task-id>-security-audit.md` for security tasks, (7) demoable end-to-end. If any is missing, it's in progress, not done.

**Risk:** Low (CRUD/config) · Medium (non-trivial logic, expect one audit finding) · High (sensitive trust boundary / external integration / complex async — budget 2x).

---

## Roadmap summary

| Product            | Tasks | Shipped | Remaining | Notes |
|--------------------|-------|---------|-----------|-------|
| Anoryx Sentinel    | 37    | 23      | 14        | F-007 + F-010 shipped; remaining = Phase 4/5 (F-022–F-036) |
| AI Orchestrator    | 14    | 6       | 8         | O-001→O-006 shipped; O-007/O-008 + ecosystem-integration + post-investment |
| Delta              | 28    | 5       | 23        | D-001→D-005 shipped; D-006→D-012 MVP + Enterprise-OS vision |
| Rendly             | 30    | 6       | 24        | R-001→R-006 shipped; R-007→R-010 MVP + culture/streaming/B2C vision |
| Cross-integration  | 6     | 0       | 6         | X-001→X-003 next (killer MVP loop) |
| **Total**          | **115**| **40** | **75**    | — |

**Current true state:** Sentinel MVP fully merged (F-001→F-021 incl. F-007 + F-010) — the stack is standable as one unit via `docker compose up` (F-010 Part 1) and Helm (Part 2). Orchestrator (O-001→O-006), Delta (D-001→D-005), and Rendly (R-001→R-006) MVP tracks are underway. Highest-leverage next: the X-001→X-003 cross-product killer loop (budget enforcement) — needs D-006 kill-switch to land first.

**Demo-readiness milestone:** REACHED for Sentinel — F-010 (`docker compose up` end-to-end) + F-007 (classifier depth) both shipped, atop the full F-011–F-021 compliance/enterprise surface. Design-partner-ready bar met.

**Known open gaps (non-feature):** (a) ~~F-010 deploy-wiring~~ — SHIPPED (#27 + #38); (b) ~~F-007 ML classifier~~ — SHIPPED (#12); (c) the most security-critical shipped code (F-012a/F-014/F-015/F-016 + the new O/D/R auth + RLS surfaces) has audits the owner has not yet personally read; (d) F-013.1 — compliance dashboard evidence-pack download deferred (`docs/followups/f-013-deferred-backend.md`).

---

# PRODUCT 1: ANORYX SENTINEL

The zero-trust AI gateway. Foundation for the entire ecosystem. Core promise: **data never leaves the organization.**

## Phase 0 — Contract lock ✅ COMPLETE

### F-001 — OpenAI-compatible API contract ✅ SHIPPED
**Merged:** `59bc234`. Full `openapi.yaml` (`/v1/chat/completions`, `/v1/completions`, `/v1/models`), VirtualApiKey auth, four stable IDs, SSE streaming contract. ADR-0002 (key-binding decision).

### F-002 — Event + policy JSON schemas ✅ SHIPPED
`events.schema.json` + `policy.schema.json` (Budget/ModelAllowlist/ModelDenylist). Draft 2020-12. `policy.schema.json` LOCKED at F-008 `a9e2344`.

---

## Phase 1 — Sentinel MVP backend

### F-003 — Persistence layer ✅ SHIPPED
Postgres schema (tenants, teams, users, virtual_api_keys, model_policies) + hash-chained `events_audit_log`. Alembic 0001-0005. ADR-0004.

### F-003b — Runtime tenant isolation (RLS) ✅ SHIPPED ➕
RLS on every tenant-scoped table. `sentinel_app` role (NOBYPASSRLS) for tenant sessions; privileged role for chain ops. ADR-0005. Added when cross-tenant leakage surfaced as real risk.

### F-004 — Gateway core ✅ SHIPPED
FastAPI implementing `openapi.yaml`. Virtual key auth → server-side tenant/team/project IDs. Non-bypassable ASGI terminal-audit middleware. ADR-0006. Router split to F-006.

### F-005 — Orchestration hooks + 4 detectors ✅ SHIPPED ❓ RE-SCOPED
Hook framework (pre/post), PII (Presidio), injection (regex), secret detector, shadow-AI emission primitive (seam only), parsed-structure outbound secret redaction. ADR-0007. Redis Streams emission deferred (webhook config path).

### F-006 — Multi-provider model router ✅ SHIPPED ❓ RE-SCOPED
Native router (no LiteLLM — ADR-0008). OpenAI/Anthropic/Bedrock adapters. Per-tenant `tenant_routing_policy` w/ RLS. Security-aware fallback. Stream-time cost enforcement. `routing_decision` event.

### F-007 — ML injection classifier ✅ SHIPPED
**Status:** SHIPPED — core PR #12 `6a386c3`, per-tenant thresholds PR #31 `d0a822c` (ADR-0025), double-begin fail-open fix PR #34 `d7f1505` (ADR-0026).
**Description:** LLM-as-judge classification step on the existing F-005 injection detector. Two preset adapters (Anthropic Haiku, OpenAI gpt-4o-mini), tenant-configurable. Regex pre-filter + structured output forcing + system-prompt hardening + advisory threshold. Final score = max(regex, judge).
**Realistic:** 12-16h (Tricky-Complex) · **Depends on:** F-006, F-008 · **Builder:** orchestration-hooks · **Risk:** Medium (recursive injection is the novel threat).

### F-008 — Policy intake + enforcement ✅ SHIPPED ❓ RE-SCOPED
**Merged:** PR #11. ECDSA P-256 (ES256) compact-JWS verification, scope-resolve-and-reject, replay/rollback defense, 3 variant handlers, content-hash signature binding, hash-chained audit on intake, F-006 router + cost integration, `sentinel-cli policy push/keygen`, ADR-0009 + 16-vector threat model. `policy.schema.json` LOCKED at `a9e2344`. No OPA.

### F-009 — Rate limiting + observability ✅ SHIPPED
Redis-backed rate limiting (moved off in-memory). Prometheus metrics (rps, error rate, p95, PII blocks/min, policy violations/min, classifier latency, `sentinel_audit_write_failures_total`). OpenTelemetry traces. Grafana JSON committed.

### F-010 — Deployment (Docker + Helm + self-host) ✅ SHIPPED
**Status:** SHIPPED both parts — Part 1 compose PR #27 `6907b9a` (`docker compose up` end-to-end), Part 2 Helm single-cluster PR #38 `743ee52` (ADR-0027, mirrors compose).
**Part 1 (compose — build first):** Multi-stage Dockerfiles (gateway/worker/frontend), root `docker-compose.yml` standing up gateway + console + worker + Postgres + Redis + MinIO, migrations auto-run to head on a fresh volume, healthchecks + dependency order, `.env.example` + gitignored `.env`, SECURITY.md, DEPLOY walkthrough. **Demo bar:** `docker compose up` → all healthy → console reachable + operator login → a real `/v1` request flows gateway→policy→DB and is governed → `down -v && up` reproduces clean.
**Part 2 (post-Part-1):** K8s manifests, Helm chart (managed-cloud + self-hosted VPC), Vault/KMS secrets, mTLS provisioning.
**Realistic:** Part 1 ~12-16h · Part 2 ~12-16h · **Depends on:** F-004/F-005/F-006/F-008 (+ all shipped features) · **Builder:** platform-infra · **Risk:** Medium (deployment reveals environmental assumptions).

### F-011 — Compliance engine ✅ SHIPPED
**Merged:** PR #15 `ff46ea9`. SOC 2 (TSC) + GDPR control mappings as versioned data. Automated checks (encryption_at_rest, audit_logging_active, rbac_enforced, pii_masking_active, signature_verification_active). Readiness score, gap report, signed evidence-pack ZIP export. *Open follow-up F-013.1: dashboard evidence-pack download + per-control gap report.*

---

## Phase 2 — Enterprise readiness ✅ SHIPPED

### F-012a — Admin console API ✅ SHIPPED
**Merged:** PR #16 `2226bb2`. First cross-tenant principal. Env `SENTINEL_ADMIN_TOKEN` (single-operator, deploy-injected, fail-closed, `hmac.compare_digest`, reserved `admin-console` slug, per-target `get_tenant_session`). ADR-0014. Audit f-012-security-audit.md.

### F-012 — Admin console frontend ✅ SHIPPED
**Merged:** PR #17 `a987a89`. Next.js console. Token-entry → signed httpOnly cookie (separate SESSION_SECRET, `timingSafeEqual`). BFF proxy (`api/admin/[...path]`), middleware route guard. `check:token` verifies token absent from client bundle. ADR-0015.

### F-013 — Dashboards ✅ SHIPPED
**Merged:** PR #18 `07847d7`. Security / compliance / governance dashboards. ADR-0016. *F-013.1 deferred: evidence-pack binary download + per-control gap report (`docs/followups/f-013-deferred-backend.md`).*

### F-014 — SSO (OIDC + SAML) ✅ SHIPPED
**Merged:** PR #19 `185654b`. OIDC + SAML middleware, group-claim→role mapping per tenant, single-use login transaction stores, `actor_id` audit attribution. ADR-0017.

### F-015 — Bulk processing pipeline ✅ SHIPPED
**Merged:** PR #20 `bbeba12`. Async batch, presigned MinIO uploads, Redis Streams + worker pool, DLQ, checkpointing, per-file manifest, idempotency. Worker uses RLS DB-row object_key (HIGH fixed). ADR-0018.

---

## Phase 3 — Differentiated features ✅ SHIPPED

### F-016 — Code scanning on LLM outputs ✅ SHIPPED
**Merged:** PR #21 `dcd58dd`. Extract code blocks → Semgrep (offline pinned) + Bandit → PASS|WARN|BLOCK, fail-safe→WARN. Hybrid streaming posture. **The CRIT-2 cautionary tale** — nearly shipped inert; caught by independent re-audit. Migration 0021. ADR-0019.

### F-017 — JSON data-lock engine ✅ SHIPPED
**Merged:** PR #22 `6c30088`. Per-field conditional withholding in assistant JSON output (time/permission conditions). Fail-CLOSED. Dotted-path selector. Streamed-under-active-rules → blocked. CRIT-2 countermeasure (migration 0022). ADR-0020.

### F-018 — Shadow-AI detection ✅ SHIPPED
**Merged:** PR #23 `6057518`. Detection/attribution/confidence + governance panel on F-007's egress seam. **Honesty boundary (verbatim in ADR/UI/API):** detects only disallowed-KNOWN-provider egress (openai/anthropic/bedrock) THROUGH Sentinel — NOT bypass traffic, NOT arbitrary consumer-AI hosts. Migration 0024 (3 nullable cols, hash opt-in rule). ADR-0021.

### F-019 — Custom model + fine-tune approval policies ✅ SHIPPED
**Merged:** PR #24 `1a823bf`. Operator approval workflow + per-tenant inventory + DEFAULT-DENY gateway enforcement. New `model_approval` policy_type (CRIT-2 countermeasure, migration 0025). Inventory (0026), event variants (0027). Minimal-hardened state machine, operator-only. ADR-0022. *(CI saga: a module-singleton engine caching a fake host across test packages — root cause #7 in banked rules.)*

### F-020 — Integration suite (Slack/Jira/Splunk webhooks) ✅ SHIPPED
**Merged:** PR #25 `eb281a8`. First data-egress feature, shipped **structurally metadata-only** (no payload/PII — honors "data never leaves"). Emit-seam tap → `webhook:candidates` stream (gated, default-OFF, fail-open). SSRF guard (resolve-and-pin, DNS-rebind-safe). HMAC-signed. F-015 worker pattern, DLQ. Migrations 0028-0030. ADR-0023.

### F-021 — Advanced governance UI ✅ SHIPPED
**Merged:** PR #26 `d044ed6`. Model inventory dashboard + approve/deny/retire UI + backend-enforced retirement with grace periods (`retire_at` deadline → `evaluate_model_policies` denies past-grace, fail-closed, non-stubbed-proven). Migration 0031. BFF-only, render lane gated. ADR-0024.

---

## Phase 4 — Scale and polish

### F-022 — Multi-region deployment 🔮 SPECULATIVE
**Blocked on F-010.** Multi-region requires a single-region deployment first. Helm multi-region active-active/passive, regional data residency, geo-routing, cross-region replication for policies + audit log.
**Realistic:** 22-30h (Heavy) · **Depends on:** F-010 (BOTH parts), F-003 · **Builder:** platform-infra · **Risk:** High.

### F-023 — Performance hardening 🔮 SPECULATIVE
Load testing vs p95<200ms, profile-guided optimization, connection pooling audit, policy-eval cache. **Depends on:** F-010 · 12-16h.

### F-024 — Disaster recovery 🔮 SPECULATIVE
Backup/restore, failover runbook, RPO/RTO validated, cross-region drill. **Depends on:** F-022 · 12-16h.

### F-025 — Self-serve onboarding 🔮 SPECULATIVE
Trial signup, guided wizard, sample policies/API calls vs sandbox tenant. **Depends on:** F-012, F-013 · 12-16h.

---

## Phase 5 — Blueprint additions

### F-026 — MCP & Third-Party Integration Layer 🔮 SPECULATIVE
Secure proxy + governance for external MCP servers / AI tools / third-party APIs. Per-tenant allow-lists, uniform inspection (PII/injection/secret), MCP audit logs. **Depends on:** F-005/F-006/F-008 · 22-30h · High.

### F-027 — Provider Key Vaulting 🔮 SPECULATIVE
Vault/KMS for upstream provider keys (currently env-var). Runtime fetch + rotation. **Depends on:** F-004 · 12-16h.

### F-028 — Custom Client-Defined PII Engine 🔮 SPECULATIVE
Per-tenant custom PII patterns (regex + ML hooks). **Depends on:** F-005, F-008 · 16-22h.

### F-029 — HIPAA Compliance Module 🔮 SPECULATIVE
HIPAA control mappings on F-011, PHI patterns, BAA-ready audit format. **Depends on:** F-011, F-028 · 16-22h.

### F-030 — EU AI Act Compliance Module 🔮 SPECULATIVE
EU AI Act mappings, high-risk classification helpers, Article 13 disclosure templates. **Depends on:** F-011 · 16-22h.

### F-031 — Production Due-Diligence Gate 🔮 SPECULATIVE
Pre-launch checklist tool (secrets vaulted, chain valid, migrations applied, CRITICAL/HIGH closed, SLOs validated). **Depends on:** F-011, F-027 · 12-16h.

### F-032 — Practical Zero-Knowledge Storage SDK 🔮 SPECULATIVE
Client-side encryption SDK, keys never leave client, ciphertext-only server, encrypted indexes. **Depends on:** F-004 · 22-30h · High.

### F-033 — Multi-Layer Tokenization Architecture 🔮 SPECULATIVE
Reversible PII tokenization, format-preserving encryption, separate token vault. **Depends on:** F-005, F-027 · 16-22h.

### F-034 — Internal Service Mesh Auth (mTLS) 🔮 SPECULATIVE
mTLS between Sentinel components + ecosystem products, cert-manager, auto-rotation. **Depends on:** F-010 · 12-16h.

### F-035 — External Pen-Test Pass 🔮 SPECULATIVE
Third-party pen test of production + findings cycle. **Depends on:** F-010, F-011, F-027 · 1-3 weeks external.

### F-036 — Self-Hosted / Air-Gapped Enterprise Deployment 🔮 SPECULATIVE
Air-gapped (no internet): offline install packages, internal mirrors, offline license validation. **Depends on:** F-010, F-027 · 22-30h.

**Sentinel grand total: 37 tasks (23 shipped + 14 remaining). F-007 + F-010 now shipped; all remaining are Phase 4/5 (F-022→F-036, 🔮).**

---

# PRODUCT 2: ANORYX AI ORCHESTRATOR

The ecosystem connector and broker. Sentinel emits events up; Delta pushes policies down; Rendly hooks in for safety; the Orchestrator routes between them. **Vision:** the central nervous system of the ecosystem — every inter-app data flow passes through it, governed by Sentinel.

**Build timing:** Orchestrator MVP is underway — O-001→O-006 shipped (Sentinel now deployable via F-010); O-007/O-008 remain. The ecosystem-integration layer (O-009→O-014) is the *vision* — committed, post-investment.

## Phase 0 — Orchestrator contracts (MVP)

### O-001 — Internal API contract ✅ SHIPPED (PR #28 `7d5986d`)
OpenAPI for: event ingest from Sentinel, policy distribution to Sentinel, query API for Delta. mTLS between products.
**Realistic:** 6-8h (Easy-Tricky) · **Depends on:** F-002 · **Builder:** api-architect · **Risk:** Medium.
**Parallelizable?** Yes — pure contract work, depends only on shipped F-002. Safe to run in its own session alongside D-001/R-001. *Caveat: O-001 defines the inter-product seam, so D-002/R-008 that consume it must align after it lands.*

### O-002 — Ecosystem event bus contract ✅ SHIPPED (PR #35 `3fe98a3`)
Standard cross-product event envelope, replay semantics, dead-letter, schema versioning.
**Realistic:** 6-8h · **Depends on:** O-001, F-002 · **Builder:** api-architect · **Risk:** Medium.

## Phase 1 — Orchestrator MVP

### O-003 — Event ingest pipeline ✅ SHIPPED (PR #37 `156c554`)
Consumer for Sentinel's event stream (Redis Streams/webhook per F-009/F-020). Validates against `events.schema.json`, persists w/ audit, forwards to subscribers.
**Realistic:** 12-16h · **Depends on:** O-001, F-005, F-009 · **Builder:** orchestration-hooks · **Risk:** Medium.

### O-004 — Policy distribution engine ✅ SHIPPED (PR #42 `9f101b0`)
Receives policies from Delta, validates against locked `policy.schema.json`, signs on Delta's behalf if needed, distributes to target Sentinels via the F-012a admin API. Tracks status, retries, alerts.
**Realistic:** 12-16h · **Depends on:** O-001, F-008, F-012a · **Builder:** orchestration-hooks · **Risk:** High.

### O-005 — Multi-Sentinel coordination ✅ SHIPPED (PR #43 `e9762db`)
Registry of all Sentinel instances, health checks, coordinated push, capability discovery.
**Realistic:** 12-16h · **Depends on:** O-003, O-004 · **Builder:** platform-infra · **Risk:** Medium.

### O-006 — Persistence consolidation + tenant-scoped read seams ✅ SHIPPED (PR #47 `10f58c8`)
Postgres schema (events, versioned policies, distribution status, registry) + hash-chained audit (reuse Sentinel F-003 pattern).
**Realistic:** 6-10h · **Depends on:** O-001 · **Builder:** persistence · **Risk:** Low.

### O-007 — Admin API + minimal UI 📋 PLANNED
REST API + minimal Next.js UI (registry, recent events, distribution status).
**Realistic:** 16-20h · **Depends on:** O-003, O-004, O-005 · **Builder:** frontend · **Risk:** Low.

### O-008 — Deployment 📋 PLANNED
Helm, K8s, mTLS provisioning, Vault. **Depends on:** O-001, F-010 · 6-10h · Medium.

## Phase 2 — Ecosystem integration layer (VISION) 🏦 POST-INVESTMENT

The eight capabilities that make the Orchestrator the ecosystem's nervous system. These are the product vision — scheduled after a funding round and after the MVP loop (X-001→X-003) proves the pattern.

### O-009 — Centralized Sentinel proxy for all inter-app traffic 🏦 POST-INVESTMENT
Every inter-app data flow (Delta↔Rendly↔Sentinel) routed through a Sentinel-governed proxy that monitors, redacts, and filters. The literal enforcement of "data never leaves the org" at the ecosystem level.
**Realistic:** 22-30h (Heavy) · **Depends on:** O-003, O-004, F-005, F-006 · **Builder:** gateway-core + orchestration · **Risk:** High.

### O-010 — Unified identity + cross-platform access management 🏦 POST-INVESTMENT
One identity/access protocol across Delta, Rendly, Sentinel. SSO federation, cross-product RBAC, single audit of who-accessed-what-where.
**Realistic:** 22-30h · **Depends on:** O-006, F-014 · **Builder:** platform-infra · **Risk:** High.

### O-011 — Event-driven cross-module automation engine 🏦 POST-INVESTMENT
"If X in module A then Y in module B" autonomous multi-step triggers across all products. (The cross-product workflow engine.)
**Realistic:** 20-28h · **Depends on:** O-003, O-004, D-005, R-008 · **Builder:** orchestration-hooks · **Risk:** High.

### O-012 — Sub-millisecond agent-to-agent messaging backbone 🏦 POST-INVESTMENT
Low-latency messaging fabric for agent-to-agent comms across the ecosystem. Global state-sync engine for flawless cross-product state consistency.
**Realistic:** 22-30h (Heavy) · **Depends on:** O-002, O-003 · **Builder:** platform-infra · **Risk:** High.

### O-013 — Global API gateway for third-party interactions 🏦 POST-INVESTMENT
Standardized external-facing gateway for all third-party interactions with the ecosystem (rate-limit, auth, governance applied uniformly). Overlaps F-026 (MCP layer) — reconcile when both are reached.
**Realistic:** 22-30h · **Depends on:** O-004, F-026 · **Builder:** gateway-core · **Risk:** High.

### O-014 — Command dashboard + automated rollback 🏦 POST-INVESTMENT
Comprehensive command center (system health, API loads, governance metrics across all products) + automated rollback if the orchestration loop detects a critical system failure.
**Realistic:** 20-28h · **Depends on:** O-005, O-007 · **Builder:** frontend + platform-infra · **Risk:** High.

### O-015 — Predictive scaling 🔮 SPECULATIVE
Telemetry analysis from the registry, traffic-spike prediction ("Algorithmic CFO"). **Depends on:** O-003, D-005 · 16-22h.

**Orchestrator total: 15 tasks (8 MVP + 6 post-investment vision + 1 speculative). O-001→O-006 shipped; O-007/O-008 remain in MVP.**

---

# PRODUCT 3: DELTA

**Vision:** the **Enterprise OS & Operations Layer** — CRM, ERP, AI project management, team/capacity management, budget governance, RBAC, invoicing — for AI-native organizations, with a B2C personal-finance track.

**Committed MVP (build first):** **AI Financial Governance & Intelligence** — the FinOps loop that consumes Sentinel events through the Orchestrator and pushes budget policies back as signed records to F-008. This is the next-buildable Delta and the half that wires into the killer cross-product feature (X-003). The full Enterprise-OS scope is the post-investment vision.

## Phase 0 — Delta contracts (MVP)

### D-001 — Financial domain model ✅ SHIPPED (PR #30 `19bd41b`)
Tokens, budgets, allocations, ledger entries, departments, projects, cost centers. Double-entry schema, reconciliation rules, time-series for burn rate.
**Realistic:** 10-14h · **Depends on:** F-001 · **Builder:** api-architect · **Risk:** Medium.
**Parallelizable?** Yes — depends only on shipped F-001. Safe in its own session alongside O-001/R-001.

### D-002 — Budget policy schema ✅ SHIPPED (PR #33 `c327b7e`)
Hard limits, soft warnings, escalation, windows, scopes. MUST round-trip through locked `policy.schema.json` as BudgetLimitPolicy variants.
**Realistic:** 6-10h · **Depends on:** D-001, F-002, O-001 · **Builder:** api-architect · **Risk:** Medium.

## Phase 1 — Delta MVP (AI Financial Governance)

### D-003 — Sub-second double-entry ledger ✅ SHIPPED (PR #39 `41848a2`)
High-throughput ledger (Postgres + Redis), atomic reversible entries, sub-second commit under load, append-only for audit.
**Realistic:** 20-28h (Complex) · **Depends on:** D-001 · **Builder:** persistence · **Risk:** High — ledger correctness is non-negotiable.

### D-004 — Event ingest from Orchestrator ✅ SHIPPED (PR #41 `49d7175`)
Consumer for Sentinel usage events (via Orchestrator) → ledger debits, idempotent.
**Realistic:** 12-16h · **Depends on:** D-003, O-003 · **Builder:** orchestration-hooks · **Risk:** Medium.

### D-005 — Budget engine (the killer-feature half) ✅ SHIPPED (PR #45 `04b893b`)
Real-time spend-vs-budget eval, threshold alerts, sub-second enforcement: cap hit → publish deny policy via Orchestrator → Sentinel blocks via F-008. **Autonomous enforcement of enterprise financial guardrails.**
**Realistic:** 16-22h (Complex) · **Depends on:** D-002, D-003, D-004, O-004, F-008 · **Builder:** policy-engine · **Risk:** High.

### D-006 — Instantaneous kill-switch for unauthorized AI agent transactions 📋 PLANNED ➕
Hard-stop protocol: an unauthorized/anomalous AI agent transaction triggers an immediate cross-ecosystem block (Delta detect → Orchestrator → Sentinel deny), faster than the budget-threshold loop. The "emergency brake" on agent spend.
**Realistic:** 12-16h · **Depends on:** D-005, O-004, F-008 · **Builder:** policy-engine · **Risk:** High.

### D-007 — Budget allocation UI 📋 PLANNED
Admin console for distributing budgets, approval workflows, change history.
**Realistic:** 12-16h · **Depends on:** D-002, D-005 · **Builder:** frontend · **Risk:** Low.

### D-008 — Live cost-to-value dashboards 📋 PLANNED
Real-time spend, burn rate, top spenders, cost-per-request, cost-per-outcome. **Dashboards configurable to client/team-set parameters** (the real-time project-parametrized view).
**Realistic:** 12-16h · **Depends on:** D-003, D-007 · **Builder:** frontend · **Risk:** Low.

### D-009 — Immutable audit trails for automated financial workflows 📋 PLANNED ➕
Hash-chained, tamper-evident audit of every automated corporate financial workflow (allocations, enforcement actions, reconciliations) — the Sentinel F-003 audit pattern applied to Delta's financial actions.
**Realistic:** 8-12h · **Depends on:** D-003 · **Builder:** persistence · **Risk:** Medium.

### D-010 — Deployment 📋 PLANNED
Helm, mTLS to Orchestrator, shared Vault, Postgres + Redis. **Depends on:** D-005, F-010 · 6-10h · Low.

## Phase 2 — Analytics + forecasting (MVP+)

### D-011 — Predictive SaaS/cloud budget optimization 📋 PLANNED ➕
Predictive modeling for optimizing SaaS procurement and cloud budget utilization (burn-rate forecasting + optimization recommendations).
**Realistic:** 12-16h · **Depends on:** D-003, D-008 · **Builder:** orchestration-hooks · **Risk:** Medium.

### D-012 — Chargeback / showback + anomaly detection 📋 PLANNED ➕
Departmental chargeback/showback reports + anomalous-spend detection.
**Realistic:** 12-16h · **Depends on:** D-003, D-008 · **Builder:** frontend + analytics · **Risk:** Low.

## Phase 3 — Enterprise OS & Operations Layer (VISION) 🏦 POST-INVESTMENT

The full Enterprise-OS scope. Committed vision, scheduled after a funding round — each is effectively a sub-product.

### D-013 — Unified CRM 🏦 POST-INVESTMENT
Complete enterprise deal pipeline, client interaction history, relationship scoring, automated stakeholder mapping. **Realistic:** 28h+ (Heavy) · **Depends on:** D-001, D-003 · **Risk:** High.

### D-014 — Comprehensive ERP engine 🏦 POST-INVESTMENT
Real-time sync of supply chain, payroll, HR, and physical assets. The full ERP. **Realistic:** 28h+ (Heavy, multi-feature) · **Depends on:** D-001, D-003, D-009 · **Risk:** High.

### D-015 — AI-driven project management 🏦 POST-INVESTMENT
Sprint-velocity tracking, dependency mapping, execution-bottleneck prediction. Real-time, integrates with client/team-set project parameters. **Realistic:** 22-30h · **Depends on:** D-001, D-008 · **Risk:** Medium.

### D-016 — Dynamic team / capacity management 🏦 POST-INVESTMENT
Squad performance, capacity tracking, automated resource allocation, real-time utilization to prevent burnout + optimize throughput. **Realistic:** 16-22h · **Depends on:** D-015 · **Risk:** Medium.

### D-017 — Strict RBAC operational dashboards 🏦 POST-INVESTMENT
Org-tier-scoped dashboards — users view/execute only what their tier authorizes. **Realistic:** 16-22h · **Depends on:** D-013, F-014 · **Risk:** Medium.

### D-018 — Automated invoicing + vendor payment reconciliation 🏦 POST-INVESTMENT
Invoicing + vendor payment reconciliation linked to project milestones/delivery metrics; continuous ERP ledger reconciliation. **Realistic:** 22-30h · **Depends on:** D-003, D-014 · **Risk:** High.

### D-019 — Corporate ERP integrations (NetSuite/SAP, Coupa/Ariba, AWS/GCP/Azure) 🏦 POST-INVESTMENT
Seamless integration with corporate ERPs for continuous ledger reconciliation; cloud cost sync; procurement. **Realistic:** 28h+ each · **Depends on:** D-014, D-018 · **Risk:** High.

### D-020 — Executive financial dashboard 🏦 POST-INVESTMENT
Top-level executive financial view across the OS. **Realistic:** 12-16h · **Depends on:** D-008, D-011, D-013 · **Risk:** Low.

## Phase 4 — B2C personal finance (VISION) 🏦 POST-INVESTMENT

### D-021 — AI personal budget tracking + financial health viz 🏦 POST-INVESTMENT
### D-022 — Automated subscription management + anomalous-charge alerts 🏦 POST-INVESTMENT
### D-023 — Personal asset allocation + micro-investment recommendations 🏦 POST-INVESTMENT
### D-024 — Real-time secure personal micro-transaction execution 🏦 POST-INVESTMENT
### D-025 — Privacy-first multi-bank financial data aggregation 🏦 POST-INVESTMENT
**B2C track (D-021→D-025):** ~12-16h each · **Depends on:** D-003 + the B2C onboarding shell · **Risk:** Medium-High (consumer financial data + open-banking compliance).

**Delta total: 28 tasks (12 MVP/MVP+ + 16 post-investment vision incl. B2C). D-001→D-005 shipped; D-006→D-012 remain in MVP (D-006 kill-switch in worktree, not merged).**

---

# PRODUCT 4: RENDLY

**Vision:** **Secure Enterprise Communication & Culture** — a zero-trust Slack/Teams/Zoom replacement where all meeting logs, transcripts, and records stay strictly within the company's control, channels auto-map to Delta project teams, and the company has full audit/oversight. Plus a B2C professional-networking track.

**Committed MVP (build first):** the **secure-comms platform** — auth, profiles, chat, 1-on-1 video, and Sentinel safety integration. This is the next-buildable Rendly. The culture/streaming/event-platform scope and the B2C networking track are the post-investment vision.

## Phase 0 — Rendly contracts (MVP)

### R-001 — Core platform API contract ✅ SHIPPED (PR #29 `309d6fc`)
**Realistic:** 10-14h · **Depends on:** F-001 · **Builder:** api-architect · **Risk:** Medium.
**Parallelizable?** Yes — depends only on shipped F-001. Safe in its own session alongside O-001/D-001.

### R-002 — Internal domain model (types, schema, invariants) ✅ SHIPPED (PR #32 `182298c`)
**Realistic:** 6-10h · **Depends on:** R-001 · **Risk:** Low.

## Phase 1 — Rendly secure-comms MVP

### R-003 — Authentication (OAuth2 + JWT ES256) ✅ SHIPPED (PR #36 `57b883f`)
**Realistic:** 10-14h · **Depends on:** R-001 · **Risk:** Medium.

### R-004 — User profiles + persistence ✅ SHIPPED (PR #40 `382bcd1`)
**Realistic:** 10-14h · **Depends on:** R-002, R-003 · **Risk:** Medium.

### R-005 — Real-time chat (WebSocket) ✅ SHIPPED (PR #44 `8351955`)
Secure team chat. Foundation for role-based channels.
**Realistic:** 12-16h · **Depends on:** R-004 · **Risk:** Medium.

### R-006 — Role-based secure channels + manual team mapping ✅ SHIPPED (PR #46 `a86f30b`) ➕
Instantaneous role-based chat groups + secure channels mapped automatically to active Delta project teams. (The Delta↔Rendly culture wiring — MVP-level if Delta team data is available; degrades gracefully to manual channels if not.)
**Realistic:** 12-16h · **Depends on:** R-005, D-016 (or manual fallback) · **Risk:** Medium.

### R-007 — Low-latency secure voice + video huddles (1-on-1) 📋 PLANNED
WebRTC. Rapid secure team sync **without generating external meeting links** (no Zoom/Meet link leaves the org).
**Realistic:** 22-30h (Complex) · **Depends on:** R-005 · **Risk:** High.

### R-008 — Sentinel integration for safety / data sovereignty 📋 PLANNED
All comms governed by Sentinel: PII/injection/secret inspection on messages, **absolute data sovereignty** (logs/transcripts/records never leave company control — the zero-trust answer to WhatsApp/Slack/Teams). Complete administrative audit/oversight of all internal comms.
**Realistic:** 12-16h · **Depends on:** R-005, F-005, F-007 · **Builder:** orchestration-hooks · **Risk:** Medium.

### R-009 — Immutable archiving of comms + video logs 📋 PLANNED ➕
Tamper-evident archiving of all corporate communications and video logs for regulatory compliance + internal security audits (Sentinel F-003 audit pattern applied to comms).
**Realistic:** 12-16h · **Depends on:** R-005, R-007 · **Risk:** Medium.

### R-010 — Deployment 📋 PLANNED
**Depends on:** R-007, F-010 · 12-16h · Medium.

## Phase 2 — Enterprise culture + events (VISION) 🏦 POST-INVESTMENT

### R-011 — Group huddles 🏦 POST-INVESTMENT
Secure multi-party huddles. **Depends on:** R-007 · 16-22h.

### R-012 — AI-powered internal culture matching engine 🏦 POST-INVESTMENT
Connect employees across departments to build collaborative corporate culture (internal, privacy-controlled). **Depends on:** R-004, R-002 · 16-22h.

### R-013 — Integrated virtual event platform 🏦 POST-INVESTMENT
Host large-scale online marketing forums, hackathons, industry conferences. **Depends on:** R-011 · 28h+ · High.

### R-014 — Encrypted live-streaming infrastructure 🏦 POST-INVESTMENT
High-fidelity encrypted live-streaming for confidential investor updates + global all-hands. **Depends on:** R-007, R-013 · 28h+ · High.

### R-015 — Context-aware summarization of comms + meeting transcripts 🏦 POST-INVESTMENT
AI summaries of executive comms/transcripts; smart scheduling vs corporate calendars; automated outreach tracking. **Depends on:** R-008, R-009 · 16-22h.

## Phase 3 — B2C professional networking (VISION) 🏦 POST-INVESTMENT

### R-016 — Intent-based matching algorithm (B2C) 🏦 POST-INVESTMENT
### R-017 — AI profile optimization + career-trajectory matching 🏦 POST-INVESTMENT
### R-018 — Hyper-personalized peer-networking interface 🏦 POST-INVESTMENT
### R-019 — Privacy-controlled DM portal (granular data exposure) 🏦 POST-INVESTMENT
### R-020 — Localized tech-event / hackathon / startup discovery 🏦 POST-INVESTMENT
### R-021 — Skill-based opportunity matching (freelance + full-time) 🏦 POST-INVESTMENT
### R-022 — Mentorship matching by exact tech-stack proficiency 🏦 POST-INVESTMENT
### R-023 — Consumer onboarding 🏦 POST-INVESTMENT
### R-024 — Discovery feed (B2C) 🏦 POST-INVESTMENT
### R-025 — Premium features + monetization (B2C, via Delta) 🏦 POST-INVESTMENT
### R-026 — Creator economy features 🏦 POST-INVESTMENT
**B2C track (R-016→R-026):** ~10-16h each · **Depends on:** R-004/R-005 + the matching core · **Risk:** Medium.

## Phase 4 — Platform-as-a-Service (VISION) 🏦 POST-INVESTMENT

### R-027 — B2B tenant + RBAC 🏦 POST-INVESTMENT
### R-028 — Intent-driven talent routing + skills inventory (B2B) 🏦 POST-INVESTMENT
### R-029 — Project/sprint workspaces + B2B analytics 🏦 POST-INVESTMENT
### R-030 — Public embedding API + developer portal 🏦 POST-INVESTMENT
**PaaS track (R-027→R-030):** ~12-22h each · **Depends on:** R-005/R-007/R-008 + Delta · **Risk:** Medium-High.

**Rendly total: 30 tasks (10 secure-comms MVP + 20 post-investment vision incl. culture/events/B2C/PaaS). R-001→R-006 shipped; R-007→R-010 remain in MVP.**

---

# CROSS-PRODUCT INTEGRATION

### X-001 — Sentinel ↔ Orchestrator wiring validated 📋 PLANNED
**Realistic:** 6-10h · **Depends on:** F-005, O-003.

### X-002 — Orchestrator ↔ Delta wiring validated 📋 PLANNED
**Realistic:** 6-10h · **Depends on:** O-003, D-004.

### X-003 — Budget enforcement loop (THE killer feature) 📋 PLANNED
Delta budget hits cap → policy pushed via Orchestrator → Sentinel blocks the team's next request within 1 second. End-to-end test budget-set → enforcement-active. Proves F-008 + Orchestrator distribution + Delta budget engine as a unit.
**Realistic:** 10-14h · **Depends on:** D-005, O-004, F-008.

### X-004 — Rendly ↔ Sentinel safety integration 🔮 SPECULATIVE
**Realistic:** 6-10h · **Depends on:** R-008.

### X-005 — Rendly ↔ Delta monetization wiring 🏦 POST-INVESTMENT
**Realistic:** 10-14h · **Depends on:** R-025, D-003.

### X-006 — End-to-end ecosystem demo 🔮 SPECULATIVE
**Realistic:** 10-14h · **Depends on:** all major component tasks.

**Cross-product total: 6 tasks, ~7-10 days realistic (MVP loop = X-001→X-003).**

---

# RECOMMENDED SEQUENCE

Optimizing for **demo-readiness → depth → ecosystem MVP → vision.**

## Immediate (Sentinel completion + deployability)

1. **F-010 Part 1** Deployment (Docker compose) — **ACTIVE; the design-partner unlock.** Makes the 21 shipped features runnable as one stack.
2. **F-007** ML injection classifier — the one remaining Phase-1 backend depth feature.
3. **F-013.1** Compliance evidence-pack download (deferred follow-up; high buyer value).
4. *(Owed, non-build)* Read the unread security audits: F-012a, F-014, F-015, F-016.

After this, Sentinel is genuinely demoable + deployable. **Natural moment for design-partner outreach.**

## Near-term (Ecosystem MVP — the killer loop)

5. **O-001, O-002** Orchestrator contracts *(O-001 parallelizable now — depends only on F-002)*
6. **D-001, D-002** Delta contracts *(D-001 parallelizable now — depends only on F-001)*
7. **R-001** Rendly contract *(parallelizable now — depends only on F-001)*
8. **O-003→O-008** Orchestrator MVP
9. **D-003→D-010** Delta AI-FinOps MVP (incl. D-006 kill-switch, D-009 immutable audit)
10. **X-001, X-002, X-003** Cross-product wiring — **proves the killer budget-enforcement loop.**

## Medium-term (Rendly secure-comms MVP + Delta analytics)

11. **R-002→R-010** Rendly secure-comms MVP (data sovereignty + Delta-mapped channels + Sentinel safety)
12. **D-011, D-012** Delta analytics/forecasting
13. **F-010 Part 2** Helm/K8s; selected Sentinel Phase 5 (F-026 MCP, F-029 HIPAA, F-030 EU AI Act)

## Post-investment (Vision tier — 🏦)

14. **Delta Enterprise OS** (D-013→D-020): CRM, full ERP, AI project management, team/capacity, RBAC, invoicing, ERP integrations
15. **Orchestrator ecosystem layer** (O-009→O-014): Sentinel-proxy-for-all-traffic, unified identity, cross-module automation, sub-ms backbone, global gateway, command dashboard + rollback
16. **Rendly culture/events/streaming** (R-011→R-015) + **B2C** (R-016→R-026) + **PaaS** (R-027→R-030)
17. **Delta B2C personal finance** (D-021→D-025)
18. **F-022→F-036** Sentinel scale/polish + F-035 external pen-test

---

## Parallel-session guidance (for the 3-session parallel plan)

**Safe to parallelize NOW (each in its own session):** O-001, D-001, R-001 — all are pure contract/domain-model work depending only on already-shipped Sentinel contracts (F-001/F-002). They don't touch each other's code.

**Cautions:**
- **Finish F-010 first.** It establishes the deploy pattern the other products' deployment tasks (O-008/D-010/R-010) copy. Set it once on Sentinel.
- **O-001 defines the inter-product seam.** D-002 and R-008 consume it — so although O-001/D-001/R-001 start in parallel, anything downstream that crosses products must align *after* O-001 lands. Keep cross-product contract changes in one session.
- **Parallel agents, serial you.** Three sessions still need the owner at every STEP-0 fork and approval gate. The constraint is reviewer attention, not agent capacity.

---

# CHECKLIST

## Sentinel — 37 tasks (23 shipped + 14 remaining)

- [x] F-001 OpenAPI contract
- [x] F-002 Event + policy schemas
- [x] F-003 Persistence + hash-chained audit
- [x] F-003b Tenant isolation RLS ➕
- [x] F-004 Gateway core
- [x] F-005 Orchestration hooks + 4 detectors
- [x] F-006 Multi-provider router
- [x] F-007 ML injection classifier ✅ (#12, +#31 thresholds, +#34 FU)
- [x] F-008 Policy intake + ECDSA-signed enforcement
- [x] F-009 Rate limiting + observability
- [x] F-010 Deployment ✅ — Part 1 compose (#27) + Part 2 Helm (#38)
- [x] F-011 Compliance engine (SOC 2 + GDPR) *(F-013.1 follow-up open)*
- [x] F-012a Admin console API
- [x] F-012 Admin console frontend
- [x] F-013 Dashboards
- [x] F-014 SSO (OIDC + SAML)
- [x] F-015 Bulk processing pipeline
- [x] F-016 Code scanning on LLM outputs
- [x] F-017 JSON data-lock engine
- [x] F-018 Shadow-AI detection
- [x] F-019 Custom model + fine-tune approval policies
- [x] F-020 Integration suite (Slack/Jira/Splunk)
- [x] F-021 Advanced governance UI
- [x] F-022 Multi-region deployment — merged #49; reconciled + independently audited (PR #50): allowlist-enforced residency scope, call-site-gated byte-identical render, fail-hard replication bootstrap, least-privilege secret, verify-full TLS. ⚠️ 1 High open (passive read-only NOT enforced — docs/audit/f-022-security-audit.md, docs/followups/f-022-passive-readonly-enforcement.md) → human remediation required before operating a serving passive region.
- [x] F-023 Performance hardening 🔮 (shipped PR #52)
- [x] F-024 Disaster recovery 🔮 (shipped PR #59)
- [x] F-025 Self-serve onboarding 🔮 (shipped PR #63 — operator CLI, scoped down from public signup; team/project admin API deferred, see docs/followups/f-025-team-project-admin-api.md)
- [x] F-026 MCP & Third-Party Integration Layer 🔮 (shipped PR #66 — governance substrate: per-tenant allow-list + SSRF guard + F-005 inspection reuse via sentinel-mcp operator CLI; live proxy deferred as open design decision, see docs/followups/f-026-mcp-proxy-endpoint.md)
- [x] F-027 Provider Key Vaulting 🔮 (shipped PR #76 — pluggable env/Vault/KMS ProviderKeySource with TTL-cached runtime fetch + bounded-lag rotation; env backend byte-identical to prior behavior; OpenAI-key-auth + instant-push rotation deferred, see docs/followups/f-027-*.md)
- [x] F-028 Custom Client-Defined PII Engine 🔮 (shipped — per-tenant client-defined regex PII: standalone ReDoS-safe engine, no spacy dependency, hot-reload + sentinel-pii CLI; runs after built-in PIIHook, emits existing pii_blocked event. Presidio ad-hoc "ML hooks" reading deferred, see docs/adr/0034 + docs/followups/f-028-presidio-adhoc-recognizers.md)
- [x] F-029 HIPAA Compliance Module 🔮 (shipped — HIPAA Security Rule control map (§164.312/§164.308) on the F-011 engine; built-in PHI patterns reusing F-028's ReDoS-safe engine; BAA-ready evidence summary + sentinel-hipaa CLI. Contract-free/CLI-only — HTTP export deferred, see docs/adr/0035 + docs/followups/f-029-hipaa-http-export.md)
- [ ] F-030 EU AI Act Compliance Module 🔮
- [ ] F-031 Production Due-Diligence Gate 🔮
- [ ] F-032 Practical Zero-Knowledge Storage SDK 🔮
- [ ] F-033 Multi-Layer Tokenization Architecture 🔮
- [ ] F-034 Internal Service Mesh Auth (mTLS) 🔮
- [ ] F-035 External Pen-Test Pass 🔮 (external)
- [ ] F-036 Self-Hosted / Air-Gapped Deployment 🔮

## Orchestrator — 15 tasks (8 MVP + 6 vision + 1 speculative) — 6 shipped

- [x] O-001 Internal API contract ✅ (#28)
- [x] O-002 Ecosystem event bus contract ✅ (#35)
- [x] O-003 Event ingest pipeline ✅ (#37)
- [x] O-004 Policy distribution engine ✅ (#42)
- [x] O-005 Multi-Sentinel coordination ✅ (#43)
- [x] O-006 Persistence consolidation + tenant-scoped read seams ✅ (#47)
- [x] O-007 Admin API + minimal UI ✅ (shipped PR #51)
- [x] O-008 Deployment ✅ (shipped PR #55)
- [x] O-009 Centralized Sentinel proxy for all inter-app traffic — Heavy 🏦 ✅ (shipped PR #60, scoped to a governed dispatch+audit seam — see ADR-0009)
- [x] O-010 Unified identity + cross-platform access mgmt — Heavy 🏦 ✅ (shipped PR #65, scoped to a cross-product identity-event correlation seam — see ADR-0010)
- [x] O-011 Event-driven cross-module automation engine — Complex 🏦 ✅ (shipped PR #67, scoped to a tenant-owned rule-triggered redistribution seam — see ADR-0011)
- [x] O-012 Sub-ms agent-to-agent messaging backbone + state-sync — Heavy 🏦 ✅ (shipped PR #74, scoped to an intra-tenant mailbox relay + optimistic-concurrency state store — see ADR-0012)
- [x] O-013 Global API gateway for third-party interactions — Heavy 🏦 ✅ (shipped PR #75, scoped to an operator-issued third-party API-key credential gating one rate-limited/scope-checked/audited read seam — see ADR-0013)
- [x] O-014 Command dashboard + automated rollback — Complex 🏦 ✅ (shipped PR #78, scoped to a read-only fleet-health summary + one operator-triggered, O-004-engine-reusing distribution rollback — see ADR-0014)
- [x] O-015 Predictive scaling — Complex 🔮 ✅ (shipped PR #80, scoped to a read-only ingest-traffic current-rate projection + deterministic spike heuristic, no autoscaling action — see ADR-0015)

## Delta — 28 tasks (12 MVP/MVP+ + 16 vision) — 5 shipped

- [x] D-001 Financial domain model ✅ (#30)
- [x] D-002 Budget policy schema ✅ (#33)
- [x] D-003 Sub-second double-entry ledger ✅ (#39)
- [x] D-004 Event ingest from Orchestrator ✅ (#41)
- [x] D-005 Budget engine (killer-feature half) ✅ (#45)
- [x] D-006 Kill-switch for unauthorized AI agent txns ✅ (shipped PR #54)
- [x] D-007 Budget allocation UI ✅ (shipped PR #57)
- [x] D-008 Live cost-to-value dashboards (param-driven) ✅ (shipped PR #62)
- [x] D-009 Immutable financial-workflow audit trails ✅ (shipped PR #68)
- [x] D-010 Deployment ✅ (shipped PR #71)
- [x] D-011 Predictive SaaS/cloud budget optimization ✅ (shipped PR #77)
- [x] D-012 Chargeback/showback + anomaly detection ✅ (shipped PR #81)
- [x] D-013 Unified CRM ✅ (shipped PR #87 — bounded vertical slice, see docs/adr/0013-delta-unified-crm.md)
- [x] D-014 Comprehensive ERP engine ✅ (shipped PR #92 — bounded vertical slice: asset register + vendor/PO procurement, see docs/adr/0014-delta-erp-assets-procurement.md)
- [x] D-015 AI-driven project management ✅ (shipped PR #94 — bounded vertical slice: sprints, tasks, dependency graph, velocity + bottleneck heuristic, see docs/adr/0015-delta-pm-sprints-dependencies.md)
- [x] D-016 Dynamic team / capacity management ✅ (shipped PR #96 — bounded vertical slice: teams, task assignment, utilization report, advisory rebalancing, see docs/adr/0016-delta-team-capacity-management.md)
- [x] D-017 Strict RBAC operational dashboards ✅ (shipped PR #106 — bounded vertical slice: locally-issued role-tagged tokens gating D-008's dashboards, see docs/adr/0017-delta-rbac-dashboards.md)
- [x] D-018 Automated invoicing + vendor reconciliation ✅ (shipped PR TBD — bounded vertical slice: PO-backed invoice/payment three-way match + per-vendor reconciliation report, see docs/adr/0018-delta-invoicing-reconciliation.md)
- [ ] D-019 Corporate ERP integrations (NetSuite/SAP/Coupa/cloud) — Heavy 🏦
- [ ] D-020 Executive financial dashboard — Tricky 🏦
- [ ] D-021 B2C personal budget tracking 🏦
- [ ] D-022 B2C subscription mgmt + charge alerts 🏦
- [ ] D-023 B2C asset allocation + micro-investment 🏦
- [ ] D-024 B2C real-time micro-transactions 🏦
- [ ] D-025 B2C privacy-first multi-bank aggregation 🏦

## Rendly — 30 tasks (10 secure-comms MVP + 20 vision) — 6 shipped

- [x] R-001 Core platform API contract ✅ (#29)
- [x] R-002 Internal domain model ✅ (#32)
- [x] R-003 Authentication (OAuth2 + JWT ES256) ✅ (#36)
- [x] R-004 User profiles + persistence ✅ (#40)
- [x] R-005 Real-time chat (WebSocket) ✅ (#44)
- [x] R-006 Role-based secure channels + manual team map ✅ (#46) ➕
- [x] R-007 Low-latency voice/video huddles (1-on-1, no external links) ✅ (#53)
- [x] R-008 Sentinel safety + data sovereignty ✅ (#58)
- [x] R-009 Immutable comms + video-log archiving ✅ (shipped PR #61)
- [x] R-010 Deployment ✅ (shipped PR #64)
- [x] R-011 Group huddles ✅ (shipped PR #69)
- [x] R-012 AI internal culture matching engine ✅ (shipped PR #70 — scoped to a deterministic, opt-in, cross-department suggestion seam; see ADR-0012)
- [x] R-013 Integrated virtual event platform — Heavy 🏦 ✅ (shipped PR #72, scoped to a single-host agenda scheduling seam — see ADR-0013)
- [x] R-014 Encrypted live-streaming infrastructure — Heavy 🏦 ✅ (shipped PR #73, scoped to a key-epoch derivation/rotation seam over R-013's EventSession — no SFU/broadcast delivery, see ADR-0014)
- [x] R-015 Context-aware comms/transcript summarization — Complex 🏦 ✅ (shipped PR #84, scoped to a deterministic extractive-digest seam over chat messages + metadata-only huddle digests — no AI/LLM, no meeting-transcript source, no calendar/outreach integration — see ADR-0015)
- [x] R-016 Intent-based matching (B2C) 🏦 ✅ (shipped PR #86, scoped to a deterministic complementary-intent matching core over the existing enterprise Profile domain — no B2C identity/persistence/REST, see ADR-0016)
- [x] R-017 AI profile optimization + career matching 🏦 ✅ (shipped PR #89, scoped to a deterministic career-trajectory stage-matching seam + a fixed profile-completeness checklist — no ML/generated text, no persistence, no REST; see ADR-0017)
- [x] R-018 Hyper-personalized peer networking 🏦 ✅ (shipped PR TBD, scoped to a deterministic composition seam combining R-016's intent matcher + R-017's career-trajectory matcher into one ranked peer suggestion — no ML, no persistence, no REST/UI; see ADR-0018)
- [x] R-019 Privacy-controlled DM portal 🏦 ✅ (shipped PR #105, scoped to a deterministic, fail-closed, per-field data-exposure grant seam ("granular data exposure") — no DM portal/transport, no persistence, no REST/UI; see ADR-0019)
- [ ] R-020 Localized tech-event discovery 🏦
- [ ] R-021 Skill-based opportunity matching 🏦
- [ ] R-022 Mentorship matching by tech-stack 🏦
- [ ] R-023 Consumer onboarding 🏦
- [ ] R-024 Discovery feed (B2C) 🏦
- [ ] R-025 Premium features + monetization (B2C) 🏦
- [ ] R-026 Creator economy features 🏦
- [ ] R-027 B2B tenant + RBAC 🏦
- [ ] R-028 Intent-driven talent routing + skills inventory 🏦
- [ ] R-029 Project/sprint workspaces + B2B analytics 🏦
- [ ] R-030 Public embedding API + developer portal 🏦

## Cross-product — 6 tasks

- [x] X-001 Sentinel ↔ Orchestrator wiring — Easy-Tricky (6-10h) (shipped PR #91)
- [x] X-002 Orchestrator ↔ Delta wiring — Easy-Tricky (6-10h) (shipped PR #97)
- [ ] X-003 Budget enforcement loop (killer feature) — Tricky (10-14h)
- [ ] X-004 Rendly ↔ Sentinel safety — Easy-Tricky 🔮
- [ ] X-005 Rendly ↔ Delta monetization — Tricky 🏦
- [ ] X-006 End-to-end ecosystem demo — Tricky 🔮

---

# Ecosystem totals

| Category | Sentinel | Orchestrator | Delta | Rendly | Cross | **Total** |
|----------|----------|--------------|-------|--------|-------|-----------|
| **Tasks** | 37 | 15 | 28 | 30 | 6 | **116** |
| **Shipped** | 23 | 6 | 5 | 6 | 0 | **40** |
| **Remaining** | 14 | 9 | 23 | 24 | 6 | **76** |

**Committed near-term (MVP, not 🏦/🔮):** Sentinel F-007 + F-010 · Orchestrator O-001→O-008 · Delta D-001→D-012 · Rendly R-001→R-010 · Cross X-001→X-003. That MVP slice is the realistic next ~4-6 months of build; the 🏦 post-investment vision tier is everything beyond it.

---

# Strategic notes

## Velocity calibration (F-001→F-021 actual)

- **Easy** (4-6h fleet + 30-45 min gates) · **Tricky** (8-12h + 1-2h gates) · **Complex** (16-28h + 2-4h gates over 1-2 days) · **Heavy** (22-30h+ + 4-6h gates over 2-3 days, anything cryptographic/contractual/cross-product).
- Assumes the established discipline: STEP gates, independent security-auditor verdict at the penultimate gate, ADR for non-obvious decisions, persistent audit artifact, non-stubbed e2e, CI-as-authority.

## Market window

AI-infrastructure window assessed at 12-18 months from June 2026 before consolidation. With 21 Sentinel features shipped, the constraint now is **deployability + first design partner**, not feature count — which is why F-010 outranks new features.

## Sequencing flexibility

The sequence is a recommendation, not a contract. A buyer request bumps priority; a discovered blocker gets fixed first; a design-partner ask becomes the next task. Update this file when reality changes. The 🏦 tier is deliberately gated on funding — don't pull it forward without capital.

---

**End of roadmap v3.** Keep open across sessions as the shared context file. Reconcile after each merge; reassess the 🏦 tier at each funding milestone.
