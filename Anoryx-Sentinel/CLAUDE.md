# Anoryx Sentinel — Engineering Standards (Sentinel subproject)

## What Sentinel is
A zero-trust AI gateway. A reverse proxy between enterprise systems and every AI
model they use. Sentinel inspects, masks, governs, and logs all AI traffic.
It is ITSELF a security product. Its own code is a target. Build accordingly.

## Source layout (inside Anoryx-Sentinel/)
- src/gateway/          — reverse proxy, multi-provider routing, key vaulting
                           (src/gateway/keyvault/: pluggable env/Vault/KMS
                           provider-key backend + rotation, see docs/adr/0033)
- src/data_protection/  — PII detection, masking, tokenization, custom PII engine
                           (src/data_protection/custom_pii/: F-028 per-tenant
                           client-defined regex PII, ReDoS-safe, see docs/adr/0034)
- src/tokenization/     — F-033 multi-layer tokenization: random format-preserving
                           surrogate token (layer 1) + AES-256-GCM vault ciphertext in
                           RLS-scoped tenant_token_vault (layer 2), reversible per-tenant
                           via sentinel-token. Honest surrogate-not-FF3-1 scope in ADR-0039
- src/defense/          — prompt injection detection, secret leak detection
- src/code_scan/        — LLM code output scanning (v2)
- src/compliance/       — SOC 2 / ISO 27001 / HIPAA / EU AI Act readiness, evidence gen
                           (src/compliance/hipaa/: F-029 PHI patterns + BAA summary;
                           src/compliance/eu_ai_act/: F-030 risk classification +
                           Art.13 disclosure. CLI-only — see docs/adr/0035, 0036)
- src/orchestration/    — event bus emitter, policy intake, internal mTLS
- src/bulk/             — async bulk batch pipeline
- src/persistence/      — Postgres schema, RBAC, audit log
- src/dr/               — disaster recovery: Postgres backup/restore + hash-chain
                           integrity verification (operator CLI, no HTTP endpoints)
- src/preflight/        — F-031 production due-diligence gate: pre-launch checklist
                           (secrets vaulted, chain valid, migrations at head, no open
                           CRITICAL/HIGH, config sane) via sentinel-preflight (ADR-0037)
- src/zk_sdk/           — F-032 practical zero-knowledge storage SDK: client-side
                           AES-256-GCM + HMAC blind-index equality search; server sees
                           ciphertext only (sentinel-zk, honest threat model in ADR-0038)
- src/onboarding/       — guided sandbox-tenant provisioning (operator CLI,
                           no HTTP endpoints — see docs/adr/0031)
- src/mcp_gateway/      — MCP/third-party integration governance: per-tenant
                           server allow-lists + uniform inspection (operator
                           CLI, no live proxy yet — see docs/adr/0032)
- frontend/             — Next.js admin/compliance console
- infra/                — Docker, K8s, Helm, CI/CD
- contracts/            — API/event/policy schemas (api-architect owns, hook-protected)
- docs/adr/             — architecture decision records
- orchestrator/         — SDK harness for the build fleet

## Non-negotiables (hooks enforce these)
1. contracts/openapi.yaml is the API contract. NEVER invent endpoints. api-architect only.
2. contracts/events.schema.json — all emitted events must conform.
3. All four stable IDs (see contracts/ids.md) REQUIRED on every request and every event.
4. Secrets come from Vault/KMS env vars at runtime. Never in code, config, logs, tests.
5. Fail-safe: on ANY inspection or policy error → BLOCK. Never silently pass.
6. No plaintext PII in logs, errors, or test fixtures. Ever.

## Honest language (mandatory in code, comments, docs, UI)
  "audit-ready" not "compliant"
  "risk reduction" not "blocks all injection"
  "high-coverage detection" not "100% PII detection"
  "likely defect" not "bug-free"

## Ecosystem context
Events flow UP to Anoryx-AI-Orchestrator (usage/security/compliance).
Policies flow DOWN from Anoryx-AI-Orchestrator/Delta (budget limits, model allow-lists).
The contracts/ files are the integration boundary — Delta and Anoryx-AI-Orchestrator
will depend on them. Treat them as immutable once locked in Phase 0.
