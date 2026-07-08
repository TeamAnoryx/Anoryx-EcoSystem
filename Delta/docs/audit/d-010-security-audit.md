# D-010 Security Audit — Deployment (Docker + Helm + K8s-native secrets)

- **Date:** 2026-07-08
- **Scope:** `Delta/Dockerfile`, `Delta/docker-entrypoint.sh`, `Delta/docker-compose.yml`,
  `Delta/.dockerignore`, `Delta/deploy/helm/delta/` (full Helm chart), `Delta/deploy/DEPLOY-K8s.md`,
  `Delta/deploy/secrets/`, `Delta/deploy/helm/gen-k8s-secret.sh`, `Delta/tests/deploy/`, and
  `Delta/docs/adr/0010-delta-deployment.md` (the design record, cross-checked against the actual
  shipped files).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per banked
  process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Three Low findings; all three fixed on
  this branch before merge.

## Note on tooling

Semgrep's registry rulesets could not be fetched in the audit environment (the egress proxy denies
`CONNECT` to `semgrep.dev` — the same known limitation recorded in every prior audit this session,
see `docs/audit/d-009-security-audit.md`). This pass is manual dataflow/config analysis, per the
same accepted precedent. `delta-ci.yml`'s `quality` job's Semgrep step runs for real in CI (registry
reachable there) and remains the authority of record for SAST on this PR.

## What was actively tried and found sound

- **Secret leakage across every surface.** No password/token is baked into `Dockerfile` (no `COPY
  .env`, no secret `ENV`/`ARG` default). `docker-compose.yml`'s `environment:` blocks contain no
  secret value anywhere — Postgres uses `POSTGRES_PASSWORD_FILE`, the two app services mount
  file-based secrets only. Every Kubernetes pod-creating template uses `secretKeyRef`/`envFrom:
  secretRef`, never a literal `value:` for a sensitive key. `docker-entrypoint.sh` never logs a
  plaintext secret — only an opaque SCRAM verifier (computed client-side) ever reaches Postgres via
  `ALTER ROLE`. No secret file is committed under `deploy/secrets/` (only `.gitignore`, `README.md`,
  `gen-dev-secrets.sh` are tracked).
- **Admin console external exposure.** Traced every path that could expose
  `delta.allocation_admin.app` outside the cluster: `admin-service.yaml` is `ClusterIP`;
  `networkpolicy.yaml`'s admin `NetworkPolicy` has no source-unrestricted ingress rule (same-
  namespace + monitoring-namespace only, `extraAdminIngress` is an explicit opt-in with no
  CIDR-based open-by-default escape hatch); component labels (`app.kubernetes.io/component: admin`)
  match consistently across the admin Deployment/Service/NetworkPolicy/PDB selectors; the chart
  renders no `Ingress` object at all (confirmed — no `ingress.yaml` template exists, matching every
  sibling product's chart). Found no path to external reachability.
- **Migration ordering / fresh-install race safety.** The migrate Job's env
  (`RUN_MIGRATIONS=1`/`DELTA_PROVISION_APP_ROLE=1`) exactly matches what `docker-entrypoint.sh`
  gates on; both the ingest and admin Deployments carry `wait-for-postgres` + `wait-for-migrate`
  init containers; the migrate Job is a normal release resource (not a Helm hook that would race the
  not-yet-existing bundled Postgres). Compose gates both app services on `delta-migrate:
  condition: service_completed_successfully`. No path found where a serve pod could reach an
  un-migrated or partially-migrated schema.
- **Entrypoint injection surface.** The SCRAM-SHA-256 verifier is built only from
  base64-encoded/fixed-format tokens; `app_pw` (extracted via regex from `APP_DATABASE_URL`) never
  enters a raw SQL string — the only interpolated value in the `ALTER ROLE` statement is the
  precomputed opaque verifier, not attacker- or operator-influenceable free text. The `_read_secret`
  file-then-env-fallback precedence is correct and matches Orchestrator's own O-008 entrypoint
  pattern exactly. The provisioning block only runs when `DELTA_PROVISION_APP_ROLE` is truthy AND
  both `DATABASE_URL`/`APP_DATABASE_URL` are present — the two live serve Deployments never set that
  flag, only the migration Job does.
- **Security contexts on every Delta-owned pod-creating template** — ingest, admin, the migrate Job,
  and both `wait-for-postgres`/`wait-for-migrate` init containers all carry the hardened
  `podSecurityContext`/`securityContext` (non-root uid 1000, `readOnlyRootFilesystem`, dropped
  capabilities, no privilege escalation, `RuntimeDefault` seccomp).
- **Zero application-code changes.** Confirmed via diff — nothing under `Delta/src/` changed; this
  is pure packaging, consistent with the ADR's claim.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `deploy/helm/delta/templates/postgres-deployment.yaml` (bundled dev/demo Postgres pod) | Carries no `securityContext`/`podSecurityContext` at all — the only Delta-owned pod-creating template without one. The ADR's threat-model table originally claimed hardened security contexts applied to "every pod template," which was factually inaccurate for this one. | **Fixed the documentation, not the behavior.** Confirmed both Anoryx-Sentinel's F-010 and Anoryx-AI-Orchestrator's O-008 bundled-Postgres templates have the exact same omission — the upstream `postgres:16-alpine` image's own init script needs root transiently to `chown` a fresh, empty data volume before dropping privileges internally; forcing `runAsNonRoot` would break first-boot on a clean install and would diverge from the two reference implementations this task was told to mirror. ADR-0010 §5 now names this explicitly as a scoped, documented exception (bundled Postgres is dev/demo-grade only; production sets `postgres.bundled=false`, which renders no Postgres pod at all), rather than an inaccurate blanket claim. |
| 2 | Low | `tests/deploy/test_helm.py` (all 6 Helm tests, including `test_helm_admin_networkpolicy_has_no_open_ingress`) | No Delta CI job installed `helm`, so every Helm-CLI-backed test — including the one verifying the admin console's isolation NetworkPolicy, the single most security-load-bearing property of this task — self-skipped in CI, providing zero automated regression protection for that invariant going forward. This was an inherited, ecosystem-wide limitation (the other three products' own `tests/deploy/test_helm.py` all have the identical gap), not something this task introduced, but it was still a real gap for the property that matters most here. | **Fixed.** Added `azure/setup-helm@v4` to `delta-ci.yml`'s `ledger-db` job (the job whose untargeted `pytest` invocation already sweeps in `tests/deploy/`) — Delta-scoped only, the other three products' CI files were not touched. All 6 Helm tests, including the admin-isolation assertion, now execute for real on every Delta PR. This makes Delta's deploy-test CI coverage a strict improvement over precedent, not a regression from it. |
| 3 | Low | `deploy/helm/delta/values.yaml` `ingress:` block; `deploy/DEPLOY-K8s.md`, `docs/adr/0010-delta-deployment.md` | `values.yaml` ships a full `ingress:` value tree (`enabled`/`className`/`annotations`/`hosts`/`tls`) and the ADR/deploy guide described `ingress.enabled=false, ingest only` as if an `Ingress` template existed — but the chart renders NO `ingress.yaml` template at all, so the entire block is inert dead config. Fails safe (no exploit — nothing can ever be exposed via a template that doesn't exist), but is misleading: an operator setting `ingress.enabled=true` expecting an `Ingress` object gets nothing. | **Fixed the documentation.** Confirmed all three sibling products' charts have the identical pattern (an `ingress:` values placeholder with no template) — a pre-existing, ecosystem-wide convention, not a Delta-specific defect. Added a comment directly above the `ingress:` block in `values.yaml` stating plainly that no template renders it and why it's kept (values-shape consistency with the sibling charts), and corrected `DEPLOY-K8s.md`'s "Exposure is minimal" section to say the same. No template was added — building one was out of scope for this review and would itself need independent security review before shipping. |

## Threat model cross-reference

See `docs/adr/0010-delta-deployment.md` §5 for the full vectors-to-mitigations-to-tests table this
audit validated against (secret leakage across every surface, admin-console external exposure,
migration-ordering races, container hardening, ingest/admin cross-wiring, minimal-deploy
crash-loop avoidance).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-010 deployment-packaging surface listed under Scope above. It does
not re-audit any Delta application code (`Delta/src/`) — zero application code changed in this task,
confirmed via diff, so D-001 through D-009's own audit records remain the authority for that
surface. It does not re-audit Anoryx-Sentinel's F-010 or Anoryx-AI-Orchestrator's O-008 charts this
task mirrors (already reviewed and merged under their own audit processes) — findings #1 and #3
above note where Delta's chart faithfully (and, per this review, now more transparently) inherits
patterns from those two reference implementations rather than deviating from them. Per ADR-0010 §4,
real Vault/KMS integration and real mTLS between Delta and the Orchestrator's O-004 seam remain
explicit, honest deferrals — there is no reference implementation for either anywhere in this
repository yet, and building either as a first-of-its-kind unreviewed integration was correctly out
of scope for this task.
