# ADR-0010 — Deployment (Docker + Helm + K8s-native secrets)

- **Status:** Accepted
- **Date:** 2026-07-08
- **Task:** D-010 (Deployment) · Builder: platform-infra
- **Depends on:** D-005 (budget engine — the enforcement path this packages), F-010 (Sentinel's
  deployment task — establishes the deploy pattern every product's deployment task mirrors)
- **Builds on:** Anoryx-Sentinel F-010 (`Anoryx-Sentinel/docs/adr/0012-deployment-and-release.md` +
  `0027-helm-deployment.md`) — the original pattern. Anoryx-AI-Orchestrator O-008
  (`Anoryx-AI-Orchestrator/docs/adr/0008-deployment.md`) — the closest architectural analog
  (single-process-per-service, DB-backed, Bearer-token peer auth to a sibling product) and this
  ADR's primary template. Rendly R-010 (`Rendly/docs/adr/0010-rendly-deployment.md`) — secondary
  reference, same chart shape.
- **Supersedes:** nothing. Adds a hardened Dockerfile, a docker-compose stack with two live
  services, and a Helm chart; does not alter any D-001…D-009 runtime code, contract, or persistence
  schema (confirmed — zero changes under `Delta/src/`).

## 1. Context

The roadmap's literal text for D-010 is "Deployment — Helm, mTLS to Orchestrator, shared Vault,
Postgres + Redis." That phrasing is copy-pasted boilerplate shared across every product's
deployment-task line (Orchestrator's O-008 line reads "Helm, K8s, mTLS provisioning, Vault";
Rendly's reads similarly) — it is not a reviewed inventory of Delta's actual dependencies. The three
sibling products that already shipped their own deployment task each independently found the same
thing and each honestly re-scoped:

- Sentinel's own ADR-0012 §10 REJECTED Vault for v1: *"External secret managers (Vault / AWS-SM)
  required at v1 — REJECTED... Deferred to F-010.1."*
- Orchestrator's ADR-0008 states outright: *"there is no shipped mTLS or Vault artifact anywhere in
  the ecosystem today to mirror."*
- Both dropped subsystems their product doesn't use (Orchestrator has no Redis/MinIO/worker/
  frontend; Rendly has no Redis either).

This ADR makes the same honest determination for Delta, confirmed by a direct repo search rather
than assumed: **zero Delta code imports Redis anywhere** (`budget_engine`/`kill_switch` use a
DB-backed outbox/drainer, not Redis Streams), and **there is no Vault or mTLS artifact anywhere in
this repository to integrate with** — building either now would be a genuine ecosystem first, with
no reference implementation, no dedicated review cycle, and no ready consumer.

## 2. Delta's actual runtime shape (why this differs from Orchestrator's chart)

Unlike Orchestrator (one ASGI service), Delta has **two independent ASGI apps** that must run as two
separate Deployments:

1. **`delta.ingest.app:create_app`** — the runtime hot path (`POST /v1/ingest/usage`). Evaluates the
   D-005 budget engine and D-006 kill-switch inline and publishes enforcement decisions to the
   Orchestrator's O-004 seam. This is the only Delta surface external callers (Sentinel, the
   Orchestrator) reach for live traffic.
2. **`delta.allocation_admin.app:create_app`** — the internal operator console (D-007 allocations +
   D-008 dashboards + D-009 audit-verify). Protected by a single break-glass Bearer token
   (`DELTA_ADMIN_TOKEN`), fail-loud if unset. Never touches the Orchestrator seam.

Both apps and their `/health` endpoints already existed before this task — D-010 is pure packaging.
Zero application code changed; `uvicorn`/`fastapi` were already core dependencies (D-004).

## 3. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **A — scope vs. the roadmap's literal "mTLS, Vault, Redis" text** | Ship Docker + Helm + K8s-native Secrets + bundled Postgres only. Formally, explicitly re-defer mTLS + Vault + Redis, mirroring Orchestrator's ADR-0008 Fork A and Sentinel's own ADR-0012/0027 deferrals. | Same reasoning as both precedents: no shipped reference implementation for Vault or mTLS exists anywhere in this monorepo, and Delta has zero Redis-consuming code path. Building any of the three now would be an unreviewed ecosystem first under an unattended run — exactly the scope-widening this run's operating procedure is instructed to avoid. |
| **B — two Deployments, not one** | `ingest` and `admin` are separate Kubernetes Deployments/Services/NetworkPolicies/PDBs, sharing one container image and one bundled-Postgres/migration-Job, distinguished only by the `command` each supplies to the same entrypoint. | They have different trust boundaries (public-reachable hot path vs. internal break-glass console), different scaling needs (ingest autoscales under load; admin is low-traffic, fixed at 1 replica), and different network exposure (ingest needs open-by-default external ingress like Sentinel/Orchestrator's own ingest seams; admin must never have that). Packaging them as one Deployment would force one NetworkPolicy/scaling policy on both, which is wrong for either. |
| **C — the admin console gets NO open-ingress escape hatch** | The ingest NetworkPolicy has an `ingressCIDRs`-restrictable-but-open-by-default external rule (honest FQDN limitation, mirrors Orchestrator's own ingest policy). The admin NetworkPolicy has no equivalent — its ingress is *always* same-namespace + monitoring-namespace only, with only an explicit-opt-in `extraAdminIngress` list for an operator who deliberately wants more. | The ingest seam's callers (Sentinel, the Orchestrator) are legitimately unknown at chart-render time and defense-in-depth is the app-layer HMAC check — an open-by-default rule there mirrors the honest limitation Orchestrator's own chart already accepted. The admin console has no such excuse: its only legitimate caller is an operator on a bastion/gateway inside the cluster's trust boundary, so defaulting it open would be a strictly worse posture than the ingest seam for no corresponding benefit. |
| **D — interim peer authentication for the Orchestrator seam** | Unchanged: the shared `ORCH_SERVICE_TOKEN` Bearer token (already shipped, D-005/D-006) remains the peer authenticator until real mTLS ships. This ADR does not weaken it, only makes explicit that D-010 does not close the mTLS deferral. | Mirrors Orchestrator's own Fork B for `ORCH_INGEST_HMAC_SECRET` — the interim mechanism already exists and already works; a deployment task's job is to package it, not replace it. |
| **E — secret delivery** | File-based Docker secrets for Compose (entrypoint shim reads `/run/secrets/*`, falling back to the environment when no file is mounted); native Kubernetes `Secret` via `envFrom: secretRef` for Helm. Passwords/tokens never appear in `docker-compose.yml`'s `environment:` block, a Deployment/Job pod spec, or `docker inspect` output. | Identical to Orchestrator's Fork D / Sentinel's ADR-0012 D2 / ADR-0027 D3 — the established ecosystem pattern. |
| **F — bundled datastore** | Bundled Postgres only (`postgres.bundled=true` default) with an `.external` escape hatch, same shape as Sentinel's and Orchestrator's. No Redis, no other bundled store. | See §1/Fork A — no Delta code path consumes Redis. |
| **G — migration ordering** | The migrate Job is a NORMAL Job (not a Helm hook, which would race the not-yet-existing bundled Postgres on a fresh install), gated by a `wait-for-postgres` initContainer; BOTH the ingest and admin Deployments gate on schema-at-head via a `wait-for-migrate` initContainer polling `alembic current`. | Copies Orchestrator's Fork F / Sentinel's ADR-0027 D1 verbatim — proven pattern, no reason to diverge. Two Deployments both need the gate (not just one), since either could otherwise serve against an un-migrated schema on a fresh install. |
| **H — health probes** | Liveness/readiness/startup probes on both Deployments target each app's existing `GET /health` (no DB-gated check — neither app has a `/livez`+`/readyz` split, same honest limitation Orchestrator's own chart names). | Zero new application code (§2) — adding a DB-gated readiness split would be an application-code change, out of scope for a packaging task, named here as a deferral rather than silently worked around. |
| **I — zero new application code needed** | Unlike Rendly's R-010 (which had to add `GET /health` and a `create_app_from_env` factory as part of its deployment task), Delta needed neither: both `create_app()` factories and both `/health` endpoints already existed (D-004, D-007). The Helm/Compose `command` for each service simply supplies `uvicorn <module>:create_app --factory --host 0.0.0.0 --port <N>` directly against the already-existing entrypoint's `exec "$@"` tail. | Named explicitly so a future reader doesn't go looking for serving-plumbing changes that don't exist in this diff — the entrypoint's pre-existing `exec "$@"` fallback (D-003) already supported launching an arbitrary command; D-010 only supplies the right one from each Deployment/Compose service. |
| **J — enabling a minimal deploy without a reachable Orchestrator** | `budgetEngineEnabled`/`killSwitchEnabled` chart values (and matching `DELTA_BUDGET_ENGINE_ENABLED`/`DELTA_KILL_SWITCH_ENABLED` compose env vars) both default to `false`. | `budget_engine.config.load_settings`/`kill_switch.config.load_settings` are BOTH fail-loud at startup when their `*_ENABLED` flag is (its own module default) `true` without a valid `DELTA_ORCH_DISTRIBUTION_URL` + `ORCH_SERVICE_TOKEN`. Without this knob, a minimal chart/compose install with no Orchestrator configured yet would crash-loop the ingest app on first boot. This changes no application code — both env vars already existed and were already read by the pre-existing config modules; the chart/compose files simply choose a sane default for their own knobs. |
| **K — Dockerfile hardening** | Upgraded from D-003's single-stage, root, migration-only image to a multi-stage, non-root (uid 1000), `HEALTHCHECK`-bearing image — mirrors Orchestrator's Fork C / Sentinel's D1 exactly. Single image variant (Delta has no optional heavy extras, like Orchestrator). | The D-003 image never ran a live server, so it never needed this hardening. Now that the same image serves two live Deployments, it needs to meet the same bar every other product's serving image already meets. |

## 4. Honest deferrals (named, not half-built)

- **Vault / KMS for secret material** — this task uses native K8s Secrets (Fork E), same posture
  Sentinel's F-010 and Orchestrator's O-008 both shipped with. A dedicated secret-manager
  integration remains future work at the Sentinel level (F-010.1/F-027), not mirrored here.
- **mTLS between Delta and the Orchestrator's O-004 distribution seam** — NOT provisioned by this
  chart. The interim peer authenticator is `ORCH_SERVICE_TOKEN` (Fork D). Sentinel's own mTLS
  (F-034) and Orchestrator's own mTLS deferral (ADR-0008) are themselves unshipped and speculative —
  there is no reference implementation to mirror.
- **Redis / KEDA queue-depth scaling** — zero Delta code has a bulk-worker/Redis-Streams queue to
  scale (Fork A/F). Not a silent omission of the roadmap's generic phrasing — a confirmed, documented
  scope decision.
- **Public TLS / cert-manager / hardened production Ingress** — the demo uses `kubectl
  port-forward`; an operator wires their own Ingress + cert-manager at the edge
  (`ingress.enabled=false` by default, ingest only — the admin console is never exposed via Ingress
  at all, per Fork C).
- **HPA / autoscaling** — the `hpa.yaml` template exists for the ingest component (mirrors the
  chart's shape) but ships with `ingest.autoscaling.enabled=false`. The admin console has no
  autoscaling knob at all (Fork B — fixed low-traffic internal surface).
- **`/livez` + `/readyz` split** — Fork H; deferred to an application-code change, not a deployment
  task change.

## 5. Threat model cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Secret leaks into `docker inspect`/pod spec/etcd | File-based Compose secrets + K8s `secretKeyRef`/`envFrom: secretRef` (Fork E) | `test_app_services_use_file_secrets_not_env_passwords`, `test_top_level_secrets_are_file_based` |
| Image baked with a real credential | Dockerfile has no `COPY .env`, no secret `ENV`/`ARG` default, no `.pem`/`id_rsa` | `test_dockerfile_no_secrets_baked` |
| Container escape / privilege escalation | Non-root uid 1000, `readOnlyRootFilesystem`, dropped capabilities, no privilege escalation, `RuntimeDefault` seccomp | `test_dockerfile_runs_as_non_root`; Helm `securityContext`/`podSecurityContext` on every Delta-owned pod template (ingest, admin, migrate Job, both init containers). **Exception, named not silent (independent security review):** the bundled dev/demo Postgres pod (`postgres-deployment.yaml`) carries NO securityContext — it runs as the official `postgres:16-alpine` image's own default user, matching Orchestrator's O-008 and Sentinel's F-010 bundled-Postgres templates exactly (neither sets one either, since the upstream image's own init script needs root transiently to `chown` a fresh data directory before dropping privileges internally; forcing `runAsNonRoot` would break first-boot on an empty volume). Bundled Postgres is dev/demo-grade only — production sets `postgres.bundled=false`. |
| Serving an un-migrated schema | `wait-for-postgres` + `wait-for-migrate` initContainers on BOTH Deployments; migrate Job is a normal resource, not a hook that would race a fresh install | `test_helm_template_renders` (Job present); manual `upgrade→downgrade→upgrade` verified in D-009's migration-roundtrip CI job, unaffected by this task |
| Admin console reachable from outside the cluster | NetworkPolicy ingress restricted to same-namespace + monitoring-namespace ONLY, no CIDR-based open-by-default rule, `ingress.enabled` never applies to it | `test_helm_admin_networkpolicy_has_no_open_ingress` |
| Ingest seam wide open with no defense-in-depth | NetworkPolicy egress/ingress port-scoped even where source/destination can't be restricted by hostname; app-layer `DELTA_INGEST_HMAC_SECRET` check is the real backstop (unchanged from D-004) | `test_helm_networkpolicy_restrictive`, `test_helm_networkpolicy_restricted_cidrs_scope_rules` |
| Ingest/admin cross-wired to the wrong app | Each Deployment's `command` explicitly names its own `create_app` target | `test_helm_ingest_admin_serve_different_targets`, `test_app_services_launch_the_correct_uvicorn_target` |
| Minimal install crash-loops with no Orchestrator configured | `budgetEngineEnabled`/`killSwitchEnabled` default false (Fork J) | manual `docker compose up` + `helm template` default-values smoke check (see §6) |

## 6. Verification

- `helm lint` + `helm template` (both bundled and external-Postgres modes) — clean.
- `pytest Delta/tests/deploy/` — 20/20 passed locally with `helm` on `PATH`.
- Full existing Delta suite (496 passed, 9 skipped) unaffected — zero changes under `Delta/src/`.
- `black --check` / `ruff check .` clean.
- These new test files ride the EXISTING `ledger-db` CI job's untargeted `pytest --tb=short -q
  --cov=src --cov-report=term-missing` invocation (`pyproject.toml`'s `testpaths = ["tests"]`
  sweeps `tests/deploy/` in automatically) — no new CI job was added.
- **CI coverage note (post-review fix).** The other three products' own `tests/deploy/
  test_helm.py` self-skip in CI (no `helm` binary on `PATH` in any of their CI jobs) — an accepted,
  ecosystem-wide limitation this task initially inherited unchanged. An independent security review
  flagged that this leaves the admin console's isolation NetworkPolicy — the single most
  security-load-bearing property of this task — with no automated CI regression backstop. Fixed
  (Delta-scoped only; the other three products' CI files were not touched) by adding
  `azure/setup-helm@v4` to `delta-ci.yml`'s `ledger-db` job, so `test_helm_admin_networkpolicy_has_
  no_open_ingress` and the other five Helm tests now execute for real on every Delta PR, not just
  locally. This makes Delta's deploy-test CI coverage a strict improvement over, not a regression
  from, precedent.

## 7. Alternatives considered

- **Build real mTLS now (cert-manager-issued certs on the Delta↔Orchestrator seam).** Rejected: no
  prior ecosystem implementation to build from or review against (Sentinel's own F-034 is itself
  unshipped), and doing so under an unattended, single-PR run without a dedicated security review
  cycle is exactly the kind of scope-widening this run's procedure instructs against.
- **Wire an External Secrets Operator / Vault sidecar now.** Rejected for the same reason — no
  established pattern anywhere in this repo to mirror; introducing one unilaterally here would
  diverge from, not follow, "F-010 establishes the deploy pattern the other products' deployment
  tasks copy."
- **One Deployment serving both apps behind a path-based router.** Rejected (Fork B) — the two apps
  have genuinely different trust boundaries and scaling needs; forcing one NetworkPolicy/scaling
  policy onto both would be a worse security posture for the admin console specifically.
- **Bundle a Redis instance "for future use."** Rejected (Fork A/F) — building unused infrastructure
  is exactly the kind of scope-widening CLAUDE.md's engineering standards warn against ("don't
  design for hypothetical future requirements"); if a future task introduces a real Redis dependency,
  that task should add the chart support alongside the code that needs it.
