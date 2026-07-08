# ADR-0010 — Deployment (Docker + Helm + K8s)

- Status: Accepted
- Date: 2026-07-08
- Task: R-010 (tenth Rendly task, first deployment task, closes the secure-comms MVP)
- Builds on: Anoryx-AI-Orchestrator's O-008 deployment (ADR-0008), which itself mirrors
  Anoryx-Sentinel's F-010 (ADR-0012 Part 1, ADR-0027 Part 2) — the established deploy
  pattern the roadmap directs every product's deployment task to copy.
- Supersedes: the R-004 `Dockerfile`/`docker-compose.yml`/`docker-entrypoint.sh`, which
  shipped as a migration-only, no-server image (identity persistence was a library + schema
  at that point). Does not alter any R-001…R-009 runtime code, contract, or persistence
  schema, beyond adding one `GET /health` probe route (see Fork G).

## Context

R-010 is "Deployment — Depends on: R-007, F-010 · 12-16h · Medium," the terminal task in
Rendly's committed secure-comms MVP (R-001→R-010). Unlike Delta/Orchestrator's deployment
tasks, Rendly's app layer is a set of composable FastAPI factories
(`app.create_app` → `persistence.identity_app.create_db_app` →
`realtime.app.create_chat_app`) with no existing ASGI launch line and no existing health
probe — R-004's image ran `alembic upgrade head` + role provisioning and exited; it never
served traffic. This ADR both adds the minimal serving plumbing the prior tasks left as an
implicit seam AND the Docker/Helm packaging around it.

The roadmap's own O-008/F-010 ADRs already resolved the "Vault/KMS, mTLS" ambiguity in the
roadmap's literal task text conservatively (ship K8s-native Secrets, defer Vault/mTLS
explicitly) — this ADR makes the same call for Rendly, for the same reasons, rather than
re-litigating it.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — scope vs. the roadmap's implied "full production deployment" | **A1**: ship Docker + Helm + K8s-native Secrets (mirrors O-008/F-010's actual shipped scope), formally deferring Vault/mTLS with this ADR — same "honest deferral" move ADR-0008/ADR-0012/ADR-0027 already made. No ecosystem product has shipped Vault/mTLS yet; there is no reference implementation to build from. |
| **B** — interim peer/secret authentication | **B1**: unchanged from R-003 — the ES256 `RENDLY_JWT_PRIVATE_KEY_PEM` remains the sole app secret, loaded fail-closed (`rendly.auth.keys.load_key_material`). Rendly has no HMAC-ingest-style peer secret or admin-token surface to carry (verified: no `ADMIN_TOKEN` pattern exists anywhere in `src/`), so this fork is narrower than O-008's. |
| **C** — container image strategy | **C1**: extends (not replaces) R-004's existing multi-stage-eligible `Dockerfile`: builder + runtime, non-root uid 1000, `python:3.12-slim` base (kept as-is rather than switching to `-bookworm`, to minimize churn against what R-004 already shipped and CI already validated). No slim/full variant split — Rendly has no optional heavy extras. |
| **D** — secret delivery | **D1**: file-based Docker secrets for Compose (`postgres_password`, `rendly_jwt_private_key_pem`, mounted at `/run/secrets/*`); native Kubernetes `Secret` via `envFrom: secretRef` for Helm. Neither the Postgres password nor the JWT signing key appears in `docker-compose.yml`, a Deployment/Job pod spec, or `docker inspect` output. |
| **E** — bundled datastore + scaling posture | **E1**: bundled Postgres only (dev/demo-grade, `postgres.bundled=true` default), same shape as Orchestrator/Sentinel. **No Redis** — Rendly's R-005/R-007 realtime layer (`ConnectionRegistry`, `HuddleManager`) is explicitly single-instance, in-process, with no cross-replica fan-out. This is a REAL capacity constraint, not merely "not needed yet": the Helm chart defaults `replicaCount: 1` and ships `autoscaling.enabled: false`, and `podDisruptionBudget.enabled: false` by default (a `minAvailable: 1` PDB against a single replica would block every voluntary eviction, including node drains, forever — a real operational trap rather than a safety net). Named loudly in `values.yaml`, `NOTES.txt`, and `DEPLOY-K8s.md`, not silently defaulted around. |
| **F** — migration ordering | **F1**: copies ADR-0008/ADR-0027's pattern verbatim — the migrate Job is a NORMAL Job (not a Helm hook, which would race the not-yet-existing bundled Postgres on a fresh install), gated by a `wait-for-postgres` initContainer; the serve Deployment gates on schema-at-head via a `wait-for-migrate` initContainer polling `alembic current`. |
| **G** — health probe + serving plumbing (NEW work, not just packaging) | **G1**: adds `GET /health` (no DB check, `include_in_schema=False`) to `rendly.app.create_app`, so every layer built on top (`create_db_app`, `create_chat_app`) inherits it — and adds `rendly.asgi.create_app_from_env`, a zero-arg factory bridging `uvicorn --factory` to the existing `create_chat_app(key=...)` signature by loading the ES256 key from the environment. This is real, minimal application code added BY this deployment task (the prior tasks left serving as an open seam) — called out explicitly rather than silently smuggled into "just the Dockerfile." No DB-gated `/readyz` split — same deferral as O-008 Fork G. |
| **H** — NetworkPolicy | **H1**: restrictive-by-default (`Ingress` + `Egress` both listed), scoped egress to DNS + the bundled Postgres pod ONLY. Simpler than O-008's own policy: Rendly makes no outbound network call to another ecosystem product (R-008's "Sentinel safety" is fully self-hosted in-process detection — verified no HTTP/gRPC call anywhere in `realtime/sentinel_inspector.py`/`detectors.py`), so there is no "arbitrary `:443` to a dynamic peer" rule to carry, unlike the Orchestrator's dynamic Sentinel registry. Ingress on the http port (serving both REST and the `GET /v1/realtime` WS upgrade — NetworkPolicy has no HTTP-path granularity) is open by default, restrictable via `ingressCIDRs`. |
| **I** — deploy-artifact tests | **I1**: `tests/deploy/test_dockerfile.py` / `test_compose.py` / `test_helm.py`, static-assertion + `helm lint`/`helm template` tests riding the existing `rendly-ci.yml` `rendly-contracts` job (skipped where `helm` is absent), mirroring O-008/F-010's `tests/deploy/` pattern. New application code (`asgi.py`, the `/health` route) is covered by unit tests in `tests/auth/` (reusing the existing ES256-keypair fixtures) rather than a new test package, since it depends directly on the R-003 key-loading seam. |

## Honest deferrals (named, not half-built)

- **Vault / KMS for secret material** — this task uses a native K8s Secret for
  `RENDLY_JWT_PRIVATE_KEY_PEM` (Fork D), same posture Orchestrator's O-008 and Sentinel's
  F-010 shipped with. A dedicated secret-manager integration is future work, not yet
  mirrored anywhere in the ecosystem.
- **mTLS** — NOT provisioned by this chart. Rendly has no inter-product network call today
  (Fork H), so there is nothing analogous to O-008's ingest-seam mTLS deferral to name beyond
  "not built yet, no reference implementation exists."
- **Public TLS / cert-manager / hardened production Ingress** — the demo uses `kubectl
  port-forward`; an operator wires their own Ingress + cert-manager at the edge
  (`ingress.enabled=false` by default).
- **HPA / autoscaling / multi-replica** — the `hpa.yaml` template exists (mirrors the
  chart's shape) but ships `autoscaling.enabled=false`, and `replicaCount` defaults to 1.
  Scaling the realtime layer horizontally needs a shared broker (Redis pub/sub or
  equivalent) for `ConnectionRegistry`/`HuddleManager` fan-out first — that broker is out of
  scope for R-010 and is a real, load-bearing prerequisite, not a nice-to-have.
- **`/livez` + `/readyz` split** — Fork G; a single `/health` today, same deferral shape as
  O-008's own Fork G.
- **`RENDLY_TURN_SHARED_SECRET`** — the coturn REST-API static-auth-secret (R-007) is
  sensitive but genuinely optional (huddles still get STUN-only ICE candidates without it);
  it is documented (`deploy/secrets/README.md`) but not wired into the bundled dev compose or
  chart as a required secret key, to avoid forcing plumbing for a feature most demo/dev
  environments won't exercise.

## Alternatives considered

- **Fold `rendly-migrate`'s one-shot Compose service into the new `rendly-app` service
  rather than keeping both.** Chosen: the new `rendly-app` service runs migrations +
  provisioning inline (matching O-008's single-service pattern) and REPLACES the old
  `rendly-migrate` service outright — running both would duplicate (harmlessly, but
  confusingly) the same idempotent migration work on every `compose up`. No other file
  referenced the `rendly-migrate` service name (verified via repo-wide grep), so removing it
  is not a breaking rename of a used seam.
- **Build real mTLS or a Vault/ESO integration now.** Rejected for the same reason ADR-0008
  rejected it for the Orchestrator: no prior ecosystem implementation, no dependent task
  ready to consume it, and doing so under an unattended single-PR run without a dedicated
  security review cycle is the scope-widening this run is instructed to avoid.
- **Default `replicaCount: 2` (matching Orchestrator's default) and rely on operators to
  read the docs before scaling.** Rejected: the failure mode (silently dropped messages/
  huddle state across replicas) is a correctness bug, not a performance question, and a
  documented default is safer than a documented warning against an unsafe default.
