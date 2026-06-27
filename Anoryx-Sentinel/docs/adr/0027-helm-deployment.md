# ADR-0027 — Helm Single-Cluster Deployment (F-010 Part 2)

- Status: Proposed
- Date: 2026-06-26
- Builds on: ADR-0012 (F-010 deployment & release — image variants, native-secrets
  β, bundled-stores γ, OTel interop, NetworkPolicy/securityContext), and the
  **Part-1 docker-compose stack** (`docker-compose.yml` + `docker-entrypoint.sh` +
  `deploy/`, merged PR #27) which is the **authoritative, proven** stack this chart
  mirrors.
- Supersedes: none (extends the ADR-0012 chart)
- Scope: **single Kubernetes cluster only.** Multi-region / active-active /
  geo-routing is **F-022** and explicitly out of scope here.

## Context

ADR-0012 (PR #14) shipped a Helm chart at `deploy/helm/sentinel/`. It predates the
compose stack growing its full shape: that chart renders only **gateway + Postgres
+ Redis + OTel-collector** (plus HPA/PDB/NetworkPolicy). The proven Part-1 compose
stack also runs **worker, frontend/console, MinIO + minio-init, and a seed step** —
none of which the chart has. F-010 Part 2 completes the chart to mirror the proven
compose stack and **proves it on a real local cluster** (kind), against the Part-1
demo bar: pods Ready in dependency order → migrate to head 0032 on a fresh PVC →
console login → a real `/v1` request governed (403 `policy_blocked` + audit row, no
upstream key) → `helm uninstall` + reinstall reproduces clean.

**A latent bug in the existing chart, surfaced by actually deploying it.** The
chart's `migration-job.yaml` is a Helm **pre-install/pre-upgrade hook** (weight -5).
Helm runs pre-install hooks **before** the main chart resources are created — but
the bundled Postgres is a *main* resource (`postgres-deployment.yaml`, no hook). So
on a fresh `helm install` with `postgres.bundled=true`, the migrate hook fires
**before the Postgres pod exists**, cannot connect, and fails. The design only ever
works against an **external, already-running** database. The chart passed CI as
`helm lint` + `helm template` (which never start a pod), so the defect shipped
invisibly — the infra-shaped instance of the inert-feature trap: *rendering is not
deploying.* The migrate step is the **linchpin** (R4: it must complete — alembic to
head **and** the `sentinel_app` SCRAM-password provisioning — before any gateway or
worker pod serves traffic), so the ordering must be correct on a bundled-store
install, not only against an external DB.

The compose entrypoint (`docker-entrypoint.sh`) is the proven boot sequence: read
file-secrets → assemble `DATABASE_URL` / `APP_DATABASE_URL` / `REDIS_URL` → (if
`RUN_MIGRATIONS=1`) `alembic upgrade head` → (if `SENTINEL_PROVISION_APP_ROLE=1`)
compute a SCRAM-SHA-256 verifier client-side and `ALTER ROLE sentinel_app … PASSWORD`
(the Part-1 "gap #1" fix — without it the `sentinel_app` NOBYPASSRLS role has no
usable password and every RLS-scoped query dies). The chart must reproduce this
**exactly**, not reinvent it.

## Decision

### D1 — Migrate ordering: a normal Job + initContainer gating (the linchpin fix)

Drop the Helm `helm.sh/hook` annotations from `migration-job.yaml`. The migrate
becomes an **ordinary Job** (named with `.Release.Revision` so each upgrade gets a
fresh one), reconciled alongside the other resources, with:

- an **initContainer `wait-for-postgres`** (same Sentinel image, runs a `pg_isready`
  / TCP-connect loop) so the migrate container starts only once bundled Postgres
  accepts connections; and
- the **same entrypoint-shim invocation as compose** —
  `command: ["/usr/local/bin/docker-entrypoint.sh"]` with **`RUN_MIGRATIONS=1`** and
  **`SENTINEL_PROVISION_APP_ROLE=1`** — so the entrypoint runs `alembic upgrade head`
  **and then** the SCRAM `sentinel_app` provisioning, in that order, identically to
  the compose gateway. **This logic is unchanged**; only the Job's lifecycle
  (hook → normal resource + init-gate) changes.

  **Ordering is load-bearing (a bug surfaced by actually deploying).** The migration
  must run via `RUN_MIGRATIONS=1`, **not** by passing `["alembic","upgrade","head"]`
  as the container `args`. The entrypoint runs the provision step *before* it `exec`s
  `args` (an `exec` is the last thing it does), and the provision step
  (`ALTER ROLE sentinel_app …`) depends on the role that migration **0006** creates.
  So migration-via-`args` provisions before the role exists and fails on every fresh
  install (`role "sentinel_app" does not exist`). Migration runs through
  `RUN_MIGRATIONS` (entrypoint step 2, before provision at step 3); the Job's `args`
  are a read-only `alembic current` head-confirmation that `exec`s last and exits 0.

The **serve and seed pods gate on migrate completion** via a shared
`wait-for-migrate` initContainer (a `_helpers.tpl` partial, reused by gateway,
worker, and the seed Job). It blocks until the schema is at head — checking
`alembic current` against `alembic heads` using the same image and DB env — so no
serve pod can start against an un-migrated or half-migrated DB, and a multi-replica
gateway never races (each replica's init independently confirms head; none runs the
migration itself).

**Why not keep the pre-install hook.** With a bundled in-chart database the hook
orders *before* the DB it depends on (the bug above). Making the bundled DB also a
hook with a more-negative weight is fragile — Helm's readiness gating for a
hook-managed Deployment is awkward and easily re-introduces the race. A normal Job +
explicit init-gate is deterministic and reads plainly.

**Why not per-pod migrate initContainers.** Running `alembic upgrade head` in every
gateway/worker pod's initContainer races when `replicaCount > 1` (default is 2) and
on rolling upgrades — concurrent `alembic upgrade` against one DB is unsafe. A
single migrate Job is the one writer; everyone else waits.

External-DB mode (`postgres.bundled=false`) keeps working unchanged: `wait-for-postgres`
simply observes an already-up endpoint and the migrate Job runs first all the same.

### D2 — Backing stores bundled in-chart (Fork 1)

Postgres, Redis, **and MinIO** are bundled as in-chart resources (Deployments +
PVCs + Services), mirroring compose and keeping the single-cluster demo self-contained
with zero external dependencies. MinIO adds `minio-{deployment,pvc,service}.yaml` plus
a `minio-init` Job (`minio/mc … mb --ignore-existing local/<bucket>`, gated by a
`wait-for-minio` init) reproducing the compose `minio-init` step. Bundled stores stay
single-replica (StatefulSet is unnecessary at one replica; the existing Deployment +
PVC pattern is retained). The ADR-0012 `bundled=false` escape hatch to managed
Postgres/Redis is preserved. (Bitnami subcharts were rejected — they add dependency
management and version drift and diverge from the proven compose images.)

### D3 — K8s Secret model (Fork 4; R3 — no secrets in the repo)

Sensitive env is delivered as **K8s Secrets**, never committed:

- a **postgres Secret** (`…-postgres`) holding `POSTGRES_PASSWORD`, referenced by
  `secretKeyRef` so the password never lands in a Deployment/Job pod spec (etcd /
  `kubectl get pod -o yaml`); and
- an **app env Secret** (`envSecret`, surfaced via `envFrom: secretRef`) carrying
  `SENTINEL_KEY_SECRET`, `SENTINEL_ADMIN_TOKEN`, `SESSION_SECRET`,
  `BULK_STORAGE_ACCESS_KEY`, `BULK_STORAGE_SECRET_KEY` (and `REDIS_PASSWORD`, empty
  in dev). The entrypoint shim still assembles the connection URLs from the parts +
  password at boot, exactly as in compose.

The Secrets are created from **freshly generated dev values** by a new
`deploy/helm/gen-k8s-secret.sh` (the K8s analog of `gen-dev-secrets.sh`) which runs
`kubectl create secret generic …` — the values stay ephemeral in the cluster and
**never touch a file in the repo**. The `createEnvSecret` + `secretData` values path
remains only as a documented escape hatch (with a "do not commit real values"
warning). Non-secret config (`POSTGRES_HOST/PORT/USER/DB`, `REDIS_HOST/PORT`,
`BULK_STORAGE_ENDPOINT/BUCKET`, `UPSTREAM_BASE_URL`, `SENTINEL_API_URL`, worker/port
flags, OTel endpoint, log level) is plain `env` / ConfigMap.

### D4 — worker & seed scripts via ConfigMap mount (mirror the compose bind-mount)

`deploy/worker/run_worker.py` and `deploy/seed/seed.py` are **not baked into the
image** — the Dockerfile copies only `src/` + `alembic.ini`; compose bind-mounts them
at `/worker` and `/seed`. The chart reproduces this with **ConfigMaps** (`worker-configmap.yaml`,
`seed-configmap.yaml`) rendered from those exact files via `.Files.Get`, mounted at
the same paths. This keeps the chart a faithful mirror and avoids any image change
(R5 — Part 2 is packaging, not feature code). The seed Job is idempotent (seed.py is
check-exists-first) and the demo virtual key surfaces in the Job's stdout
(`SEEDED_VIRTUAL_KEY=…`), retrieved with `kubectl logs job/…-seed` — the K8s-native
equivalent of compose writing it to a bind-mounted file.

### D5 — Local demo on kind (Fork 3)

The demo bar is proven on **kind** (`kind create cluster`), using the existing Docker
engine. The three local images (`anoryx-sentinel:0.10.0`, `anoryx-sentinel:0.10.0-bulk`
for the worker's bulk/boto3 extras, `anoryx-sentinel-frontend`) are **built locally
and `kind load docker-image`-ed**, with `image.*` values overridden to those tags
(the chart's default `ghcr.io/…:{appVersion}-{variant}` remains for registry pulls).
Access for the demo is `kubectl port-forward` (Services stay `ClusterIP`).

### D6 — runtime config the bundled/slim demo requires (live-surfaced)

Walking the demo bar on a real cluster surfaced two more "rendering is not
deploying" gaps the chart now closes (same class as the D1 migrate bug):

- **`UPSTREAM_BASE_URL` is required and was unset.** `GatewaySettings.upstream_base_url`
  is a required field; the gateway crashes on boot without it. The chart had no
  default and `values.example.yaml` did not set it, so every gateway/worker pod
  `CrashLoopBackOff`ed. The chart now defaults `upstreamBaseUrl` to
  `https://api.openai.com/v1` (mirroring the compose `${UPSTREAM_BASE_URL:-…}`
  default) and wires it onto the gateway and worker.
- **PII detection must be OFF on the slim image.** The default image is `slim`,
  which omits Presidio/spaCy (they ship only in the full image / `pii-spacy`
  extra). Per the fail-safe contract (ADR-0007 D3) a PII hook that cannot load its
  analyzer BLOCKS the request (`HookFailSafeError` → 500), so a slim gateway with
  PII detection on fail-safe-blocks **every** `/v1` request. The chart adds
  `piiDetectionEnabled` (default **false**, wired to `PII_DETECTION_ENABLED` on
  gateway + worker); set it true only with a full/`pii-spacy` image. **Security
  note:** this changes the default detection posture to PII-off — coherent with
  the default slim image (which cannot do PII at all), but it is a deliberate
  default and full-image deployments must re-enable it. Secret + injection
  detection have no heavy deps and remain on; the demo's governed-block bar is met
  by an **injection** block (regex, `classifier_enabled=false`) → `403
  policy_blocked` + hash-chained audit row, with no upstream provider key (Phase 0
  has no upstream-key vaulting, so a non-blocked request forwards keyless and fails
  at the upstream rather than yielding a Sentinel-side 403).

## Honest deferrals (F-022 / later — named, not half-built)

- **Multi-region / active-active / geo-routing / cross-region replication** — F-022 (the whole point of this single-cluster prerequisite).
- **Vault / KMS** for secret material — this Part uses K8s Secrets (ADR-0012 β); Vault is a later hardening.
- **Public TLS / cert-manager / hardened production ingress** — the demo uses port-forward; the chart's `ingress.enabled=false` stub is unchanged.
- **HPA / autoscaling** — the `hpa.yaml` template exists but stays `autoscaling.enabled=false`; load-driven scaling is out of scope.

## Consequences

**Positive.** The chart finally deploys and serves on a real cluster (not just
lints); the migrate linchpin is correctly ordered on bundled stores; the SCRAM
provisioning and seed are reproduced exactly from the proven compose path; secrets
stay out of the repo; the compose path is untouched (the chart is additive; `deploy/`
scripts are read, not modified) so Part-1 still passes.

**Negative / costs.** The init-gate pattern adds a `wait-for-postgres` / `wait-for-migrate`
initContainer to several pods (a few seconds of startup latency, acceptable for a
deploy). Bundled single-replica stores are demo-grade, not HA. The worker pulls bulk
extras (boto3) via the `…-bulk` image, a second image to build/load.

**Rollback.** Revert the chart additions; the ADR-0012 chart (gateway + PG + Redis +
OTel, external-DB mode) and the entire compose path are unaffected.
