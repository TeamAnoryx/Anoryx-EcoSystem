# ADR-0012 — Deployment & Release Tooling (F-010)

- **Status:** Proposed
- **Date:** 2026-06-18
- **Deciders:** platform-infra (owner / implementer — Dockerfile, Compose, Helm, release workflow), gateway-core (health endpoints + the Affu-authorized OTLP-export wiring), security-auditor (deployment-adversarial gate, STEP 10), Affu (solo founder & product owner — resolved the four STEP-0 architectural forks below and authorized the one R1 deviation; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Extends ADR-0006 (gateway architecture — F-010 **adds** k8s-idiomatic operational endpoints `/livez`, `/readyz`, `/healthz` alongside the ADR-0006 Decision 2 `/health` + `/ready`; ADR-0006 is **not amended**, the original two endpoints keep their exact behavior). Closes the ADR-0011 §6/§10 **OTel-export deferral** ("OTLP export, collector, and sampling are F-010"). Preserves ADR-0011 §3/§10 **failure-mode γ** (Redis non-fatal) — see §"F-009 fallback preservation" for the dispatch-R6 correction. ADR-0004/0005/0007/0008/0009/0010 unchanged. **No `contracts/` change** (F-010 adds no API, event, or policy schema). The contracts win over this ADR on any conflict.
- **Feature:** F-010 — make Sentinel genuinely deployable by a design partner: a multi-stage container image, a dual orchestration target (Docker Compose for SMB self-host + a Helm chart for k8s enterprises), native-secrets primitives, a bundled OpenTelemetry Collector, k8s-compatible health probes, and a signed, SBOM-bearing release pipeline on git tag.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

F-009 introduced the repo's first `docker-compose.yml` (`redis:7-alpine` + `postgres:16-alpine`, env-based credentials, `sentinel-net` bridge, named volumes) and a Grafana dashboard under `deploy/`. There is **no Sentinel container image** (no Dockerfile, no `.dockerignore`), **no k8s artifacts** (`infra/helm/` is a `.gitkeep` stub), and **no release pipeline** — only `sentinel-ci.yml` (lint · test · SAST on PRs). The gateway app is a factory (`gateway.main:create_app`, uvicorn `--factory`) reading config via pydantic-settings (`gateway.config.GatewaySettings`): required `UPSTREAM_BASE_URL`, `DATABASE_URL`, `APP_DATABASE_URL`, `SENTINEL_KEY_SECRET`; optional `REDIS_URL` (default `redis://localhost:6379/0`, kept optional so γ fallback works without Redis), `ENABLE_OTEL` (default `True`), `METRICS_PATH` (`/metrics`).

`src/gateway/routes/health.py` already exists (ADR-0006 Decision 2): `GET /health` (liveness, no DB, `{"status":"ok"}`) and `GET /ready` (readiness, a non-tenant `SELECT 1` on `get_privileged_session()`, 200 `{"status":"ready"}` / 503 `{"status":"unavailable"}`). Both are wired in `main.py` and are explicitly out-of-contract operational endpoints (not in `openapi.yaml`).

F-009 wired OpenTelemetry instrumentation (`observability/tracing.py`) but configured the `TracerProvider` with **no SpanProcessor / exporter** — spans exist in-memory for W3C context propagation only. The module docstring states verbatim: *"F-010 replaces this with an OTLP exporter configured from env vars."* The `sentinel_redis_health` gauge (1 healthy / 0 degraded) and `redis_client.is_degraded()` track Redis health via a 5 s background loop; on Redis failure the limiter falls back to the in-process path (failure-mode γ) and the gateway **keeps serving** (ADR-0011 §3/§10 explicitly **rejected** fail-closed-on-Redis-outage).

The base image `python:3.12-slim-bookworm` ships **without `curl`** (confirmed empirically at STEP 0). The gateway runtime import graph does **not** pull in Presidio / spaCy (PII detection is not on the `create_app()` middleware path), lowering image-size risk.

### 1.2 Decision (one paragraph)

We ship a **multi-stage** Dockerfile (`python:3.12-slim-bookworm`; builder installs deps, runtime copies them + `src/`, runs as **non-root uid 1000**, `WORKDIR /app`, `ENTRYPOINT` uvicorn `--factory` with `SENTINEL_WORKERS`-configurable worker count, `HEALTHCHECK` via `python -c urllib` against `/livez` since curl is absent, OCI labels, no baked secrets — R4) and target **<300 MB** (a target, not a hard gate; measured at STEP 2 and reported honestly). We provide a **dual orchestration target (γ)**: we **extend** the F-009 `docker-compose.yml` (adding `sentinel-app`, `otel-collector`, and an opt-in `caddy` under a `tls` compose profile, plus a top-level file-based `secrets:` section — never touching the existing redis/postgres/networks/volumes, R3) **and** ship a **Helm chart** (`deploy/helm/sentinel/`). **Secrets are native (β):** Docker **file-secrets** mounted at `/run/secrets/*` (a small entrypoint shim assembles `DATABASE_URL`/`REDIS_URL` from the secret files at container start, because pydantic-settings has no `*_FILE` convention) for Compose; **Kubernetes Secrets** via `envFrom: secretRef` for Helm. External Vault / AWS-SM is **documented future work (F-010.1)**, not required. **Postgres + Redis are bundled by default (γ)** with disclaimers and a documented escape hatch (`postgres.bundled=false` / `redis.bundled=false` + `.external` block pointing at managed services). We add **k8s-idiomatic health endpoints** `/livez` (pure liveness, no deps), `/readyz` (**Postgres-only** readiness gate; Redis health surfaced as a **non-gating** body field read from `redis_client.is_degraded()` — no fresh probe), and `/healthz` (alias of `/readyz`), **preserving** `/health` and `/ready` byte-for-byte (back-compat). We bundle an **OpenTelemetry Collector (β)** (default `logging` exporter, no backend wired) and **complete F-009's explicit OTLP-export handoff** with one env-gated, R8-safe SpanProcessor in `tracing.py` (an **Affu-authorized R1 deviation** — see §"R1 deviation note"). We add a **release workflow** (`.github/workflows/sentinel-release.yml`, alongside CI — R2) triggered on a `v*` semver tag: multi-arch image build + push to GHCR, **cosign keyless OIDC** signing, **syft** SBOM, Helm chart publish to GitHub Pages, and auto-generated release notes. A restrictive-by-default **NetworkPolicy** and a pre-upgrade **Alembic migration Job** make the chart actually runnable. Version bumps `0.1.0 → 0.10.0` (package / image / chart appVersion); the FastAPI app's API-surface `version="1.0.0"` is a distinct axis and stays.

### 1.3 STEP-0 architectural forks (resolved by Affu) + what is frozen

| Fork (dispatch said) | Resolution (Affu) |
|---|---|
| R6: `/readyz` → 503 when Postgres **or Redis** down | **Postgres-only gate.** Redis-down is non-fatal (F-009 γ); a Redis-gated probe would pull every pod from the k8s Service on a Redis blip = self-inflicted outage. Redis status is a non-gating body field. See §"F-009 fallback preservation". |
| R1: `health.py` is a **new** file | **EDIT** the existing file. Add `/livez`/`/readyz`/`/healthz`; **preserve** `/health`/`/ready`. main.py router include unchanged. |
| §5: bundle OTel Collector ("traces flow") | Collector bundled **and** app-side OTLP export wired (env-gated) — an Affu-authorized **R1 deviation** to `tracing.py`, completing F-009's documented handoff. |
| helm/actionlint availability | Installed locally ✓. No kind cluster → `kubectl apply --dry-run=client`; server-side validation deferred to CI (honest gap). |

| Frozen (MUST NOT change) | F-010 change |
|---|---|
| Existing compose `redis`/`postgres`/`networks`/`volumes` (R3) | New services + top-level `secrets:` added alongside |
| CI workflow `sentinel-ci.yml` (R2) | New `sentinel-release.yml` added alongside |
| `/health` + `/ready` behavior (ADR-0006 D2) | New z-endpoints added; old two byte-identical |
| F-009 γ Redis fallback (ADR-0011 §3) | `/readyz` honors it (Postgres-only) |
| orchestration / policy / persistence logic (R1) | Untouched |
| middleware **logic** (R1) | Untouched except an additive 3-literal allowlist entry per §11 Deviation 2 (auth / tenant_context / terminal_audit) — no branch/gate change |
| src/ allow-list | health.py, main.py (unchanged in practice), __init__.py + two authorized deviations: **tracing.py** (export) and the **middleware allowlists** (§11) |
| `contracts/*` | Untouched (no API/event/policy change) |

---

## 2. Decision D1: Multi-stage non-root image (R4, R9)

`python:3.12-slim-bookworm`, two stages. **builder:** install build deps (`gcc`, `libpq-dev`), `pip install --user .` into `/root/.local`. **runtime:** copy `--from=builder /root/.local` + `src/`, create uid/gid 1000 (`useradd`), `USER 1000`, `WORKDIR /app`, `PYTHONPATH=/app/src`. `ENTRYPOINT` runs the secrets shim → `exec uvicorn gateway.main:create_app --factory --host 0.0.0.0 --port 8000 --workers ${SENTINEL_WORKERS:-1}`. Because the base image lacks `curl`, `HEALTHCHECK` uses `python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/livez',timeout=3).status==200 else 1)"`. OCI labels: `org.opencontainers.image.{title,version,source,licenses,description}` (version via `ARG`). `.dockerignore` excludes `tests/`, `docs/`, `deploy/`, `__pycache__`, `.git`, `*.pyc`. **No secrets, keys, or env-specific config baked** (R4) — all runtime config is injected. Target **<300 MB**; measured at STEP 2 and reported honestly (no silent miss).

## 3. Decision D2: Native secrets — Docker file-secrets + k8s Secrets (β)

**Compose:** top-level `secrets:` declares file-based `postgres_password` (`./secrets/postgres_password`) and `redis_password` (`./secrets/redis_password`); `sentinel-app` mounts them at `/run/secrets/*`. A `docker-entrypoint.sh` shim reads the files, assembles `DATABASE_URL` / `APP_DATABASE_URL` / `REDIS_URL`, then `exec`s uvicorn. The password therefore **never appears in the compose file, `environment:`, or `docker inspect` `Config.Env`** (vector 8); it lives only in the mounted file and the live process env assembled at runtime (honest limitation: visible inside the container via `/proc`, which is the same trust boundary as the file mount). **Helm:** sensitive config (the four required URLs/secrets, provider keys) comes from a pre-existing k8s `Secret` named by `.Values.envSecret`, surfaced via `envFrom: secretRef`; non-secret config via `env:`. External secret managers (Vault, AWS-SM, External Secrets Operator) are **documented future work (F-010.1)**, not wired.

## 4. Decision D3: Bundled-by-default Postgres + Redis + escape hatch (γ)

Helm `postgres.bundled` / `redis.bundled` default `true` (bundled Deployments + a Postgres PVC) so a design partner can `helm install` and have a running stack. Each has an escape hatch: set `bundled=false` and provide a `.external` block (`{host,port,database,secretName}`) pointing at managed Postgres (RDS / CloudSQL / AlloyDB) or Redis (ElastiCache / MemoryStore). `deploy/SELF_HOST.md` recommends managed services for production and marks bundled stores as dev/demo-grade. A pre-upgrade **Alembic migration Job** (`alembic upgrade head`, Helm hook) runs before the app rolls out so `/readyz` can pass; Compose runs the migration in the app entrypoint shim before uvicorn.

## 5. Decision D4: OTel Collector interop (β) + app-export wiring

Bundle `otel/opentelemetry-collector-contrib` (Compose service + gated Helm Deployment) with `deploy/otel/collector-config.yaml`: OTLP receivers (gRPC `:4317` + HTTP `:4318`), `memory_limiter` then `batch` processors, **`logging` exporter only** (no backend — R10), `health_check`/`pprof`/`zpages` extensions, traces + metrics pipelines. Commented stanzas show how to add Jaeger / Tempo / Honeycomb / Datadog exporters; `deploy/otel/README.md` documents backend wiring. **App-side export (R1 deviation, §"R1 deviation note"):** `tracing.py._configure_provider()` gains an env-gated `BatchSpanProcessor(OTLPSpanExporter())` — added **only** when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (the OTel-standard env var, read by the exporter itself), wrapped R8-safe (failure → WARNING, request unaffected). When unset, behavior is byte-identical to F-009 (no-op sink). Compose/Helm set `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317`, so traces flow end-to-end into the collector's log by default. Adds dependency `opentelemetry-exporter-otlp-proto-grpc` (upper-bounded `<2`, matching the F-009 pins).

## 6. Decision D5: Health endpoint evolution (additive; ADR-0006 not amended)

`health.py` is refactored to shared helpers (`_check_liveness()`, `_check_readiness()`) with thin route handlers. Five endpoints, two response shapes:

| Endpoint | Gate | Body |
|---|---|---|
| `/livez` (new, k8s liveness) | none — no DB/Redis import (R5) | `{"status":"alive","postgres":...,"redis":...,"version":"0.10.0"}` |
| `/readyz` (new, k8s readiness) | **Postgres only** → 200/503 | `{"status":"ready","postgres":"healthy\|unhealthy","redis":"healthy\|degraded","version":"0.10.0"}` |
| `/healthz` (new, alias → readyz) | Postgres only | same as `/readyz` |
| `/health` (preserved) | none | `{"status":"ok"}` (exact ADR-0006 D2) |
| `/ready` (preserved) | Postgres only (unchanged) | `{"status":"ready"}` / 503 `{"status":"unavailable"}` |

Redis status is read from `redis_client.is_degraded()` (the in-process flag the `sentinel_redis_health` gauge mirrors) — **no fresh Redis connection** is opened (prevents probe storms; vector 3b). The only DB touch on the readiness path is the existing `SELECT 1` on `get_privileged_session()`. `/livez` opens no connection of any kind. The `version` field exposes the app release version only (vector 4). Migration guidance: existing customers on `/health`+`/ready` may stay; new k8s deployments use `/livez`+`/readyz`. No deprecation timeline (revisit F-013+). Dockerfile/Compose `HEALTHCHECK` and Helm `livenessProbe` use `/livez`; Helm `readinessProbe`/`startupProbe` use `/livez`+`/readyz`.

## 7. Decision D6: Release on git tag + signing + SBOM (R11)

`sentinel-release.yml` triggers on `push: tags: ['v*']`. Jobs: **build-push** (multi-arch amd64+arm64 via `docker/build-push-action`, GHA cache, tags `VERSION` + `latest`, push `ghcr.io/teamanoryx/anoryx-sentinel`); **sign-sbom** (cosign **keyless OIDC** image signature via Sigstore + syft SPDX-JSON SBOM, both attached to the GitHub Release); **helm-publish** (`helm/chart-releaser-action` → `gh-pages`); **release-notes** (auto-generated from PRs since the previous tag). Permissions are job-scoped minimum: `contents: write` (release), `packages: write` (GHCR), `pages: write` (chart), `id-token: write` (OIDC). README documents `cosign verify` for consumers.

## 8. Decision D7: Restrictive NetworkPolicy + securityContext (R8, R9)

Helm pod `securityContext`: `runAsNonRoot: true`, `runAsUser: 1000`, `readOnlyRootFilesystem: true` (with `emptyDir` writable mounts for `/tmp` and `/run`), `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`. Default-restrictive **NetworkPolicy** (`.Values.networkPolicy.enabled=true`): ingress from same namespace + Prometheus scrape; egress limited to in-cluster Postgres, Redis, and the OTel Collector (pod/namespace selectors) + DNS (`:53`) + `:443`. **Honest limitation:** plain Kubernetes NetworkPolicy cannot match egress by hostname, so `*.openai.com` / `*.anthropic.com` FQDN restriction requires a FQDN-aware CNI (Cilium / Calico); the chart ships a `:443` egress rule plus a `.Values` CIDR-override hook and documents this. **Bedrock egress** is disabled by default and enabled via a values override (F-007 carryover).

---

## 9. Threat Model — 13 vectors + 2 regression tests (CANONICAL; cite these numbers)

Each test **proves the control holds**, not merely "runs". Test files: `tests/gateway/test_health_endpoints.py` (1–4, 3b, regressions), `tests/gateway/test_tracing_export.py` (13), `tests/deploy/test_dockerfile.py` (5–7), `tests/deploy/test_compose.py` (8), `tests/deploy/test_helm.py` (9–11), `tests/deploy/test_release_workflow.py` (12).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | `/livez` touches DB | no DB/Redis import on liveness path (R5/D5) | Postgres down → `/livez` still 200 |
| 2 | `/readyz` masks Postgres outage | Postgres `SELECT 1` gate (D5) | Postgres down → `/readyz` 503 |
| 3 | `/readyz` over-gates on Redis (reframed) | Postgres-only gate; Redis non-gating (D5, §F-009) | Redis down → `/readyz` **200** + body `redis:"degraded"` |
| 3b | `/readyz` probe storm | reads `is_degraded()` flag, no fresh probe (D5) | `/readyz` opens **no** Redis connection |
| 4 | Health info disclosure | bounded body; app-version only (D5, R9) | no keys / DB URLs / build info beyond app version |
| 5 | Image runs as root | `USER 1000` (D1, R9) | inspect → non-root uid 1000 |
| 6 | Secrets baked in layers | no secret COPY; `.dockerignore` (D1, R4) | history/layers → no `.env`/keys/tokens |
| 7 | Healthcheck non-functional | python-urllib `/livez` (D1) | container reports healthy ≤30 s |
| 8 | Compose secret in env dump | file-secrets + shim (D2) | `docker inspect` env has no `*_PASSWORD` |
| 9 | Helm chart invalid | `helm lint` (D-chart) | exits 0, zero warnings |
| 10 | Helm renders broken YAML | `helm template` (D-chart) | all templates parse as valid YAML |
| 11 | NetworkPolicy permissive | default-deny + explicit allow (D7, R8) | rendered NP denies egress except allowed |
| 12 | Release workflow invalid | `actionlint` (D6) | passes; required permissions present |
| 13 | OTLP exporter wiring (new) | env-gated SpanProcessor (D4) | exporter added **iff** endpoint set; no-op when unset |
| R-a | `/health`+`/ready` drift (regression) | preserved handlers (D5) | exact ADR-0006 D2 shapes + codes |
| R-b | `/healthz` ≠ `/readyz` (regression) | alias wiring (D5) | identical shape/status to `/readyz` |

---

## 10. Alternatives Considered & Honest Deferrals

- **Compose-only — REJECTED.** Enterprise k8s customers locked out; the design-partner target includes both SMB self-host and k8s.
- **Helm-only — REJECTED.** SMB onboarding friction too high for early design partners; Compose is the one-command path.
- **External secret managers (Vault / AWS-SM) required at v1 — REJECTED.** Raises onboarding friction; native Docker/k8s secrets suffice for v1. Deferred to **F-010.1** as a documented integration.
- **External Postgres/Redis required from v1 — REJECTED.** Onboarding friction; bundled-by-default with a documented escape hatch is the lower-friction default.
- **Jaeger bundled directly — REJECTED.** Locks customers into one backend; the OTel Collector is the standard interop layer (customer points it anywhere).
- **`/readyz` hard-gates on Redis (dispatch R6) — REJECTED.** Contradicts F-009 γ; a Redis blip would remove every pod from the Service = self-inflicted outage. Postgres-only gate; Redis surfaced non-gating. (§"F-009 fallback preservation".)
- **Rename `/health`+`/ready` to z-names — REJECTED.** Breaks ADR-0006 D2 and any already-wired probes. Additive is back-compat-safe.
- **`curl`-based HEALTHCHECK (dispatch literal) — REJECTED.** `curl` is absent from `python:3.12-slim-bookworm`; installing it bloats the image. `python -c urllib` uses the interpreter already present.
- **Collector-only, defer app export — REJECTED (Affu).** F-009 explicitly handed OTLP export to F-010; shipping a collector that receives nothing is a hollow deliverable. The env-gated export is wired under an authorized R1 deviation.
- **Honest deferrals/gaps:** cosign keyless signing ties **verification** to Sigstore availability (no key-management burden, but an external dependency); Caddy auto-TLS assumes a **public-facing deployment with valid DNS** (private deployments need manual cert provisioning / cert-manager); **External Secrets Operator** deferred to F-010.1; **Bedrock egress allowlist** deferred (F-007 carryover, values-override documented); **NetworkPolicy FQDN egress** for provider hosts needs a FQDN-aware CNI (plain NP ships `:443` + CIDR override); **kube server-side dry-run** deferred to CI (no local kind cluster); **<300 MB** is a target measured at STEP 2, not a guarantee; F-009's per-worker duplication of degraded/recovered events is unchanged.

## 11. R1 deviation notes (explicit, Affu-authorized)

R1 reads: *"the only src/ changes allowed: health.py, main.py, __init__.py."* F-010 takes **two** bounded, additive deviations beyond that allow-list, each authorized by Affu and each changing **no request semantics**. Both mirror the ADR-0011 §8 R7-deviation precedent.

**Deviation 1 — `src/gateway/observability/tracing.py` (OTLP export).** Adds an env-gated OTLP `BatchSpanProcessor` to `_configure_provider()`. This is the **direct completion of F-009's own documented handoff** (the F-009 `tracing.py` docstring: *"F-010 replaces this with an OTLP exporter configured from env vars"*) and ADR-0011 §6/§10's deferral. **Additive and env-gated** (no-op when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset → byte-identical to F-009), **R8-safe** (wrapped; an export failure never affects the request path).

**Deviation 2 — middleware operational-exempt allowlists.** The new `/livez`, `/readyz`, `/healthz` probes are unauthenticated by design (§6, dispatch §4), but the operational-exempt allowlists are hardcoded `frozenset({"/health","/ready"})` in three files: `middleware/auth.py` (`_AUTH_EXEMPT_PATHS`), `middleware/tenant_context.py` (`_AUTH_EXEMPT_PATHS`), and `middleware/terminal_audit_wrapper.py` (`_AUDIT_EXEMPT_PATHS`). F-010 **adds the three new literals** to each set. This is **purely additive** — the new entries are the same category as the existing `/health`/`/ready` (operational, no tenant data, no `/v1` surface, no usage to audit); **no branch, gate, or logic is changed**. Without it the new probes return 400 (header-gated) and would spam the audit log on every k8s probe interval. Surfaced as a consequence of the Fork-A decision (add new endpoints) and authorized by Affu.

Outside these two deviations and the R1 allow-list (health.py, main.py — unchanged in practice, __init__.py), the only other touched file is `pyproject.toml` (the OTLP-exporter dependency + version bump), which is not under `src/`.

## 12. F-009 fallback preservation (dispatch-R6 correction)

The deployment layer **MUST NOT contradict** F-009's γ design. ADR-0011 §3/§10 makes Redis **non-fatal**: on a Redis outage the limiter falls back to in-process enforcement and the gateway **keeps serving**. The original dispatch R6 ("`/readyz` returns 503 when Postgres **or** Redis unreachable") would have a readiness probe remove every pod from the k8s Service the instant Redis blips — converting a graceful degradation into a hard outage and directly contradicting a locked decision. **Corrected R6:** `/readyz` returns 503 **only** when Postgres (a hard dependency — audit log, RBAC, policy all require it, with no fallback) is unreachable; Redis health is surfaced as a **non-gating** informational body field read from the existing F-009 health signal (`redis_client.is_degraded()` / the `sentinel_redis_health` gauge), with **no fresh probe** opened by the readiness path. This is the architecturally correct posture for a gateway that, by design, tolerates Redis loss.

## 13. Contract Changes

**None.** F-010 adds no endpoint to `contracts/openapi.yaml`, no variant to `contracts/events.schema.json`, and no change to `contracts/policy.schema.json`. The new `/livez`/`/readyz`/`/healthz` endpoints are out-of-contract **operational** endpoints (the ADR-0006 Decision 2 precedent for `/health`+`/ready`) for k8s probes and load balancers; they carry no tenant data, require none of the four ID headers, and emit no events. No `contracts/` write occurs, so the api-architect gate does not apply.

## 14. Consequences

### 14.1 Positive
- Sentinel becomes **genuinely deployable** by a design partner on both SMB (one `docker compose up`) and enterprise k8s (`helm install`).
- The **OTel deferral closes**: traces flow end-to-end into a bundled, vendor-neutral collector; customers point it at any backend via config.
- The image is **supply-chain hardened**: non-root, minimal, signed (cosign keyless), with a per-release SBOM (syft).
- k8s-idiomatic probes (`/livez`/`/readyz`) integrate cleanly with standard tooling while preserving back-compat.

### 14.2 Negative / costs
- A **container image + Helm chart** are now maintenance surface (base-image CVE patching, chart version skew). Mitigated by the release pipeline + Dependabot-style base pinning.
- Bundled Postgres/Redis are **dev/demo-grade**; production must opt into managed services (documented). The escape hatch adds values-schema complexity.
- cosign keyless signing introduces a **Sigstore availability** dependency for verification.
- NetworkPolicy FQDN egress is **CNI-dependent** (honest limitation documented).
- One authorized R1 deviation (tracing.py export) — bounded, env-gated, recorded (§11).

### 14.3 Rollback / migration
- **Migration path: none.** F-010 is **purely additive** — no schema migration, no `contracts/` change, nothing to roll back at the data layer.
- **OTel export:** unset `OTEL_EXPORTER_OTLP_ENDPOINT` → app reverts to the F-009 no-op sink immediately.
- **Health endpoints:** the new z-endpoints are additive; `/health`+`/ready` are byte-identical, so existing probes are unaffected.
- **Whole feature:** revert `task/F-010-deployment-release-native`; the Dockerfile, compose additions, Helm chart, and release workflow are all inert if unused, and the version bump is cosmetic. The single tracing.py line reverts to the F-009 no-op provider.
