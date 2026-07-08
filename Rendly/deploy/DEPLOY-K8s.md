# Deploying Rendly to a single Kubernetes cluster (R-010)

This packages the same stack the compose file runs (rendly app + Postgres) as a Helm chart
for **one** cluster. Mirrors Anoryx-AI-Orchestrator's O-008 pattern (ADR-0008), scaled down
further: no Redis/MinIO/worker/frontend, and no cross-product network dependency either.

> Honest status: the chart `helm lint`s + `helm template`s clean and deploys its topology
> with correct migration ordering. Vault/KMS and mTLS are NOT provisioned by this chart
> (ADR-0010 §Honest deferrals) — Rendly's one secret (the ES256 JWT signing key) is delivered
> as a native K8s Secret.

## 0. Prerequisites

- `kubectl` + `helm` v3, and a single-node local cluster (Docker Desktop Kubernetes or `kind`).
- The image built by the repo Dockerfile:

```bash
# Build (from Rendly/) if not already built:
docker build -t anoryx-rendly:1.0.0 .

# kind only — load it into the node:
kind load docker-image anoryx-rendly:1.0.0 --name rendly
```

## 1. Create the namespace + Secret (no secrets in the repo)

`gen-k8s-secret.sh` generates a **fresh dev ES256 key** and creates the env Secret. Nothing
sensitive is ever written into the repo.

```bash
bash deploy/helm/gen-k8s-secret.sh rendly rendly   # <namespace> <release>
# -> Secret rendly-rendly-env
```

The bundled-Postgres password is dev-grade (`rendly`) and is rendered by the chart itself —
change it (and switch to `postgres.bundled=false` + a managed DB) for anything beyond a demo.

## 2. Install

```bash
helm install rendly deploy/helm/rendly -n rendly \
  -f deploy/helm/rendly/values.example.yaml --set envSecret=rendly-rendly-env
```

Ordering: the **migrate Job** (`alembic upgrade head` + `rendly_app` SCRAM provisioning, via
the entrypoint shim) runs behind a `wait-for-postgres` init; the rendly Deployment carries a
`wait-for-migrate` init that blocks until the schema is at head — so nothing serves an
un-migrated DB.

```bash
kubectl -n rendly get pods -w
kubectl -n rendly logs job/rendly-rendly-migrate-1 | grep -E 'alembic|rendly_app'
```

## 3. Smoke test

```bash
kubectl -n rendly port-forward svc/rendly-rendly 8082:8082 &
curl -fs http://localhost:8082/health
# Expected: {"status":"ok"}
```

`helm test` runs the same probe against the live Service:

```bash
helm test rendly -n rendly
```

## 4. Clean reproduce

```bash
helm uninstall rendly -n rendly
kubectl -n rendly wait --for=delete pvc --all --timeout=180s   # PVC is chart-owned -> fresh DB next install
helm install rendly deploy/helm/rendly -n rendly -f deploy/helm/rendly/values.example.yaml --set envSecret=rendly-rendly-env
```

The env Secret is NOT chart-owned, so it persists across uninstall and is reused — the only
documented prerequisite is the one `gen-k8s-secret.sh` run. The PVC is chart-owned →
reinstall gets a fresh DB, migrate re-runs idempotently.

---

## Security notes — K8s attack surface

- **Secrets.** Sensitive material lives in K8s Secrets (`…-env`, `…-postgres`), never in the
  chart or repo. The Postgres password and the JWT signing key are both referenced by
  `secretKeyRef`/`envFrom` so neither appears in a pod spec (`kubectl get pod -o yaml` /
  etcd). `gen-k8s-secret.sh` keeps generated values ephemeral. K8s Secrets are base64, not
  encrypted at rest by default — enable etcd encryption / a secrets operator for production
  (deferred, below).
- **Non-root + hardened.** The rendly/migrate pods run as non-root (uid 1000) with
  `readOnlyRootFilesystem`, dropped capabilities, no privilege escalation, `RuntimeDefault`
  seccomp.
- **Exposure is minimal.** The Service is `ClusterIP`; access for the demo is `kubectl
  port-forward`. No NodePort/LoadBalancer/Ingress is opened by default.
- **NetworkPolicy.** The chart ships a NetworkPolicy that is stricter than the
  Orchestrator's own: Rendly has no outbound cross-product dependency, so egress is scoped to
  DNS + the bundled Postgres pod only — there is no open `:443`-to-anywhere rule to carry.
  Ingress on the http port is open by default (clients are not known at chart-render time) —
  restrict via `networkPolicy.ingressCIDRs`. Enforcement needs a policy-capable CNI (kind's
  kindnet / Docker Desktop do not enforce it).
- **Single instance by default.** `replicaCount: 1`, `autoscaling.enabled: false`. The
  realtime WebSocket chat/huddle layer keeps connection + huddle state IN-PROCESS (no
  Redis/broker fan-out) — running more than one replica silently breaks cross-replica
  message/huddle delivery. Do not raise `replicaCount` or enable `autoscaling` without first
  adding a shared broker (out of scope for R-010).

## Still out of scope — named, not half-built (ADR-0010 §Honest deferrals)

Vault / KMS (this chart uses a K8s Secret for the ES256 key, mirroring the Orchestrator's
own O-008 pattern) · real mTLS (Rendly has no inter-product network call to protect; deferred
alongside the rest of the ecosystem's mTLS work) · public TLS / cert-manager / hardened
production Ingress (demo uses port-forward) · HPA / autoscaling (the `hpa.yaml` template
exists but stays `autoscaling.enabled=false` — NOT safe for the realtime layer without a
shared broker) · a DB-gated `/readyz` split (single `/health` today).
