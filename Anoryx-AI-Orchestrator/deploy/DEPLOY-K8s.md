# Deploying Anoryx-AI-Orchestrator to a single Kubernetes cluster (O-008)

This packages the same stack the compose file runs (orchestrator app + Postgres)
as a Helm chart for **one** cluster. Mirrors Anoryx-Sentinel's F-010 Part 2
pattern (ADR-0012/0027), scaled down: no Redis/MinIO/worker/frontend.

> Honest status: the chart `helm lint`s + `helm template`s clean and deploys its
> topology with correct migration ordering. mTLS between Sentinel and this
> ingest seam is NOT provisioned by this chart (ADR-0008 §Honest deferrals) —
> the interim peer authenticator is the shared `ORCH_INGEST_HMAC_SECRET`.

## 0. Prerequisites

- `kubectl` + `helm` v3, and a single-node local cluster (Docker Desktop
  Kubernetes or `kind`).
- The image built by the repo Dockerfile:

```bash
# Build (from Anoryx-AI-Orchestrator/) if not already built:
docker build -t anoryx-orchestrator:0.1.0 .

# kind only — load it into the node:
kind load docker-image anoryx-orchestrator:0.1.0 --name orchestrator
```

## 1. Create the namespace + Secret (no secrets in the repo)

`gen-k8s-secret.sh` generates **fresh dev values** and creates the env Secret.
Nothing sensitive is ever written into the repo.

```bash
bash deploy/helm/gen-k8s-secret.sh orchestrator orchestrator   # <namespace> <release>
# -> Secret orchestrator-orchestrator-env
```

The bundled-Postgres password is dev-grade (`orchestrator`) and is rendered by
the chart itself — change it (and switch to `postgres.bundled=false` + a
managed DB) for anything beyond a demo.

## 2. Install

```bash
helm install orchestrator deploy/helm/orchestrator -n orchestrator \
  -f deploy/helm/orchestrator/values.example.yaml --set envSecret=orchestrator-orchestrator-env
```

Ordering: the **migrate Job** (`alembic upgrade head` + `orchestrator_app`
SCRAM provisioning, via the entrypoint shim) runs behind a `wait-for-postgres`
init; the orchestrator Deployment carries a `wait-for-migrate` init that blocks
until the schema is at head — so nothing serves an un-migrated DB.

```bash
kubectl -n orchestrator get pods -w
kubectl -n orchestrator logs job/orchestrator-orchestrator-migrate-1 | grep -E 'alembic|orchestrator_app'
```

## 3. Smoke test

```bash
kubectl -n orchestrator port-forward svc/orchestrator-orchestrator 8081:8081 &
curl -fs http://localhost:8081/health
# Expected: {"status":"ok"}

ADMIN_TOKEN=$(kubectl -n orchestrator get secret orchestrator-orchestrator-env -o jsonpath='{.data.ORCH_ADMIN_TOKEN}' | base64 -d)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8081/v1/admin/events/recent -H "Authorization: Bearer $ADMIN_TOKEN"
# Expected: 200
```

`helm test` runs the same probe against the live Service:

```bash
helm test orchestrator -n orchestrator
```

## 4. Clean reproduce

```bash
helm uninstall orchestrator -n orchestrator
kubectl -n orchestrator wait --for=delete pvc --all --timeout=180s   # PVC is chart-owned -> fresh DB next install
helm install orchestrator deploy/helm/orchestrator -n orchestrator -f deploy/helm/orchestrator/values.example.yaml --set envSecret=orchestrator-orchestrator-env
```

The env Secret is NOT chart-owned, so it persists across uninstall and is
reused — the only documented prerequisite is the one `gen-k8s-secret.sh` run.
The PVC is chart-owned → reinstall gets a fresh DB, migrate re-runs
idempotently.

---

## Security notes — K8s attack surface

- **Secrets.** Sensitive material lives in K8s Secrets (`…-env`, `…-postgres`),
  never in the chart or repo. The Postgres password is referenced by
  `secretKeyRef` so it never appears in a pod spec (`kubectl get pod -o yaml` /
  etcd). `gen-k8s-secret.sh` keeps generated values ephemeral. K8s Secrets are
  base64, not encrypted at rest by default — enable etcd encryption / a secrets
  operator for production (deferred, below).
- **Non-root + hardened.** The orchestrator/migrate pods run as non-root (uid
  1000) with `readOnlyRootFilesystem`, dropped capabilities, no privilege
  escalation, `RuntimeDefault` seccomp.
- **Exposure is minimal.** The Service is `ClusterIP`; access for the demo is
  `kubectl port-forward`. No NodePort/LoadBalancer/Ingress is opened by default.
- **NetworkPolicy.** The chart ships a NetworkPolicy, but egress to Sentinel
  instances and ingress on the ingest port are open by default (plain
  NetworkPolicy cannot match by hostname, and neither endpoint is known at
  chart-render time) — restrict both via `networkPolicy.sentinelEgressCIDRs`
  and `networkPolicy.ingressCIDRs`. It is only enforced by a policy-capable CNI
  (kind's kindnet / Docker Desktop do not enforce it).

## Still out of scope — named, not half-built (ADR-0008 §Honest deferrals)

Vault / KMS (this chart uses K8s Secrets, mirroring Sentinel's own F-010
pattern) · real mTLS between Sentinel and the ingest seam (the interim peer
authenticator is `ORCH_INGEST_HMAC_SECRET`) · public TLS / cert-manager /
hardened production Ingress (demo uses port-forward) · HPA / autoscaling (the
`hpa.yaml` template exists but stays `autoscaling.enabled=false`).
