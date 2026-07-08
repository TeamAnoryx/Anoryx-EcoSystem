# Deploying Delta to a single Kubernetes cluster (D-010)

This packages the same stack the compose file runs (delta-ingest + delta-admin
+ Postgres) as a Helm chart for **one** cluster. Mirrors Anoryx-AI-
Orchestrator's O-008 pattern (ADR-0008), itself mirroring Anoryx-Sentinel's
F-010 Part 2 pattern (ADR-0012/0027) — adapted for Delta's TWO ASGI services
instead of one, and with NO bundled Redis (zero Delta code imports it — a
deliberate, documented scope decision, not a silent omission of the roadmap's
generic "Postgres + Redis" phrasing).

> Honest status: the chart `helm lint`s + `helm template`s clean and deploys
> its topology with correct migration ordering. mTLS between Delta and the
> Orchestrator's O-004 distribution seam is NOT provisioned by this chart (see
> "Honest deferrals" below) — the interim peer authenticator is the shared
> `ORCH_SERVICE_TOKEN` bearer.

## 0. Prerequisites

- `kubectl` + `helm` v3, and a single-node local cluster (Docker Desktop
  Kubernetes or `kind`).
- The image built by the repo Dockerfile:

```bash
# Build (from Delta/) if not already built:
docker build -t anoryx-delta:0.2.0 .

# kind only — load it into the node:
kind load docker-image anoryx-delta:0.2.0 --name delta
```

## 1. Create the namespace + Secret (no secrets in the repo)

`gen-k8s-secret.sh` generates **fresh dev values** and creates the shared env
Secret both apps read from. Nothing sensitive is ever written into the repo.

```bash
bash deploy/helm/gen-k8s-secret.sh delta delta   # <namespace> <release>
# -> Secret delta-delta-env
```

The bundled-Postgres password is dev-grade (`delta`) and is rendered by the
chart itself — change it (and switch to `postgres.bundled=false` + a managed
DB) for anything beyond a demo.

## 2. Install

```bash
helm install delta deploy/helm/delta -n delta \
  -f deploy/helm/delta/values.example.yaml --set envSecret=delta-delta-env
```

Ordering: the **migrate Job** (`alembic upgrade head` + `delta_app` SCRAM
provisioning, via the entrypoint shim) runs behind a `wait-for-postgres` init;
BOTH the ingest and admin Deployments carry a `wait-for-migrate` init that
blocks until the schema is at head — so nothing serves an un-migrated DB.

```bash
kubectl -n delta get pods -w
kubectl -n delta logs job/delta-delta-migrate-1 | grep -E 'alembic|delta_app'
```

## 3. Smoke test

```bash
kubectl -n delta port-forward svc/delta-delta-ingest 8000:8000 &
curl -fs http://localhost:8000/health
# Expected: {"status":"ok"}

kubectl -n delta port-forward svc/delta-delta-admin 8001:8001 &
ADMIN_TOKEN=$(kubectl -n delta get secret delta-delta-env -o jsonpath='{.data.DELTA_ADMIN_TOKEN}' | base64 -d)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8001/health
# Expected: 200
```

`helm test` runs the same two probes against both live Services:

```bash
helm test delta -n delta
```

## 4. Enabling real enforcement publishing (optional)

By default `budgetEngineEnabled=false` and `killSwitchEnabled=false` — the
ingest app starts cleanly with no reachable Orchestrator configured. Both the
D-005 budget engine and D-006 kill-switch are fail-loud at startup when
enabled without a valid `DELTA_ORCH_DISTRIBUTION_URL` + `ORCH_SERVICE_TOKEN`,
so turning enforcement on requires both:

```bash
helm upgrade delta deploy/helm/delta -n delta \
  --set envSecret=delta-delta-env \
  --set orchestratorDistributionUrl=https://orchestrator.example.internal \
  --set budgetEngineEnabled=true \
  --set killSwitchEnabled=true
```

(`ORCH_SERVICE_TOKEN` in the `envSecret` must be a token the Orchestrator's
O-004 distribution seam actually accepts — `gen-k8s-secret.sh` generates a
random placeholder, not a value the Orchestrator recognizes.)

## 5. Clean reproduce

```bash
helm uninstall delta -n delta
kubectl -n delta wait --for=delete pvc --all --timeout=180s   # PVC is chart-owned -> fresh DB next install
helm install delta deploy/helm/delta -n delta -f deploy/helm/delta/values.example.yaml --set envSecret=delta-delta-env
```

The env Secret is NOT chart-owned, so it persists across uninstall and is
reused — the only documented prerequisite is the one `gen-k8s-secret.sh` run.
The PVC is chart-owned -> reinstall gets a fresh DB, migrate re-runs
idempotently.

---

## Security notes — K8s attack surface

- **Secrets.** Sensitive material lives in K8s Secrets (`…-env`, `…-postgres`),
  never in the chart or repo. The Postgres password is referenced by
  `secretKeyRef` so it never appears in a pod spec (`kubectl get pod -o yaml` /
  etcd). `gen-k8s-secret.sh` keeps generated values ephemeral. K8s Secrets are
  base64, not encrypted at rest by default — enable etcd encryption / a secrets
  operator for production (deferred, below).
- **Non-root + hardened.** The ingest/admin/migrate pods run as non-root (uid
  1000) with `readOnlyRootFilesystem`, dropped capabilities, no privilege
  escalation, `RuntimeDefault` seccomp.
- **Admin is internal-only.** The admin console's Service is `ClusterIP` and
  its NetworkPolicy allows ONLY same-namespace + the monitoring namespace —
  there is no CIDR-based open-by-default escape hatch for it (unlike the
  ingest component). It is reached via `kubectl port-forward` or an
  operator-supplied internal gateway, never a public Ingress.
- **Exposure is minimal.** Both Services are `ClusterIP`; access for the demo
  is `kubectl port-forward`. No NodePort/LoadBalancer/Ingress is opened by
  default (`ingress.enabled=false`, ingest only).
- **NetworkPolicy.** The chart ships a NetworkPolicy per component, but egress
  to the Orchestrator and ingress on the ingest port are open by default
  (plain NetworkPolicy cannot match by hostname, and neither endpoint is known
  at chart-render time) — restrict both via
  `networkPolicy.orchestratorEgressCIDRs` and `networkPolicy.ingressCIDRs`.
  Enforcement requires a policy-capable CNI (kind's kindnet / Docker Desktop
  do not enforce it).

## Still out of scope — named, not half-built ("Honest deferrals")

Vault / KMS (this chart uses K8s Secrets, mirroring Anoryx-AI-Orchestrator's
own O-008 and Anoryx-Sentinel's F-010 pattern) · real mTLS between Delta and
the Orchestrator's O-004 distribution seam (the interim peer authenticator is
`ORCH_SERVICE_TOKEN`) · public TLS / cert-manager / hardened production
Ingress (demo uses port-forward) · HPA / autoscaling for the ingest component
(the `hpa.yaml` template exists but stays `ingest.autoscaling.enabled=false`;
the admin console has no autoscaling knob at all) · Redis / KEDA queue-depth
scaling (zero Delta code has a bulk-worker/Redis-Streams queue to scale — this
is a documented scope decision, not an omission of the roadmap's generic
"Postgres + Redis" phrasing).
