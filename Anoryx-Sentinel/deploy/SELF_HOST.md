# Self-Hosting Anoryx Sentinel

Production deployment guide for the Anoryx Sentinel zero-trust AI gateway
(F-010, ADR-0012). Two supported targets:

- **Docker Compose** — SMB / single-host self-hosting.
- **Helm chart** — Kubernetes for enterprises.

> Related docs: local dev bring-up → [`deploy/README.md`](./README.md); secrets →
> [`deploy/secrets/README.md`](./secrets/README.md); observability backends →
> [`deploy/otel/README.md`](./otel/README.md); design rationale →
> [`docs/adr/0012-deployment-and-release.md`](../docs/adr/0012-deployment-and-release.md).

> **Honest scope (ADR-0012 §10):** bundled Postgres/Redis are dev/demo-grade —
> use managed services in production. cosign signature verification depends on
> Sigstore availability. Caddy auto-TLS assumes public DNS. External Secrets
> Operator / Vault / AWS-SM integration is documented future work (F-010.1).

---

## 1. Quick start — Docker Compose

```bash
cd Anoryx-Sentinel

# 1. Create the secret files (see deploy/secrets/README.md for details).
printf 'sentinel'              > deploy/secrets/postgres_password
: >                              deploy/secrets/redis_password        # empty: bundled Redis is password-less
openssl rand -base64 48        > deploy/secrets/sentinel_key_secret

# 2. Point the gateway at your model provider (example: OpenAI).
export UPSTREAM_BASE_URL=https://api.openai.com/v1

# 3. Bring up the stack (postgres + redis + otel-collector + sentinel-app).
docker compose up -d --build

# 4. Verify.
curl -fs http://localhost:8000/livez && echo
curl -fs http://localhost:8000/readyz && echo
```

The `sentinel-app` entrypoint runs `alembic upgrade head` (provisioning the
`sentinel_app` role) before serving. Add TLS with the opt-in profile:

```bash
docker compose --profile tls up -d   # adds Caddy auto-TLS (needs public DNS)
```

## 2. Quick start — Kubernetes (Helm)

```bash
# 1. Create the Secret holding sensitive config (external mode shown).
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-env \
  --from-literal=SENTINEL_KEY_SECRET="$(openssl rand -base64 48)" \
  --from-literal=UPSTREAM_BASE_URL=https://api.openai.com/v1 \
  --from-literal=DATABASE_URL='postgresql://user:pass@your-pg-host:5432/sentinel' \
  --from-literal=APP_DATABASE_URL='postgresql://sentinel_app:pass@your-pg-host:5432/sentinel' \
  --from-literal=REDIS_URL='redis://your-redis-host:6379/0'

# 2. Install (external managed PG/Redis).
helm install sentinel Anoryx-Sentinel/deploy/helm/sentinel -n sentinel \
  --set postgres.bundled=false --set redis.bundled=false \
  --set envSecret=sentinel-env

# 3. Verify.
kubectl -n sentinel rollout status deploy/sentinel-sentinel
kubectl -n sentinel port-forward svc/sentinel-sentinel 8000:8000
curl -fs http://localhost:8000/readyz && echo
```

For a zero-config demo (bundled, dev-grade PG/Redis), omit the `--set
postgres.bundled=false ...` flags and supply only `SENTINEL_KEY_SECRET` +
`UPSTREAM_BASE_URL` in the Secret.

---

## 3. Secrets management

| Target | Mechanism |
|--------|-----------|
| Docker Compose | **File-based Docker secrets** mounted at `/run/secrets/*`; the entrypoint assembles `DATABASE_URL`/`APP_DATABASE_URL`/`REDIS_URL`. Passwords never appear in `docker inspect`. |
| Kubernetes | **k8s Secret** named by `envSecret`, surfaced via `envFrom: secretRef`. |
| Future (F-010.1) | External Secrets Operator / Vault / AWS-SM — sync an external store into the k8s Secret consumed by `envSecret`. |

**Never** commit secret files or bake secrets into the image (the Dockerfile and
`.dockerignore` enforce this — R4).

## 4. TLS termination

- **Compose:** the `tls` profile runs Caddy with automatic Let's Encrypt certs.
  Edit `deploy/caddy/Caddyfile` (set your hostname + ACME email). Requires public
  DNS pointing at the host and ports 80/443 reachable. Private deployments:
  replace the site block with `tls /path/to/cert /path/to/key`.
- **Kubernetes:** terminate TLS at your ingress. Example with nginx + cert-manager:

  ```yaml
  # values override
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: sentinel.example.com
        paths: [{ path: /, pathType: Prefix }]
    tls:
      - secretName: sentinel-tls
        hosts: [sentinel.example.com]
  ```

## 5. Observability backend wiring

Sentinel exports OTLP to the bundled OpenTelemetry Collector
(`OTEL_EXPORTER_OTLP_ENDPOINT` is preset). By default the collector only logs to
its stdout. To ship to a backend (Jaeger, Tempo, Honeycomb, Datadog), edit the
collector config and add an exporter — full examples in
[`deploy/otel/README.md`](./otel/README.md). Prometheus scrapes `/metrics`
(unauthenticated — firewall/NetworkPolicy it; F-009 posture).

---

## 6. Production data stores

### Postgres (recommended: managed)
Use **RDS / Cloud SQL / AlloyDB**. Set `postgres.bundled=false` and provide
`DATABASE_URL` (privileged/owner role) + `APP_DATABASE_URL` (the `sentinel_app`
NOBYPASSRLS role) in the envSecret. The bundled in-cluster Postgres is
**dev/demo-grade only** (single replica, single PVC, default password).

### Redis (recommended: managed)
Use **ElastiCache / MemoryStore**. Set `redis.bundled=false` and provide
`REDIS_URL`. Redis is **non-fatal** (ADR-0011 §3 / ADR-0012 §12): if it is
unreachable the gateway falls back to in-process rate limiting and keeps serving
— `/readyz` reports `redis: degraded` but stays `200`.

---

## 7. Common operational scenarios

- **Rotate the signing key (`SENTINEL_KEY_SECRET`).** Update the secret file
  (compose) or the k8s Secret, then restart: `docker compose up -d` /
  `kubectl rollout restart deploy/sentinel-sentinel`. Note: rotating invalidates
  HMAC verification of any value derived from the old key — plan a window.
- **Scale up replicas.** Compose: `SENTINEL_WORKERS=4 docker compose up -d`.
  Helm: `--set replicaCount=4` or enable `autoscaling.enabled=true`.
- **Run migrations on a new version.** Compose runs them on startup
  (`RUN_MIGRATIONS=1`). Helm runs a pre-upgrade Job automatically on
  `helm upgrade`.
- **Change the OTel exporter.** Edit `deploy/otel/collector-config.yaml` (compose)
  or the collector ConfigMap (Helm), then restart the collector.
- **Restrict provider egress (Helm).** Set `networkPolicy.providerEgressCIDRs`
  (FQDN rules need a Cilium/Calico CNI). Allow AWS Bedrock egress (F-007 carryover)
  — and reach EXTERNAL managed Postgres/Redis when `bundled=false` — by adding raw
  rules to `networkPolicy.extraEgress`, e.g.:
  ```yaml
  networkPolicy:
    extraEgress:
      - to: [{ ipBlock: { cidr: 10.20.0.0/16 } }]
        ports: [{ port: 5432, protocol: TCP }]
  ```

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Sentinel won't start (CrashLoop) | Missing required env (`UPSTREAM_BASE_URL`, `DATABASE_URL`, `APP_DATABASE_URL`, `SENTINEL_KEY_SECRET`). Check `kubectl logs` / `docker compose logs sentinel-app`. |
| `/readyz` returns 503 | Postgres unreachable (the only readiness gate). Check `DATABASE_URL`, network policy, and that the migration Job/role provisioning succeeded. |
| `/readyz` shows `redis: degraded` but 200 | Expected when Redis is down — the gateway is serving with in-process rate limiting. Reconnect Redis to restore distributed limits. |
| Postgres migration fails | Verify the privileged role can `CREATE ROLE` (for `SENTINEL_PROVISION_APP_ROLE`). For managed PG, pre-create `sentinel_app` and set `provisionAppRole=false`. |
| OTel traces not in your backend | The bundled collector logs by default — you must add a backend exporter (`deploy/otel/README.md`). Confirm `OTEL_EXPORTER_OTLP_ENDPOINT` is set on the app. |
| `cosign verify` fails | Sigstore/Fulcio/Rekor must be reachable. See the verify command in the GitHub Release notes (ADR-0012 §7). |
