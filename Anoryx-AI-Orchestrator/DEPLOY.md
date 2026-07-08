# Anoryx-AI-Orchestrator — Compose Demo Walkthrough (O-008)

This guide stands up the Orchestrator + a bundled Postgres locally with zero
manual steps beyond the two commands below. Helm/K8s is covered in
`deploy/DEPLOY-K8s.md`.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2) — `docker compose` (not `docker-compose`).
- Ports 8081 and 5434 free on the host.

## Step 1 — Generate dev secrets

Run once from `Anoryx-AI-Orchestrator/`:

```bash
bash deploy/secrets/gen-dev-secrets.sh
```

This creates three files in `deploy/secrets/` (git-ignored):
`postgres_password`, `orch_ingest_hmac_secret`, `orch_admin_token`.

The script is idempotent — re-running skips files that already exist.

## Step 2 — Start the stack

```bash
docker compose up -d --build
```

Wait for both services to be healthy:

```bash
docker compose ps
```

Expected healthy state:

| Service                | Status  |
|-------------------------|---------|
| orchestrator-postgres   | healthy |
| orchestrator-app        | healthy |

## Step 3 — Smoke test

### a) Confirm migrations ran to head

```bash
docker compose exec -T orchestrator-app sh -c 'cd /app && PYTHONPATH=/app/src alembic current'
```

### b) Health probe

```bash
curl -fs http://localhost:8081/health
# Expected: {"status":"ok"}
```

### c) Send a signed ingest event (mirrors Sentinel's outbound HMAC signer)

The ingest seam requires an HMAC-SHA256 signature over the raw request body
using `orch_ingest_hmac_secret`, plus an `X-Anoryx-Timestamp` header within the
replay window — see `contracts/openapi.yaml` and `src/orchestrator/ingest/` for
the exact signing scheme. `tests/integration/test_ingest_e2e.py` has a working
reference signer.

### d) Admin API (requires ORCH_ADMIN_TOKEN)

```bash
ADMIN_TOKEN=$(cat deploy/secrets/orch_admin_token | tr -d '\r\n')
curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8081/v1/admin/events/recent \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# Expected: 200
```

## Step 4 — Teardown and reproduce

```bash
docker compose down -v   # removes volumes — fresh DB on next up
docker compose up -d     # no --build needed (image cached)
```

## Postgres direct access (dev only)

The compose postgres is exposed on host port **5434** (internal 5432):

```bash
psql -h localhost -p 5434 -U orchestrator -d orchestrator_dev
# Password: orchestrator (from deploy/secrets/postgres_password)
```

## Compose-only scope

This guide is compose-only (local dev). For Kubernetes, Helm values, and
production secret injection, see `deploy/DEPLOY-K8s.md`. External Secrets
Operator / Vault / mTLS integration is documented future work — see
`docs/adr/0008-deployment.md` §Honest deferrals.
