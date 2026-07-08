# Docker secrets — Delta (Docker Compose)

D-010 mounts credentials as **file-based Docker secrets** (mirrors Anoryx-AI-
Orchestrator's O-008, ADR-0008 Fork D, itself mirroring Anoryx-Sentinel's
F-010, ADR-0012 §3), not environment variables. The `delta-ingest` and
`delta-admin` entrypoints read these files at `/run/secrets/*` and assemble
the connection URLs / tokens at startup, so no secret ever appears in
`docker-compose.yml`, the container `environment:`, or `docker inspect`
output.

This directory is git-ignored (see `.gitignore`) — **the files you create here
are never committed.**

## Generate the secret files

Run from the repository root (`Delta/`):

```bash
bash deploy/secrets/gen-dev-secrets.sh
```

Or manually:

```bash
# 1. Postgres password — MUST match the postgres service password.
printf '%s' "${POSTGRES_PASSWORD:-delta}" > deploy/secrets/postgres_password

# 2. Ingest HMAC signing secret (DELTA_INGEST_HMAC_SECRET) — random, 32+ bytes.
openssl rand -base64 48 > deploy/secrets/delta_ingest_hmac_secret

# 3. Outbound Bearer token to the Orchestrator (ORCH_SERVICE_TOKEN) — random,
#    32+ bytes. Only exercised when DELTA_BUDGET_ENGINE_ENABLED=1 or
#    DELTA_KILL_SWITCH_ENABLED=1 (both default 0 in docker-compose.yml).
openssl rand -base64 48 > deploy/secrets/orch_service_token

# 4. Admin break-glass bearer token (DELTA_ADMIN_TOKEN) — random, 32+ bytes.
openssl rand -base64 48 > deploy/secrets/delta_admin_token
```

## Required files

| File | Contents | Notes |
|------|----------|-------|
| `postgres_password` | Postgres password | Must equal the postgres service's `POSTGRES_PASSWORD`. |
| `delta_ingest_hmac_secret` | Random ≥32 bytes | HMAC key `delta.ingest` uses to verify `POST /v1/ingest/usage` signatures (`DELTA_INGEST_HMAC_SECRET`). Fail-loud if unset — the ingest app refuses to start. |
| `orch_service_token` | Random ≥32 bytes | Bearer token authenticating the Delta -> Orchestrator O-004 distribution seam (`ORCH_SERVICE_TOKEN`). Only required when the budget engine or kill-switch publish path is enabled. |
| `delta_admin_token` | Random ≥32 bytes | Break-glass bearer for the admin console (`DELTA_ADMIN_TOKEN`). Fail-loud if unset — the admin app refuses to start. |

## Production note

The bundled Postgres is dev/demo-grade. For production, point Delta at a
managed Postgres instance (set `DATABASE_URL` / `APP_DATABASE_URL` directly,
or via a secret manager) — see `deploy/DEPLOY-K8s.md`. External Secrets
Operator / Vault / cloud KMS integration is documented future work (see
"Honest deferrals" in `deploy/DEPLOY-K8s.md`), same posture Anoryx-AI-
Orchestrator's own O-008 and Anoryx-Sentinel's F-010 shipped with.
