# Docker secrets — Anoryx Sentinel (Docker Compose)

F-010 mounts credentials as **file-based Docker secrets** (ADR-0012 §3, native
secrets = β), not environment variables. The `sentinel-app` entrypoint reads
these files at `/run/secrets/*` and assembles the connection URLs at startup, so
no password ever appears in `docker-compose.yml`, the container `environment:`,
or `docker inspect` output (threat vector 8).

This directory is git-ignored (see `.gitignore`) — **the files you create here
are never committed.**

## Generate the secret files

Run from the repository root (`Anoryx-Sentinel/`):

```bash
# 1. Postgres password — MUST match the postgres service password.
#    The bundled postgres service reads POSTGRES_PASSWORD (default "sentinel").
#    For a real deployment, set a strong password in BOTH places:
#      export POSTGRES_PASSWORD=$(openssl rand -base64 24)
#    then write the same value here:
printf '%s' "${POSTGRES_PASSWORD:-sentinel}" > deploy/secrets/postgres_password

# 2. Redis password — LEAVE EMPTY for the bundled Redis (it runs WITHOUT
#    requirepass; the entrypoint then builds a password-less REDIS_URL). Only
#    put a value here when pointing REDIS at an external authenticated instance.
:> deploy/secrets/redis_password            # creates an empty file

# 3. Sentinel signing-key secret (HMAC for virtual API keys) — random, 32+ bytes.
openssl rand -base64 48 > deploy/secrets/sentinel_key_secret
```

> Windows PowerShell equivalents:
> ```powershell
> "sentinel" | Out-File -NoNewline deploy/secrets/postgres_password -Encoding ascii
> New-Item -ItemType File -Force deploy/secrets/redis_password | Out-Null
> [Convert]::ToBase64String((1..48 | % {Get-Random -Max 256})) | Out-File -NoNewline deploy/secrets/sentinel_key_secret -Encoding ascii
> ```

## Required files

| File | Contents | Notes |
|------|----------|-------|
| `postgres_password` | Postgres password | Must equal the postgres service's `POSTGRES_PASSWORD`. |
| `redis_password` | (empty for bundled) | Empty ⇒ password-less `REDIS_URL`. Set only for external Redis. |
| `sentinel_key_secret` | Random ≥32 bytes | HMAC key for virtual API keys. Rotate per `deploy/SELF_HOST.md`. |

## Production note

Bundled Postgres/Redis are dev/demo-grade. For production, point Sentinel at
managed services (set `DATABASE_URL` / `APP_DATABASE_URL` / `REDIS_URL` directly,
or via a secret manager) — see `deploy/SELF_HOST.md`. External Secrets Operator /
Vault / AWS-SM integration is documented future work (F-010.1, ADR-0012 §10).
