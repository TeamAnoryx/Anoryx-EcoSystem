# Docker secrets — Rendly (Docker Compose)

R-010 mounts credentials as **file-based Docker secrets** (mirrors Anoryx-AI-Orchestrator's
O-008, ADR-0008 §Fork D, itself mirroring Anoryx-Sentinel's F-010), not environment
variables. The `rendly-app` entrypoint reads these files at `/run/secrets/*` and assembles
the connection URLs / signing key at startup, so no secret ever appears in
`docker-compose.yml`, the container `environment:`, or `docker inspect` output.

This directory is git-ignored (see `.gitignore`) — **the files you create here are never
committed.**

## Generate the secret files

Run from the repository root (`Rendly/`):

```bash
bash deploy/secrets/gen-dev-secrets.sh
```

Or manually:

```bash
# 1. Postgres password — MUST match the postgres service password.
printf '%s' "${POSTGRES_PASSWORD:-rendly}" > deploy/secrets/postgres_password

# 2. ES256 (P-256) JWT signing key (RENDLY_JWT_PRIVATE_KEY_PEM).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
  > deploy/secrets/rendly_jwt_private_key_pem
```

## Required files

| File | Contents | Notes |
|------|----------|-------|
| `postgres_password` | Postgres password | Must equal the postgres service's `POSTGRES_PASSWORD`. |
| `rendly_jwt_private_key_pem` | ES256 (P-256) private key, PKCS8 PEM | Signs + verifies every access/refresh token (`RENDLY_JWT_PRIVATE_KEY_PEM`). Loaded fail-closed — the app refuses to start if this is absent, malformed, or not a P-256 key (`rendly.auth.keys`). Rotating it invalidates every outstanding token. |

## Optional, not wired into this dev compose

`RENDLY_STUN_URLS` / `RENDLY_TURN_URLS` (R-007 self-hosted ICE bootstrap) are non-secret
config — set them as plain env vars if you run your own coturn. `RENDLY_TURN_SHARED_SECRET`
(the coturn REST-API static-auth-secret) is sensitive but optional: unset, huddles still get
STUN-only ICE candidates. Wire it as a mounted secret the same way as the two files above if
you operate TURN in production.

## Production note

The bundled Postgres is dev/demo-grade. For production, point Rendly at a managed Postgres
instance (set `DATABASE_URL` / `APP_DATABASE_URL` directly, or via a secret manager) and
inject `RENDLY_JWT_PRIVATE_KEY_PEM` from your KMS/Vault — see `deploy/DEPLOY-K8s.md`.
External Secrets Operator / Vault / cloud KMS integration is documented future work (ADR-0010
§Honest deferrals), the same posture Orchestrator's O-008 and Sentinel's F-010 shipped with.
