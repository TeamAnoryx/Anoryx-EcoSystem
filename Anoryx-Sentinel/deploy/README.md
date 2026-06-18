# Sentinel Local Dev Stack — Bring-up Guide

This directory contains deployment documentation for the Anoryx Sentinel service.
The `docker-compose.yml` lives at the Sentinel root (`../docker-compose.yml`).

---

## Prerequisites

- Docker Engine 24+ with Compose V2 (`docker compose` not `docker-compose`)
- Host ports 5432 and 6379 available (or only 6379 if postgres runs standalone)

---

## Bring-up Options

### Option A — Full stack (both services)

Use this on a clean machine or in CI where neither postgres nor redis is running.

```sh
docker compose up -d
```

Waits for healthchecks: postgres (`pg_isready`) and redis (`redis-cli PING`).

### Option B — Redis only (postgres already running standalone)

The sentinel-postgres container may already be running via a plain `docker run`
on host port 5432. Starting the compose postgres service in that state will fail
with a port-binding conflict. Start redis only:

```sh
docker compose up -d redis
```

Verify redis is healthy:

```sh
docker exec sentinel-redis redis-cli PING
# Expected: PONG
```

---

## Environment Variables

The following variables govern the compose services. Supply them via a `.env`
file at the Sentinel root (gitignored) or via shell exports before running compose.

| Variable          | Default       | Notes                                      |
|-------------------|---------------|--------------------------------------------|
| `POSTGRES_USER`   | `sentinel`    | Postgres superuser for local dev           |
| `POSTGRES_PASSWORD` | `sentinel`  | Local-dev only. Vault/KMS in production    |
| `POSTGRES_DB`     | `sentinel_dev`| Database name                              |

### REDIS_URL

The application reads `REDIS_URL` from the environment (or `.env` file).

```
REDIS_URL=redis://localhost:6379/0
```

Production deployments MUST inject `REDIS_URL` with a password from Vault or
cloud KMS. Example:

```
REDIS_URL=redis://:mysecretpassword@redis.internal:6379/0
```

Never add `requirepass` to the compose file. Never commit a password to git.

---

## Redis Configuration Rationale

The redis service is started with:

```
redis-server --save 60 1 --loglevel warning --maxmemory 256mb --maxmemory-policy allkeys-lru
```

**`--save 60 1`** — RDB snapshot every 60 seconds if at least 1 key changed.
Provides crash recovery for the rate-limit ZSET windows without requiring AOF.
Acceptable data loss window: up to 60 seconds of rate-limit counters (safe —
the fallback path re-initialises on restart).

**`--maxmemory 256mb`** — Hard ceiling. Sentinel rate-limit ZSETs are small
(~200 bytes per tenant per minute). 256 MiB is well above the expected working
set for thousands of tenants.

**`--maxmemory-policy allkeys-lru`** — When the ceiling is reached Redis evicts
the least-recently-used key. Rate-limit ZSETs for inactive tenants are evicted
first. Active tenants continue normally. This is intentionally permissive for
rate limiting: an evicted key means the next admission starts a fresh window
(slightly under-counted), which is the correct trade-off versus OOM or
fail-closed behaviour.

---

## Prometheus /metrics Endpoint

The gateway exposes `GET /metrics` (Prometheus text format, unauthenticated) on
the same port as the API. This is intentional for Prometheus scrape simplicity.

**Production hardening required:** The `/metrics` path MUST be firewalled at the
load-balancer or ingress layer so that it is not reachable from the public
internet. Failure to do so would expose internal cardinality data (tenant IDs in
per-tenant metrics, queue depths, error rates) to unauthenticated callers.

Recommended approach: restrict `/metrics` to the internal scrape CIDR only, or
place it on a separate internal port behind a network policy.

---

## Teardown

Stop and remove containers (volumes preserved):

```sh
docker compose down
```

Stop, remove containers, and delete volumes (destroys all local data):

```sh
docker compose down -v
```

---

## Service Summary

| Service    | Container          | Host Port | Image             |
|------------|--------------------|-----------|-------------------|
| `redis`    | `sentinel-redis`   | 6379      | `redis:7-alpine`  |
| `postgres` | `sentinel-postgres`| 5432      | `postgres:16-alpine` |
