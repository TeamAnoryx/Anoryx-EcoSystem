#!/bin/sh
# Anoryx Sentinel container entrypoint (F-010, ADR-0012 D2/D3).
#
# Bridges file-based Docker secrets to the env vars pydantic-settings expects.
# pydantic-settings has no *_FILE convention, so this shim reads the mounted
# secret files at /run/secrets/* and assembles the connection URLs at startup.
#
# Security posture (ADR-0012 §3):
#   - Passwords live ONLY in mounted secret files, never in the compose file,
#     the `environment:` block, or `docker inspect` Config.Env (threat vector 8).
#   - URLs are assembled into the live process environment here, at start — that
#     is the same trust boundary as the mounted file (visible only inside the
#     container). They are never logged.
#
# Escape hatch (external managed services): if a URL is already present in the
# environment (e.g. set from a k8s Secret or a full external URL), it is used
# verbatim and NO assembly occurs for that URL.
#
# This script is POSIX sh (the slim base image has /bin/sh, not bash).
set -eu

# Read a secret file, stripping trailing newlines. Echoes empty if absent.
_read_secret() {
    if [ -f "$1" ]; then
        tr -d '\n\r' < "$1"
    fi
}

# --- Postgres (privileged DATABASE_URL + app-role APP_DATABASE_URL) --------- #
PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-sentinel}"
PG_DB="${POSTGRES_DB:-sentinel_dev}"
PG_APP_USER="${SENTINEL_APP_USER:-sentinel_app}"
# Prefer a mounted file secret (Compose); fall back to POSTGRES_PASSWORD env
# (Kubernetes injects it via secretKeyRef — kept out of the pod spec, ADR-0012 §3).
PG_PW="$(_read_secret /run/secrets/postgres_password)"
[ -z "$PG_PW" ] && PG_PW="${POSTGRES_PASSWORD:-}"

if [ -z "${DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Privileged (owner / BYPASSRLS) role — migrations, chain ops, /readyz check.
    export DATABASE_URL="postgresql://${PG_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi
if [ -z "${APP_DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Application (sentinel_app / NOBYPASSRLS) role — tenant request traffic.
    # Bundled stack shares the password file across both roles; RLS is enforced
    # by the role privilege (NOBYPASSRLS), not by the password (ADR-0012 §3).
    export APP_DATABASE_URL="postgresql://${PG_APP_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi

# Surface a missing/unreadable Postgres credential early instead of failing with
# an opaque connection error 30 s later (code-review LOW).
if [ -z "${DATABASE_URL:-}" ]; then
    echo "sentinel-entrypoint: WARNING: DATABASE_URL is unset and no postgres password was found (file /run/secrets/postgres_password or POSTGRES_PASSWORD env) — the gateway will not reach Postgres." >&2
fi

# --- Redis ------------------------------------------------------------------ #
# The bundled Redis (F-009 compose) runs WITHOUT requirepass (R3 — that service
# is frozen). So when no redis password secret is provided we build a
# password-less URL. The redis_password secret applies when REDIS points at an
# external authenticated instance (documented in deploy/secrets/README.md).
REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PW="$(_read_secret /run/secrets/redis_password)"
[ -z "$REDIS_PW" ] && REDIS_PW="${REDIS_PASSWORD:-}"
if [ -z "${REDIS_URL:-}" ]; then
    if [ -n "$REDIS_PW" ]; then
        export REDIS_URL="redis://:${REDIS_PW}@${REDIS_HOST}:${REDIS_PORT}/0"
    else
        export REDIS_URL="redis://${REDIS_HOST}:${REDIS_PORT}/0"
    fi
fi

# --- Signing key secret (most sensitive value; prefer a file mount) --------- #
KEY_SECRET="$(_read_secret /run/secrets/sentinel_key_secret)"
if [ -z "${SENTINEL_KEY_SECRET:-}" ] && [ -n "$KEY_SECRET" ]; then
    export SENTINEL_KEY_SECRET="$KEY_SECRET"
fi

# --- Admin token (break-glass for /admin/* — F-012a) ----------------------- #
# Read admin_token secret file if present. Export as SENTINEL_ADMIN_TOKEN so
# the admin auth middleware can gate /admin/* requests (never logged).
ADMIN_TOKEN="$(_read_secret /run/secrets/admin_token)"
if [ -z "${SENTINEL_ADMIN_TOKEN:-}" ] && [ -n "$ADMIN_TOKEN" ]; then
    export SENTINEL_ADMIN_TOKEN="$ADMIN_TOKEN"
fi

# --- Optional one-shot schema migration ------------------------------------- #
# Compose convenience: run migrations in-line before the app starts. In
# Kubernetes a dedicated pre-upgrade Job owns this instead (ADR-0012 §4), so
# RUN_MIGRATIONS is left unset (0) there to avoid every replica racing.
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "sentinel-entrypoint: running alembic upgrade head"
    alembic upgrade head
fi

# --- Provision sentinel_app role password (gap #1 — R3 wiring) ------------- #
# After alembic runs, migration 0006 ensures sentinel_app EXISTS but with NO
# LOGIN password ("provisioned out-of-band"). Without a password, every
# APP_DATABASE_URL (SCRAM-SHA-256) connection fails → all tenant /v1 traffic
# is dead. When SENTINEL_PROVISION_APP_ROLE=1 and we have both DATABASE_URL
# and a postgres password, set the password here via the privileged role.
# Idempotent (ALTER ROLE ... WITH PASSWORD is always safe to re-run).
# The plaintext password is NEVER logged; only a one-line status is emitted.
_NORMALIZE_FLAG() { case "$1" in 1|true|yes|on) echo 1;; *) echo 0;; esac; }
if [ "$(_NORMALIZE_FLAG "${SENTINEL_PROVISION_APP_ROLE:-0}")" = "1" ] \
   && [ -n "${DATABASE_URL:-}" ] \
   && [ -n "${APP_DATABASE_URL:-}" ]; then
    echo "sentinel-entrypoint: provisioning sentinel_app role password"
    python - <<'PYEOF'
import asyncio, base64, hashlib, hmac, os, re, sys

async def _provision():
    app_url = os.environ.get("APP_DATABASE_URL", "")
    db_url  = os.environ.get("DATABASE_URL", "")
    m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url)
    if not m:
        print("sentinel-entrypoint: WARN: could not extract password from APP_DATABASE_URL; skipping provision", file=sys.stderr)
        return
    app_pw = m.group(1)
    dm = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_url)
    if not dm:
        print("sentinel-entrypoint: WARN: could not parse DATABASE_URL; skipping provision", file=sys.stderr)
        return
    import asyncpg
    conn = await asyncpg.connect(user=dm.group(1), password=dm.group(2),
                                  host=dm.group(3), port=int(dm.group(4)),
                                  database=dm.group(5))
    # Compute SCRAM-SHA-256 verifier client-side; the plaintext is never a SQL literal.
    salt   = os.urandom(16)
    iters  = 4096
    salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
    ck     = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    sk     = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    verifier = (f"SCRAM-SHA-256${iters}"
                f":{base64.b64encode(salt).decode()}"
                f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
                f":{base64.b64encode(sk).decode()}")
    await conn.execute(f"ALTER ROLE sentinel_app WITH LOGIN PASSWORD '{verifier}'")
    await conn.close()
    print("sentinel-entrypoint: provisioned sentinel_app role password")

asyncio.run(_provision())
PYEOF
fi

# --- Launch ----------------------------------------------------------------- #
# If a command was supplied (e.g. `docker run sentinel sh` for debugging), exec
# it. Otherwise launch uvicorn with the configured worker count.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec uvicorn gateway.main:create_app --factory \
    --host 0.0.0.0 --port "${SENTINEL_PORT:-8000}" --workers "${SENTINEL_WORKERS:-1}"
