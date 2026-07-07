#!/bin/sh
# Anoryx-AI-Orchestrator container entrypoint (O-008, ADR-0008).
#
# Bridges file-based Docker secrets to the env vars the Orchestrator's config
# module expects. Mirrors Anoryx-Sentinel's F-010 entrypoint (ADR-0012 D2/D3).
#
# Security posture:
#   - Passwords/tokens live ONLY in mounted secret files, never in the compose
#     file, the `environment:` block, or `docker inspect` Config.Env.
#   - URLs/secrets are assembled into the live process environment here, at
#     start — never logged.
#
# Escape hatch (external managed services / Kubernetes Secret): if a var is
# already present in the environment, it is used verbatim and NO assembly
# occurs for that var.
#
# POSIX sh (the slim base image has /bin/sh, not bash).
set -eu

_read_secret() {
    if [ -f "$1" ]; then
        tr -d '\n\r' < "$1"
    fi
}

# --- Postgres (privileged ORCH_DATABASE_URL + app-role ORCH_APP_DATABASE_URL) #
PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-orchestrator}"
PG_DB="${POSTGRES_DB:-orchestrator_dev}"
PG_APP_USER="${ORCH_APP_USER:-orchestrator_app}"
# Prefer a mounted file secret (Compose); fall back to POSTGRES_PASSWORD env
# (Kubernetes injects it via secretKeyRef — kept out of the pod spec).
PG_PW="$(_read_secret /run/secrets/postgres_password)"
[ -z "$PG_PW" ] && PG_PW="${POSTGRES_PASSWORD:-}"

if [ -z "${ORCH_DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Privileged (owner / BYPASSRLS) role — migrations, registry infra, chain ops.
    export ORCH_DATABASE_URL="postgresql://${PG_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi
if [ -z "${ORCH_APP_DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Application (orchestrator_app / NOBYPASSRLS) role — tenant request traffic.
    # Bundled stack shares the password file across both roles; RLS is enforced
    # by the role privilege (NOBYPASSRLS), not by the password.
    export ORCH_APP_DATABASE_URL="postgresql://${PG_APP_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi

if [ -z "${ORCH_DATABASE_URL:-}" ]; then
    echo "orchestrator-entrypoint: WARNING: ORCH_DATABASE_URL is unset and no postgres password was found (file /run/secrets/postgres_password or POSTGRES_PASSWORD env) — the orchestrator will not reach Postgres." >&2
fi

# --- Ingest HMAC secret (most sensitive value; prefer a file mount) --------- #
HMAC_SECRET="$(_read_secret /run/secrets/orch_ingest_hmac_secret)"
if [ -z "${ORCH_INGEST_HMAC_SECRET:-}" ] && [ -n "$HMAC_SECRET" ]; then
    export ORCH_INGEST_HMAC_SECRET="$HMAC_SECRET"
fi

# --- Admin token (operator bearer for registry CRUD + admin API) ----------- #
ADMIN_TOKEN="$(_read_secret /run/secrets/orch_admin_token)"
if [ -z "${ORCH_ADMIN_TOKEN:-}" ] && [ -n "$ADMIN_TOKEN" ]; then
    export ORCH_ADMIN_TOKEN="$ADMIN_TOKEN"
fi

# --- Optional one-shot schema migration ------------------------------------- #
# Compose convenience: run migrations in-line before the app starts. In
# Kubernetes a dedicated pre-upgrade Job owns this instead (mirrors ADR-0012
# §4), so RUN_MIGRATIONS is left unset (0) there to avoid every replica racing.
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "orchestrator-entrypoint: running alembic upgrade head"
    alembic upgrade head
fi

# --- Provision orchestrator_app role password ------------------------------- #
# After alembic runs, migration 0001 ensures orchestrator_app EXISTS but with NO
# LOGIN password ("provisioned out-of-band"). Without a password, every
# ORCH_APP_DATABASE_URL (SCRAM-SHA-256) connection fails. When
# ORCH_PROVISION_APP_ROLE=1 and we have both ORCH_DATABASE_URL and
# ORCH_APP_DATABASE_URL, set the password here via the privileged role.
# Idempotent (ALTER ROLE ... WITH PASSWORD is always safe to re-run). The
# plaintext password is NEVER logged; only a one-line status is emitted.
_NORMALIZE_FLAG() { case "$1" in 1|true|yes|on) echo 1;; *) echo 0;; esac; }
if [ "$(_NORMALIZE_FLAG "${ORCH_PROVISION_APP_ROLE:-0}")" = "1" ] \
   && [ -n "${ORCH_DATABASE_URL:-}" ] \
   && [ -n "${ORCH_APP_DATABASE_URL:-}" ]; then
    echo "orchestrator-entrypoint: provisioning orchestrator_app role password"
    python - <<'PYEOF'
import asyncio, base64, hashlib, hmac, os, re, sys

async def _provision():
    app_url = os.environ.get("ORCH_APP_DATABASE_URL", "")
    db_url  = os.environ.get("ORCH_DATABASE_URL", "")
    m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url)
    if not m:
        print("orchestrator-entrypoint: WARN: could not extract password from ORCH_APP_DATABASE_URL; skipping provision", file=sys.stderr)
        return
    app_pw = m.group(1)
    dm = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_url)
    if not dm:
        print("orchestrator-entrypoint: WARN: could not parse ORCH_DATABASE_URL; skipping provision", file=sys.stderr)
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
    await conn.execute(f"ALTER ROLE orchestrator_app WITH LOGIN PASSWORD '{verifier}'")
    await conn.close()
    print("orchestrator-entrypoint: provisioned orchestrator_app role password")

asyncio.run(_provision())
PYEOF
fi

# --- Launch ----------------------------------------------------------------- #
# If a command was supplied (e.g. `docker run orchestrator sh` for debugging),
# exec it. Otherwise launch uvicorn with the configured worker count.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec uvicorn orchestrator.app:create_app --factory \
    --host 0.0.0.0 --port "${ORCH_PORT:-8081}" --workers "${ORCH_WORKERS:-1}"
