#!/bin/sh
# Delta container entrypoint (D-003, extended D-010).
#
# Ports the proven Sentinel F-010 fix (Anoryx-Sentinel/docker-entrypoint.sh): a
# migration that creates the app role passwordless breaks every RLS tenant
# connection on a fresh `compose up` (the migration-0006 defect). This shim runs
# alembic, then provisions the delta_app SCRAM password POST-migrate so a fresh DB
# authenticates.
#
# D-010 extends this SAME shim (mirrors the Orchestrator's O-008 entrypoint,
# ADR-0008 Fork D) to bridge file-based Docker secrets under /run/secrets/* to
# the env vars Delta's config modules expect, falling back to the environment
# when no file is mounted (Kubernetes' secretKeyRef/envFrom case). It then
# execs whatever command it was given — either app's uvicorn invocation (the
# Helm Deployment / compose service supplies the target) or `alembic current`
# (the migration Job).
#
# Security posture:
#   - No password is ever in the migration SQL or logged. The plaintext is read from
#     APP_DATABASE_URL (the same trust boundary as the process env) and only an
#     opaque SCRAM verifier is ever sent to the server in ALTER ROLE.
#   - Passwords/tokens live ONLY in mounted secret files or the environment,
#     never in the compose file's `environment:` block or `docker inspect`
#     Config.Env for a value assembled here.
#
# POSIX sh (slim base has /bin/sh, not bash).
set -eu

_read_secret() {
    if [ -f "$1" ]; then
        tr -d '\n\r' < "$1"
    fi
}

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-delta}"
PG_DB="${POSTGRES_DB:-delta_dev}"
PG_APP_USER="${DELTA_APP_USER:-delta_app}"
# Prefer a mounted file secret (Compose); fall back to POSTGRES_PASSWORD env
# (Kubernetes injects it via secretKeyRef — kept out of the pod spec).
PG_PW="$(_read_secret /run/secrets/postgres_password)"
[ -z "$PG_PW" ] && PG_PW="${POSTGRES_PASSWORD:-}"

# Assemble the two role URLs if not already supplied (k8s/external services may set
# them verbatim, in which case no assembly happens for that URL).
if [ -z "${DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Privileged owner role (BYPASSRLS) — migrations + admin.
    export DATABASE_URL="postgresql://${PG_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi
if [ -z "${APP_DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # delta_app role (NOBYPASSRLS) — tenant traffic. Bundled stack shares the
    # password across both roles; RLS is enforced by the role privilege, not the pw.
    export APP_DATABASE_URL="postgresql://${PG_APP_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "delta-entrypoint: WARNING: DATABASE_URL unset and no postgres password was found (file /run/secrets/postgres_password or POSTGRES_PASSWORD env) — migrations will fail." >&2
fi

# --- Ingest HMAC secret (POST /v1/ingest/usage signature verification) ------ #
INGEST_HMAC="$(_read_secret /run/secrets/delta_ingest_hmac_secret)"
if [ -z "${DELTA_INGEST_HMAC_SECRET:-}" ] && [ -n "$INGEST_HMAC" ]; then
    export DELTA_INGEST_HMAC_SECRET="$INGEST_HMAC"
fi

# --- Outbound Bearer token to the Orchestrator's O-004 distribution seam ---- #
# Empty is a VALID value (the budget-engine/kill-switch configs treat "" as
# "disabled, inert no-op" when their own *_ENABLED flag is off) — this shim
# only bridges the file if one is mounted; it never fabricates a value.
ORCH_TOKEN="$(_read_secret /run/secrets/orch_service_token)"
if [ -z "${ORCH_SERVICE_TOKEN:-}" ] && [ -n "$ORCH_TOKEN" ]; then
    export ORCH_SERVICE_TOKEN="$ORCH_TOKEN"
fi

# --- Admin break-glass bearer (delta.allocation_admin app; fail-loud) ------- #
ADMIN_TOKEN="$(_read_secret /run/secrets/delta_admin_token)"
if [ -z "${DELTA_ADMIN_TOKEN:-}" ] && [ -n "$ADMIN_TOKEN" ]; then
    export DELTA_ADMIN_TOKEN="$ADMIN_TOKEN"
fi

# --- Migrations (compose convenience; k8s uses a dedicated Job) -------------- #
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "delta-entrypoint: running alembic upgrade head"
    alembic upgrade head
fi

# --- Provision delta_app SCRAM password POST-migrate (the F-010 fix) --------- #
# Migration 0001 creates delta_app with NO password. Without a password every
# SCRAM-SHA-256 APP_DATABASE_URL connection fails -> all tenant traffic is dead.
# Provision it here from the privileged role. Idempotent; plaintext never logged.
# Case-insensitive: "True"/"TRUE"/"On" (common in generated env files) all count.
_NORMALIZE_FLAG() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|on) echo 1;; *) echo 0;; esac; }
if [ "$(_NORMALIZE_FLAG "${DELTA_PROVISION_APP_ROLE:-0}")" = "1" ] \
   && [ -n "${DATABASE_URL:-}" ] \
   && [ -n "${APP_DATABASE_URL:-}" ]; then
    echo "delta-entrypoint: provisioning delta_app role password"
    python - <<'PYEOF'
import asyncio, base64, hashlib, hmac, os, re, sys

async def _provision():
    app_url = os.environ.get("APP_DATABASE_URL", "")
    db_url  = os.environ.get("DATABASE_URL", "")
    m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url)
    if not m:
        print("delta-entrypoint: WARN: no password in APP_DATABASE_URL; skipping provision", file=sys.stderr)
        return
    app_pw = m.group(1)
    dm = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_url)
    if not dm:
        print("delta-entrypoint: WARN: could not parse DATABASE_URL; skipping provision", file=sys.stderr)
        return
    import asyncpg
    conn = await asyncpg.connect(user=dm.group(1), password=dm.group(2),
                                 host=dm.group(3), port=int(dm.group(4)), database=dm.group(5))
    # SCRAM-SHA-256 verifier computed client-side; the plaintext is never a SQL literal.
    salt   = os.urandom(16)
    iters  = 4096
    salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
    ck     = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    sk     = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    verifier = (f"SCRAM-SHA-256${iters}"
                f":{base64.b64encode(salt).decode()}"
                f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
                f":{base64.b64encode(sk).decode()}")
    await conn.execute(f"ALTER ROLE delta_app WITH LOGIN PASSWORD '{verifier}'")
    await conn.close()
    print("delta-entrypoint: provisioned delta_app role password")

asyncio.run(_provision())
PYEOF
fi

# --- Launch ----------------------------------------------------------------- #
# This image has no baked-in default command (D-010: two ASGI apps share one
# image — delta.ingest.app:create_app and delta.allocation_admin.app:
# create_app — plus the migration/`alembic current` use). If a command was
# supplied (uvicorn for a serve target, alembic for the migration Job, sh for
# debugging), exec it; otherwise the migrate/provision work above is done —
# exit cleanly (the original D-003 migration-only-image behavior).
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
echo "delta-entrypoint: migrations + role provisioning complete"
