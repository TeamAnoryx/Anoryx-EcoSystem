#!/bin/sh
# Delta ledger container entrypoint (D-003).
#
# Ports the proven Sentinel F-010 fix (Anoryx-Sentinel/docker-entrypoint.sh): a
# migration that creates the app role passwordless breaks every RLS tenant
# connection on a fresh `compose up` (the migration-0006 defect). This shim runs
# alembic, then provisions the delta_app SCRAM password POST-migrate so a fresh DB
# authenticates.
#
# Security posture:
#   - No password is ever in the migration SQL or logged. The plaintext is read from
#     APP_DATABASE_URL (the same trust boundary as the process env) and only an
#     opaque SCRAM verifier is ever sent to the server in ALTER ROLE.
#
# POSIX sh (slim base has /bin/sh, not bash).
set -eu

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-delta}"
PG_DB="${POSTGRES_DB:-delta_dev}"
PG_APP_USER="${DELTA_APP_USER:-delta_app}"
PG_PW="${POSTGRES_PASSWORD:-}"

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
    echo "delta-entrypoint: WARNING: DATABASE_URL unset and no POSTGRES_PASSWORD — migrations will fail." >&2
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
# D-003 ships no app server (the ledger is a library + schema). If a command was
# supplied, exec it; otherwise the migrate/provision work is done — exit cleanly.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
echo "delta-entrypoint: migrations + role provisioning complete"
