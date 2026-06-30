#!/bin/sh
# Rendly identity persistence container entrypoint (R-004).
#
# Ports the proven Sentinel F-010 fix (as Delta D-003 did): a migration that creates the
# app role passwordless breaks every RLS tenant connection on a fresh `compose up`. This
# shim runs alembic, then provisions the rendly_app SCRAM password POST-migrate so a fresh
# DB authenticates. Rendly is sync, so the inline provisioning uses psycopg (not asyncpg).
#
# Security posture:
#   - No password is ever in the migration SQL or logged. The plaintext is read from
#     APP_DATABASE_URL (the same trust boundary as the process env) and only an opaque
#     SCRAM-SHA-256 verifier is ever sent to the server in ALTER ROLE.
#
# POSIX sh (slim base has /bin/sh, not bash).
set -eu

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-rendly}"
PG_DB="${POSTGRES_DB:-rendly_dev}"
PG_APP_USER="${RENDLY_APP_USER:-rendly_app}"
PG_PW="${POSTGRES_PASSWORD:-}"

# Assemble the two role URLs if not already supplied (k8s/external services may set them
# verbatim, in which case no assembly happens for that URL).
if [ -z "${DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # Privileged owner role (BYPASSRLS) — migrations + admin.
    export DATABASE_URL="postgresql://${PG_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi
if [ -z "${APP_DATABASE_URL:-}" ] && [ -n "$PG_PW" ]; then
    # rendly_app role (NOBYPASSRLS) — tenant traffic. Bundled stack shares the password
    # across both roles; RLS is enforced by the role privilege, not the password.
    export APP_DATABASE_URL="postgresql://${PG_APP_USER}:${PG_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "rendly-entrypoint: WARNING: DATABASE_URL unset and no POSTGRES_PASSWORD — migrations will fail." >&2
fi

# --- Migrations (compose convenience; k8s uses a dedicated Job) -------------- #
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "rendly-entrypoint: running alembic upgrade head"
    alembic upgrade head
fi

# --- Provision rendly_app SCRAM password POST-migrate (the F-010 fix) -------- #
# Migration 0001 creates rendly_app with NO password. Without a password every
# SCRAM-SHA-256 APP_DATABASE_URL connection fails -> all tenant traffic is dead.
# Provision it here from the privileged role. Idempotent; plaintext never logged.
# Case-insensitive: "True"/"TRUE"/"On" (common in generated env files) all count.
_NORMALIZE_FLAG() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|on) echo 1;; *) echo 0;; esac; }
if [ "$(_NORMALIZE_FLAG "${RENDLY_PROVISION_APP_ROLE:-0}")" = "1" ] \
   && [ -n "${DATABASE_URL:-}" ] \
   && [ -n "${APP_DATABASE_URL:-}" ]; then
    echo "rendly-entrypoint: provisioning rendly_app role password"
    python - <<'PYEOF'
import base64, hashlib, hmac, os, re, sys

import psycopg
from psycopg import sql

app_url = os.environ.get("APP_DATABASE_URL", "")
db_url  = os.environ.get("DATABASE_URL", "")
m = re.match(r"postgresql(?:\+\w+)?://[^:]+:([^@]+)@", app_url)
if not m:
    print("rendly-entrypoint: WARN: no password in APP_DATABASE_URL; skipping provision", file=sys.stderr)
    sys.exit(0)
app_pw = m.group(1)

# psycopg connects with the plain (non-driver) URL; strip any SQLAlchemy +driver suffix.
conn_url = re.sub(r"^postgresql\+\w+://", "postgresql://", db_url)

# SCRAM-SHA-256 verifier computed CLIENT-SIDE; the plaintext is never a SQL literal.
salt   = os.urandom(16)
iters  = 4096
salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
ck     = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
sk     = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
verifier = (f"SCRAM-SHA-256${iters}"
            f":{base64.b64encode(salt).decode()}"
            f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
            f":{base64.b64encode(sk).decode()}")

with psycopg.connect(conn_url, autocommit=True) as conn:
    # ALTER ROLE ... PASSWORD cannot take a bound parameter (it is DDL), so the verifier is
    # composed as a safely-quoted SQL literal. Only the opaque verifier is sent — never the
    # plaintext, which is never a SQL literal and is never logged.
    conn.execute(
        sql.SQL("ALTER ROLE rendly_app WITH LOGIN PASSWORD {}").format(sql.Literal(verifier))
    )
print("rendly-entrypoint: provisioned rendly_app role password")
PYEOF
fi

# --- Launch ----------------------------------------------------------------- #
# R-004 ships no app server (identity persistence is a library + schema). If a command was
# supplied, exec it; otherwise the migrate/provision work is done — exit cleanly.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
echo "rendly-entrypoint: migrations + role provisioning complete"
