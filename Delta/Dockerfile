# Delta ledger image (D-003) — migration + role-provisioning runner.
# The ledger is a library + Postgres schema; this image runs alembic and provisions
# the delta_app SCRAM password (the F-010 fix). It ships no long-running app server.
FROM python:3.12-slim

WORKDIR /app

# Install build deps for asyncpg/psycopg wheels are prebuilt, but keep gcc out by
# relying on binary wheels (psycopg[binary], asyncpg manylinux).
COPY pyproject.toml alembic.ini ./
COPY src ./src

RUN pip install --no-cache-dir -e . \
    && chmod +x /app/docker-entrypoint.sh 2>/dev/null || true

COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Default: run migrations + provision the app role, then exit (one-shot).
ENV RUN_MIGRATIONS=1 \
    DELTA_PROVISION_APP_ROLE=1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
