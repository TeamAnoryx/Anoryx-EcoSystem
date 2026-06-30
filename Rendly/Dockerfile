# Rendly identity-persistence image (R-004) — migration + role-provisioning runner.
# Identity persistence is a library + Postgres schema; this image runs alembic and provisions
# the rendly_app SCRAM password (the F-010 fix). It ships no long-running app server.
FROM python:3.12-slim

WORKDIR /app

# psycopg[binary] ships a prebuilt wheel, so no compiler is needed.
COPY pyproject.toml alembic.ini ./
COPY src ./src

RUN pip install --no-cache-dir -e .

COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Default: run migrations + provision the app role, then exit (one-shot).
ENV RUN_MIGRATIONS=1 \
    RENDLY_PROVISION_APP_ROLE=1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
