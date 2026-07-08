# syntax=docker/dockerfile:1
#
# Delta — multi-stage container image (D-010, mirrors Anoryx-AI-Orchestrator's
# O-008 pattern, ADR-0008, itself mirroring Anoryx-Sentinel's F-010 ADR-0012 D1).
# A builder stage installs dependencies into a --user prefix; the runtime stage
# copies only the installed tree + application source and runs as a non-root
# user. Single image variant — Delta has no optional heavy extras.
#
# Delta has TWO ASGI apps (delta.ingest.app:create_app, the live enforcement
# hot path, and delta.allocation_admin.app:create_app, the internal operator
# console) plus a migration/provisioning role. This image is generic: it bakes
# no default serve command. The Helm Deployment / docker-compose service for
# each app supplies its own explicit `command` (or `args` through the
# entrypoint shim) selecting which uvicorn target to launch; the migration Job
# supplies `alembic current` (see docker-entrypoint.sh). Kubernetes probes
# don't consult the Dockerfile HEALTHCHECK at all (only Compose does) — see
# DELTA_PORT below for the Compose-only default this HEALTHCHECK targets.
#
# HARD RULES honored (mirrors Anoryx-Sentinel R4/R9 and Orchestrator ADR-0008):
#   - no secrets, tokens, or env-specific config are baked into the image. All
#     runtime config is injected via env vars / mounted secrets at start.
#   - image runs as non-root uid 1000.
#
# The base image (python:3.12-slim-bookworm) ships WITHOUT curl, so the
# HEALTHCHECK uses the bundled Python interpreter (urllib) instead of curl.

# --------------------------------------------------------------------------- #
# Stage 1 — builder                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# build-essential + libpq-dev cover any sdist that lacks a manylinux wheel
# (asyncpg / psycopg[binary] ship wheels, but the toolchain stays here so the
# build never fails on a wheel-less transitive dep).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# pyproject uses src-layout auto-discovery. Unlike the Orchestrator, uvicorn
# and fastapi are already core (non-extra) dependencies here (D-004), so a
# plain install pulls in everything the two ASGI apps need.
COPY pyproject.toml ./
COPY src ./src

RUN pip install --user --no-warn-script-location .

# --------------------------------------------------------------------------- #
# Stage 2 — runtime                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS runtime

ARG VERSION=0.2.0
LABEL org.opencontainers.image.title="Anoryx Delta" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Delta — FinOps / ERP / budget-policy ledger, enforcement ingest, and allocation-admin console." \
      org.opencontainers.image.source="https://github.com/TeamAnoryx/anoryx-ecosystem" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PATH=/home/delta/.local/bin:$PATH \
    DELTA_PORT=8000

# Non-root user (mirrors Sentinel R9 / Orchestrator ADR-0008 Fork C). nologin
# shell — the container only ever execs uvicorn or alembic via the entrypoint.
RUN groupadd --gid 1000 delta \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin delta

WORKDIR /app

# Installed Python packages (+ console scripts) from the builder's --user
# tree. --chown sets ownership AT COPY TIME — a `chown -R` afterward would
# duplicate this (large) layer and roughly double the image size.
COPY --from=builder --chown=delta:delta /root/.local /home/delta/.local

# Application source + Alembic config (migrations live under
# src/delta/persistence/migrations; alembic.ini's script_location points
# there).
COPY --chown=delta:delta src ./src
COPY --chown=delta:delta alembic.ini ./alembic.ini
# Entrypoint stays ROOT-owned (world-readable + executable) so the unprivileged
# runtime user cannot rewrite its own entrypoint.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

USER 1000

# Both possible serve targets (delta.ingest.app / delta.allocation_admin.app)
# are documented, not baked in — the caller's `command` picks the port.
EXPOSE 8000 8001

# Liveness/readiness probe against whichever port DELTA_PORT resolves to
# (default 8000, the ingest app's conventional port). curl is absent from the
# slim base image, so the interpreter that is already present is used
# instead. Kubernetes ignores this (its own probes target /health directly
# per-Deployment); this only matters for `docker run` / Compose.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen(f'http://localhost:{os.environ.get(\"DELTA_PORT\",\"8000\")}/health', timeout=3).status == 200 else 1)" || exit 1

# The entrypoint assembles DATABASE_URL / APP_DATABASE_URL / DELTA_INGEST_HMAC_
# SECRET / ORCH_SERVICE_TOKEN / DELTA_ADMIN_TOKEN from mounted secrets
# (file-based, compose) or the environment (Kubernetes Secret), then execs
# whatever command it was given (uvicorn for a serve target, alembic for the
# migration Job).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
