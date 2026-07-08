# syntax=docker/dockerfile:1
#
# Anoryx-AI-Orchestrator — multi-stage container image (O-008, ADR-0008).
# Mirrors Anoryx-Sentinel's F-010 pattern (ADR-0012 D1): a builder stage installs
# dependencies into a --user prefix, the runtime stage copies only the installed
# tree + application source and runs as a non-root user.
#
# Unlike Sentinel there is no slim/full image-variant split: the Orchestrator has
# no optional heavy extras (no boto3/Presidio/spaCy) — a single image variant covers
# every deployment.
#
# HARD RULES honored (mirrors Anoryx-Sentinel R4/R9):
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
# (asyncpg / psycopg ship wheels, but the toolchain stays here so the build never
# fails on a wheel-less transitive dep).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# pyproject uses src-layout auto-discovery, so installing ".[server]" pulls in the
# pinned runtime dependency set plus uvicorn (kept out of core — pyproject.toml
# comment: "not needed by CI or tests" — the image is the one consumer that needs it).
COPY pyproject.toml ./
COPY src ./src

RUN pip install --user --no-warn-script-location ".[server]"

# --------------------------------------------------------------------------- #
# Stage 2 — runtime                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS runtime

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="Anoryx AI Orchestrator" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Central AI orchestration layer — event ingest, policy distribution, multi-Sentinel coordination." \
      org.opencontainers.image.source="https://github.com/TeamAnoryx/anoryx-ecosystem" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PATH=/home/orchestrator/.local/bin:$PATH \
    ORCH_WORKERS=1 \
    ORCH_PORT=8081

# Non-root user (mirrors Sentinel R9). nologin shell — the container only ever
# execs uvicorn.
RUN groupadd --gid 1000 orchestrator \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin orchestrator

WORKDIR /app

# Installed Python packages (+ console scripts) from the builder's --user tree.
# --chown sets ownership AT COPY TIME — a `chown -R` afterward would duplicate
# this (large) layer and roughly double the image size.
COPY --from=builder --chown=orchestrator:orchestrator /root/.local /home/orchestrator/.local

# Application source + Alembic config (migrations live under
# src/orchestrator/persistence/migrations; alembic.ini's script_location points
# there, prepend_sys_path=src).
COPY --chown=orchestrator:orchestrator src ./src
COPY --chown=orchestrator:orchestrator alembic.ini ./alembic.ini
# Entrypoint stays ROOT-owned (world-readable + executable) so the unprivileged
# runtime user cannot rewrite its own entrypoint.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

USER 1000

EXPOSE 8081

# Liveness/readiness probe. curl is absent from the slim base image, so we probe
# with the interpreter that is already present. The Orchestrator exposes a single
# /health endpoint today (no DB-gated /readyz split yet — a documented deferral,
# ADR-0008 §Honest deferrals).
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8081/health', timeout=3).status == 200 else 1)" || exit 1

# The entrypoint assembles ORCH_DATABASE_URL / ORCH_APP_DATABASE_URL / the ingest
# HMAC secret / the admin token from mounted secrets (file-based, compose) or the
# environment (Kubernetes Secret), then launches uvicorn.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
