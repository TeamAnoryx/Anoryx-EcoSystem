# syntax=docker/dockerfile:1
#
# Rendly — multi-stage container image (R-010, ADR-0010).
# Mirrors Anoryx-AI-Orchestrator's O-008 pattern (ADR-0008 Fork C), itself mirroring
# Anoryx-Sentinel's F-010 (ADR-0012 D1): a builder stage installs dependencies into a
# --user prefix, the runtime stage copies only the installed tree + application source and
# runs as a non-root user. Single image variant (no slim/full split) — Rendly has no
# optional heavy extras.
#
# R-004 shipped this image as a one-shot migration+role-provisioning runner (no server).
# R-010 extends it: the SAME image now also serves the app (uvicorn), selected by whether a
# command is supplied to the entrypoint — see docker-entrypoint.sh.
#
# HARD RULES honored (mirrors Anoryx-Sentinel R4/R9):
#   - no secrets, tokens, or env-specific config are baked into the image. All runtime
#     config is injected via env vars / mounted secrets at start.
#   - image runs as non-root uid 1000.
#
# The base image (python:3.12-slim) ships WITHOUT curl, so the HEALTHCHECK uses the
# bundled Python interpreter (urllib) instead of curl.

# --------------------------------------------------------------------------- #
# Stage 1 — builder                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# psycopg[binary] ships a prebuilt wheel, so no compiler is strictly required, but
# build-essential+libpq-dev stay here so the build never fails on a wheel-less transitive dep.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# pyproject uses src-layout auto-discovery. ".[server]" pulls in the pinned runtime
# dependency set plus uvicorn (kept out of core deps — the image is the one consumer that
# needs it; CI/tests never install it).
COPY pyproject.toml alembic.ini ./
COPY src ./src

RUN pip install --user --no-warn-script-location ".[server]"

# --------------------------------------------------------------------------- #
# Stage 2 — runtime                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="Rendly" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Secure enterprise communication — auth, profiles, real-time chat, 1-on-1 huddles, Sentinel-safety inspection, immutable comms archiving." \
      org.opencontainers.image.source="https://github.com/TeamAnoryx/anoryx-ecosystem" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PATH=/home/rendly/.local/bin:$PATH \
    RENDLY_WORKERS=1 \
    RENDLY_PORT=8082

# Non-root user (mirrors Sentinel R9 / Orchestrator O-008). nologin shell — the container
# only ever execs alembic or uvicorn.
RUN groupadd --gid 1000 rendly \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin rendly

WORKDIR /app

# Installed Python packages (+ console scripts) from the builder's --user tree. --chown sets
# ownership AT COPY TIME — a `chown -R` afterward would duplicate this (large) layer.
COPY --from=builder --chown=rendly:rendly /root/.local /home/rendly/.local

# Application source + Alembic config (migrations live under
# src/rendly/persistence/migrations; alembic.ini's script_location points there,
# prepend_sys_path=src).
COPY --chown=rendly:rendly src ./src
COPY --chown=rendly:rendly alembic.ini ./alembic.ini
# Entrypoint stays ROOT-owned (world-readable + executable) so the unprivileged runtime
# user cannot rewrite its own entrypoint.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

USER 1000

EXPOSE 8082

# Liveness/readiness/startup probe. curl is absent from the slim base image, so we probe
# with the interpreter that is already present. Rendly exposes a single /health endpoint
# today (no DB-gated /readyz split yet — a documented deferral, ADR-0010 §Honest deferrals,
# mirroring Anoryx-AI-Orchestrator's own ADR-0008 Fork G).
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8082/health', timeout=3).status == 200 else 1)" || exit 1

# The entrypoint assembles DATABASE_URL / APP_DATABASE_URL / RENDLY_JWT_PRIVATE_KEY_PEM from
# mounted secrets (file-based, Compose) or the environment (Kubernetes Secret), optionally
# runs migrations + role provisioning, then launches uvicorn (or execs a supplied command —
# e.g. the migrate-only Job/Compose service continues to work unchanged).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
