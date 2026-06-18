# syntax=docker/dockerfile:1
#
# Anoryx Sentinel — multi-stage container image (F-010, ADR-0012 D1).
#
# Stage 1 (builder): install Python dependencies into a --user prefix with the
#   build toolchain available, then discard the toolchain by not carrying it
#   into the runtime stage.
# Stage 2 (runtime): copy only the installed packages + application source, run
#   as a non-root user (uid/gid 1000), read-only-root-filesystem friendly.
#
# HARD RULES honored:
#   R4 — no secrets, API keys, signing keys, or env-specific config are baked.
#        All runtime config is injected via env vars / mounted secrets at start.
#   R9 — image runs as non-root uid 1000.
#
# The base image (python:3.12-slim-bookworm) ships WITHOUT curl, so the
# HEALTHCHECK uses the bundled Python interpreter (urllib) instead of curl —
# this avoids installing an extra package purely for the health probe.

# --------------------------------------------------------------------------- #
# Stage 1 — builder                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# build-essential + libpq-dev cover any sdist that lacks a manylinux wheel
# (asyncpg / psycopg / cryptography / argon2-cffi ship wheels, but we keep the
# toolchain here so the build never fails on a wheel-less transitive dep).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy metadata + source. pyproject uses src-layout auto-discovery (the same
# mechanism CI's `pip install -e .` relies on), so installing "." pulls in the
# pinned dependency set and the Sentinel packages.
COPY pyproject.toml ./
COPY src ./src

# Install into the per-user prefix (/root/.local) so the runtime stage can copy
# a single self-contained tree (packages + console scripts: uvicorn, alembic).
RUN pip install --user --no-warn-script-location .

# --------------------------------------------------------------------------- #
# Stage 2 — runtime                                                           #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS runtime

# OCI image-spec labels (R: OCI compliance). VERSION is injected at build time.
ARG VERSION=0.10.0
LABEL org.opencontainers.image.title="Anoryx Sentinel" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Zero-trust AI gateway — OpenAI-compatible surface." \
      org.opencontainers.image.source="https://github.com/TeamAnoryx/anoryx-sentinel" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PATH=/home/sentinel/.local/bin:$PATH \
    SENTINEL_WORKERS=1 \
    SENTINEL_PORT=8000

# Non-root user (R9). nologin shell — the container only ever execs uvicorn.
RUN groupadd --gid 1000 sentinel \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin sentinel

WORKDIR /app

# Installed Python packages (+ console scripts) from the builder's --user tree.
COPY --from=builder /root/.local /home/sentinel/.local

# Application source + Alembic config (migrations live under src/persistence/
# migrations; alembic.ini's script_location points there, prepend_sys_path=.).
COPY src ./src
COPY alembic.ini ./alembic.ini
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chown -R sentinel:sentinel /app /home/sentinel/.local

USER 1000

EXPOSE 8000

# Liveness probe (R5): /livez performs NO dependency I/O. curl is absent from
# the slim base image, so we probe with the interpreter that is already present.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/livez', timeout=3).status == 200 else 1)" || exit 1

# The entrypoint assembles DATABASE_URL / APP_DATABASE_URL / REDIS_URL from
# mounted Docker secrets (file-based, β) when present, then launches uvicorn.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
