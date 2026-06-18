"""Dockerfile threat-model tests (F-010, ADR-0012 §9 vectors 5, 6, 7).

These assert the image's security guarantees from the Dockerfile + .dockerignore
text — deterministic and CI-safe (no Docker daemon required). The empirical
build+inspect proof is run at STEP 11 (and was verified manually at STEP 2:
USER=1000, env carries no secrets, container healthy < 10 s).

  5  test_dockerfile_runs_as_non_root        — USER directive sets uid 1000
  6  test_dockerfile_no_secrets_baked        — no secret COPY/ENV; .dockerignore excludes
  7  test_dockerfile_health_check_targets_livez — HEALTHCHECK probes /livez (no DB)
"""

from __future__ import annotations

from pathlib import Path

# tests/deploy/test_dockerfile.py → Anoryx-Sentinel/
_SENTINEL_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _SENTINEL_ROOT / "Dockerfile"
_DOCKERIGNORE = _SENTINEL_ROOT / ".dockerignore"


def _dockerfile_text() -> str:
    return _DOCKERFILE.read_text(encoding="utf-8")


def _dockerignore_text() -> str:
    return _DOCKERIGNORE.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Vector 5 — non-root runtime user.                                           #
# --------------------------------------------------------------------------- #
def test_dockerfile_runs_as_non_root():
    text = _dockerfile_text()
    assert "USER 1000" in text, "runtime stage must run as non-root uid 1000 (R9)"
    # The non-root user must be created before it is switched to.
    assert "useradd" in text and "--uid 1000" in text
    # USER must come AFTER the package/source COPY (so build steps that need root
    # have run, and the running process is unprivileged).
    user_idx = text.index("USER 1000")
    copy_idx = text.rindex("COPY")
    assert user_idx > copy_idx, "USER 1000 must be set after the final COPY"


# --------------------------------------------------------------------------- #
# Vector 6 — no secrets baked into the image; build context excludes them.    #
# --------------------------------------------------------------------------- #
def test_dockerfile_no_secrets_baked():
    text = _dockerfile_text().lower()
    # No secret VALUE is ever set via ENV/ARG in the image.
    for forbidden in (
        "sentinel_key_secret=",
        "postgres_password=",
        "redis_password=",
        "anthropic_api_key=",
        "aws_secret_access_key=",
        "database_url=postgresql",
    ):
        assert forbidden not in text, f"Dockerfile must not bake a secret: {forbidden}"
    # No copying of dotenv / key material into a layer.
    assert "copy .env" not in text
    assert ".pem" not in text and "id_rsa" not in text


def test_dockerignore_excludes_secrets_and_cruft():
    text = _dockerignore_text()
    for needed in (".env", "secrets", "tests", "__pycache__", ".git"):
        assert needed in text, f".dockerignore must exclude {needed!r} (R4 / size)"


# --------------------------------------------------------------------------- #
# Vector 7 — health check probes /livez via the bundled interpreter.          #
# --------------------------------------------------------------------------- #
def test_dockerfile_health_check_targets_livez():
    text = _dockerfile_text()
    assert "HEALTHCHECK" in text, "image must declare a HEALTHCHECK"
    # Inspect ONLY the HEALTHCHECK directive (the surrounding comments legitimately
    # mention curl to explain why it is NOT used). /livez is the dependency-free
    # liveness probe (R5); curl is absent from the slim base, so the probe uses
    # the bundled python interpreter.
    lines = text.splitlines()
    # The directive line starts with HEALTHCHECK (a comment that merely mentions
    # the word is indented behind '#').
    hc_idx = next(i for i, ln in enumerate(lines) if ln.strip().startswith("HEALTHCHECK"))
    hc_block = "\n".join(lines[hc_idx : hc_idx + 3])  # directive + its CMD continuation
    assert "/livez" in hc_block, "HEALTHCHECK must probe /livez"
    assert "urlopen" in hc_block and "python" in hc_block, "HEALTHCHECK must use python urllib"
    assert "curl" not in hc_block, "HEALTHCHECK command must not invoke curl"


def test_dockerfile_is_multistage_slim_base():
    text = _dockerfile_text()
    assert text.count("FROM python:3.12-slim-bookworm") >= 2, "must be multi-stage"
    assert "AS builder" in text and "AS runtime" in text
