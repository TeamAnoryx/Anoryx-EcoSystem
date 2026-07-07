"""Dockerfile threat-model tests (O-008, ADR-0008 Fork C).

These assert the image's security guarantees from the Dockerfile + .dockerignore
text — deterministic and CI-safe (no Docker daemon required). Mirrors
Anoryx-Sentinel's tests/deploy/test_dockerfile.py (F-010, ADR-0012 §9).

  - test_dockerfile_runs_as_non_root         — USER directive sets uid 1000
  - test_dockerfile_no_secrets_baked         — no secret COPY/ENV; .dockerignore excludes
  - test_dockerfile_health_check_targets_health — HEALTHCHECK probes /health (no curl)
"""

from __future__ import annotations

from pathlib import Path

# tests/deploy/test_dockerfile.py -> Anoryx-AI-Orchestrator/
_ORCH_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _ORCH_ROOT / "Dockerfile"
_DOCKERIGNORE = _ORCH_ROOT / ".dockerignore"


def _dockerfile_text() -> str:
    return _DOCKERFILE.read_text(encoding="utf-8")


def _dockerignore_text() -> str:
    return _DOCKERIGNORE.read_text(encoding="utf-8")


def test_dockerfile_runs_as_non_root():
    text = _dockerfile_text()
    assert "USER 1000" in text, "runtime stage must run as non-root uid 1000"
    assert "useradd" in text and "--uid 1000" in text
    # USER must come AFTER the final COPY (build steps needing root have run).
    user_idx = text.index("USER 1000")
    copy_idx = text.rindex("COPY")
    assert user_idx > copy_idx, "USER 1000 must be set after the final COPY"


def test_dockerfile_no_secrets_baked():
    text = _dockerfile_text().lower()
    for forbidden in (
        "orch_ingest_hmac_secret=",
        "orch_admin_token=",
        "postgres_password=",
        "anthropic_api_key=",
        "aws_secret_access_key=",
        "orch_database_url=postgresql",
    ):
        assert forbidden not in text, f"Dockerfile must not bake a secret: {forbidden}"
    assert "copy .env" not in text
    assert ".pem" not in text and "id_rsa" not in text


def test_dockerignore_excludes_secrets_and_cruft():
    text = _dockerignore_text()
    for needed in (".env", "secrets", "tests", "__pycache__", ".git"):
        assert needed in text, f".dockerignore must exclude {needed!r}"


def test_dockerfile_health_check_targets_health():
    text = _dockerfile_text()
    assert "HEALTHCHECK" in text, "image must declare a HEALTHCHECK"
    lines = text.splitlines()
    hc_idx = next(i for i, ln in enumerate(lines) if ln.strip().startswith("HEALTHCHECK"))
    hc_block = "\n".join(lines[hc_idx : hc_idx + 3])
    assert "/health" in hc_block, "HEALTHCHECK must probe /health"
    assert "urlopen" in hc_block and "python" in hc_block, "HEALTHCHECK must use python urllib"
    assert "curl" not in hc_block, "HEALTHCHECK command must not invoke curl"


def test_dockerfile_is_multistage_slim_base():
    text = _dockerfile_text()
    assert text.count("FROM python:3.12-slim-bookworm") >= 2, "must be multi-stage"
    assert "AS builder" in text and "AS runtime" in text
