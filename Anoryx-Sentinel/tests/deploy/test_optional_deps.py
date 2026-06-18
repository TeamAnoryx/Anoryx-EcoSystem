"""Optional-dependency boundary tests (F-010 fix-up, ADR-0012 §Image variants).

Proves the slim/full dependency split: the heavy deps (boto3/aioboto3, spaCy/
Presidio, gRPC OTLP) are optional extras, NOT core; and the guarded use sites
raise a clear install hint when the extra is absent (so a slim image fails
honestly, never with a raw ImportError mid-request).
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

_SENTINEL_ROOT = Path(__file__).resolve().parents[2]


def _pyproject() -> dict:
    return tomllib.loads((_SENTINEL_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_heavy_deps_are_extras_not_core():
    pp = _pyproject()
    core = " ".join(pp["project"]["dependencies"])
    extras = pp["project"]["optional-dependencies"]
    # None of the heavy deps may be in core.
    for pkg in (
        "boto3",
        "aioboto3",
        "spacy",
        "presidio-analyzer",
        "presidio-anonymizer",
        "otlp-proto-grpc",
    ):
        assert pkg not in core, f"{pkg} must be an optional extra, not a core dependency"
    # Extras exist and are correctly populated.
    assert any("boto3" in d for d in extras["bedrock"])
    assert any("aioboto3" in d for d in extras["bedrock"])
    assert any("presidio" in d for d in extras["pii-spacy"])
    assert any("spacy" in d for d in extras["pii-spacy"])
    assert any("otlp-proto-grpc" in d for d in extras["otlp-grpc"])
    assert "all" in extras
    # The lightweight HTTP OTLP exporter IS a core dependency (default transport).
    assert "opentelemetry-exporter-otlp-proto-http" in core


def test_bedrock_session_raises_clear_error_without_aioboto3(monkeypatch):
    """Slim image (no [bedrock]) → Bedrock use raises a clear install hint, not ImportError."""
    from gateway.router.providers.bedrock_provider import BedrockAdapter

    # Force `import aioboto3` to raise ImportError even if it is installed locally.
    monkeypatch.setitem(sys.modules, "aioboto3", None)
    adapter = BedrockAdapter("us-east-1", "ak", "sk")
    with pytest.raises(RuntimeError, match=r"bedrock"):
        adapter._session()
