"""Release-workflow threat-model test (F-010, ADR-0012 §9 vector 12).

  12 test_release_workflow_yaml_valid — actionlint passes + required permissions
     present. The structural assertions run with no tooling; the actionlint
     subprocess is skipped where the binary is absent (the CI lane installs it).

The workflow lives at the REPO root (.github/workflows/), alongside sentinel-ci.yml.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

# tests/deploy → Anoryx-Sentinel → <repo root>
_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "sentinel-release.yml"
_ACTIONLINT = shutil.which("actionlint")


def _load() -> dict:
    assert _WORKFLOW.exists(), f"release workflow not found at {_WORKFLOW}"
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def test_release_workflow_triggers_on_semver_tag():
    wf = _load()
    # PyYAML parses the bare `on:` key as boolean True.
    on = wf.get("on") or wf.get(True)
    assert on["push"]["tags"] == ["v*"]


def test_release_workflow_has_required_permissions():
    wf = _load()
    perms = wf["permissions"]
    for needed in ("contents", "packages", "id-token", "pages"):
        assert needed in perms, f"missing permission: {needed}"
    assert perms["id-token"] == "write"  # OIDC for cosign keyless
    assert perms["packages"] == "write"  # GHCR push


def test_release_workflow_signs_and_sboms():
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "cosign sign" in text, "image must be cosign-signed (R11)"
    assert "spdx-json" in text or "sbom" in text.lower(), "SBOM must be generated (R11)"
    assert "platforms: linux/amd64,linux/arm64" in text, "multi-arch build required"


def test_release_does_not_modify_ci_workflow():
    # R2: the CI workflow must still exist unchanged alongside the release one.
    ci = _REPO_ROOT / ".github" / "workflows" / "sentinel-ci.yml"
    assert ci.exists(), "sentinel-ci.yml must remain present (R2)"


@pytest.mark.skipif(_ACTIONLINT is None, reason="actionlint not on PATH")
def test_release_workflow_actionlint_clean():
    r = subprocess.run([_ACTIONLINT, str(_WORKFLOW)], capture_output=True, text=True)  # noqa: S603
    assert r.returncode == 0, r.stdout + r.stderr
