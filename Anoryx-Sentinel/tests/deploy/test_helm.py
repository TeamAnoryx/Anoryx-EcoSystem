"""Helm chart threat-model tests (F-010, ADR-0012 §9 vectors 9, 10, 11).

Runs the real `helm` CLI via subprocess (skipped where helm is absent, e.g. a
minimal CI lane — the release/helm CI job installs helm). kubectl --dry-run is
NOT used: in kubectl 1.34 even client dry-run requires a reachable API server,
so server-side validation is deferred to CI with a kind cluster (ADR-0012 §10).

  9  test_helm_lint_passes          — helm lint exits 0, no chart failures
  10 test_helm_template_renders     — both bundled + external modes render valid YAML
  11 test_helm_networkpolicy_restrictive — default-deny + scoped egress only
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_SENTINEL_ROOT = Path(__file__).resolve().parents[2]
_CHART = _SENTINEL_ROOT / "deploy" / "helm" / "sentinel"
_HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(_HELM is None, reason="helm CLI not on PATH")


def _helm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([_HELM, *args], capture_output=True, text=True)  # noqa: S603


def test_helm_lint_passes():
    r = _helm("lint", str(_CHART))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 chart(s) failed" in r.stdout


def test_helm_template_renders():
    # Default (bundled) mode.
    r = _helm("template", "t", str(_CHART))
    assert r.returncode == 0, r.stderr
    kinds = {d["kind"] for d in yaml.safe_load_all(r.stdout) if d}
    assert {"Deployment", "Service", "NetworkPolicy", "PodDisruptionBudget", "Job"}.issubset(kinds)
    assert "PersistentVolumeClaim" in kinds  # bundled postgres PVC

    # External mode: managed PG/Redis + HPA, no bundled PVC.
    r2 = _helm(
        "template",
        "t",
        str(_CHART),
        "--set",
        "postgres.bundled=false",
        "--set",
        "redis.bundled=false",
        "--set",
        "envSecret=my-secret",
        "--set",
        "autoscaling.enabled=true",
    )
    assert r2.returncode == 0, r2.stderr
    kinds2 = {d["kind"] for d in yaml.safe_load_all(r2.stdout) if d}
    assert "HorizontalPodAutoscaler" in kinds2
    assert "PersistentVolumeClaim" not in kinds2


def test_helm_networkpolicy_restrictive():
    r = _helm("template", "t", str(_CHART), "--show-only", "templates/networkpolicy.yaml")
    assert r.returncode == 0, r.stderr
    np = yaml.safe_load(r.stdout)
    spec = np["spec"]
    # Default-deny posture: both directions listed → only explicit rules allowed.
    assert "Egress" in spec["policyTypes"] and "Ingress" in spec["policyTypes"]
    # The policy is scoped to the gateway pods, not the whole namespace.
    assert spec["podSelector"]["matchLabels"]
    # EVERY egress rule must constrain ports — no open all-port rule (code-review Med M1).
    assert all(
        rule.get("ports") for rule in spec["egress"]
    ), "every egress rule must specify ports (no open podSelector rule)"
    # Allowed egress ports: DNS, in-cluster deps (pg/redis/otel), provider HTTPS.
    egress_ports = {p.get("port") for rule in spec["egress"] for p in rule["ports"]}
    assert egress_ports <= {
        53,
        5432,
        6379,
        4317,
        4318,
        443,
    }, f"unexpected egress ports: {egress_ports}"
    # In-cluster destinations must be label-scoped to component pods, not the namespace.
    for rule in spec["egress"]:
        for dest in rule.get("to", []):
            sel = dest.get("podSelector")
            if sel is not None:
                assert sel.get("matchLabels"), "podSelector egress must be label-scoped, not empty"
