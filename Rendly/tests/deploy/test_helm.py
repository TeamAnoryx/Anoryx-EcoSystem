"""Helm chart threat-model tests (R-010, ADR-0010 Fork E/H).

Runs the real `helm` CLI via subprocess (skipped where helm is absent — the release/deploy
CI job installs helm). Mirrors Anoryx-AI-Orchestrator's tests/deploy/test_helm.py (O-008,
ADR-0008).

  - test_helm_lint_passes                — helm lint exits 0, no chart failures
  - test_helm_template_renders           — both bundled + external modes render valid YAML
  - test_helm_networkpolicy_restrictive  — Ingress+Egress default, scoped ports only
  - test_helm_default_replica_count_is_one — the single-instance realtime constraint (Fork E)
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_RENDLY_ROOT = Path(__file__).resolve().parents[2]
_CHART = _RENDLY_ROOT / "deploy" / "helm" / "rendly"
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
    assert {"Deployment", "Service", "NetworkPolicy", "Job"}.issubset(kinds)
    assert "PersistentVolumeClaim" in kinds  # bundled postgres PVC
    assert "PodDisruptionBudget" not in kinds  # disabled by default (Fork E)

    # External mode: managed Postgres + HPA, no bundled PVC.
    r2 = _helm(
        "template",
        "t",
        str(_CHART),
        "--set",
        "postgres.bundled=false",
        "--set",
        "envSecret=my-secret",
        "--set",
        "autoscaling.enabled=true",
    )
    assert r2.returncode == 0, r2.stderr
    docs2 = [d for d in yaml.safe_load_all(r2.stdout) if d]
    kinds2 = {d["kind"] for d in docs2}
    assert "HorizontalPodAutoscaler" in kinds2
    assert "PersistentVolumeClaim" not in kinds2, "external mode must not render the bundled PVC"


def test_helm_default_replica_count_is_one():
    # The realtime WS/huddle layer keeps state in-process (no cross-replica fan-out) — the
    # chart must not default to >1 replica (ADR-0010 Fork E).
    r = _helm("template", "t", str(_CHART), "--show-only", "templates/deployment.yaml")
    assert r.returncode == 0, r.stderr
    dep = yaml.safe_load(r.stdout)
    assert dep["spec"]["replicas"] == 1


def test_helm_networkpolicy_restrictive():
    r = _helm("template", "t", str(_CHART), "--show-only", "templates/networkpolicy.yaml")
    assert r.returncode == 0, r.stderr
    np = yaml.safe_load(r.stdout)
    spec = np["spec"]
    assert "Egress" in spec["policyTypes"] and "Ingress" in spec["policyTypes"]
    assert spec["podSelector"]["matchLabels"]
    # EVERY egress rule must constrain ports — no open all-port rule.
    assert all(rule.get("ports") for rule in spec["egress"]), "every egress rule must specify ports"
    egress_ports = {p.get("port") for rule in spec["egress"] for p in rule["ports"]}
    # No cross-product network dependency (unlike the Orchestrator) — no :443 rule at all.
    assert egress_ports <= {53, 5432}, f"unexpected egress ports: {egress_ports}"
    # Every ingress rule must also constrain ports.
    assert all(
        rule.get("ports") for rule in spec["ingress"]
    ), "every ingress rule must specify ports"


def test_helm_networkpolicy_restricted_ingress_cidrs_scope_rules():
    r = _helm(
        "template",
        "t",
        str(_CHART),
        "--show-only",
        "templates/networkpolicy.yaml",
        "--set",
        "networkPolicy.ingressCIDRs={198.51.100.0/24}",
    )
    assert r.returncode == 0, r.stderr
    np = yaml.safe_load(r.stdout)
    spec = np["spec"]
    ingress_cidrs = {
        src["ipBlock"]["cidr"]
        for rule in spec["ingress"]
        for src in rule.get("from", [])
        if "ipBlock" in src
    }
    assert "198.51.100.0/24" in ingress_cidrs
