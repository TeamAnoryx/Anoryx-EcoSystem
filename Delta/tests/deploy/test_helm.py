"""Helm chart threat-model tests (D-010).

Runs the real `helm` CLI via subprocess (skipped where helm is absent — no
existing Delta CI job installs helm, matching precedent). Mirrors Anoryx-AI-
Orchestrator's tests/deploy/test_helm.py (O-008, ADR-0008 Fork F/H), itself
mirroring Anoryx-Sentinel's tests/deploy/test_helm.py (F-010, ADR-0012 §9
vectors 9-11) — adapted for Delta's TWO components (ingest + admin) instead of
one.

  - test_helm_lint_passes                 — helm lint exits 0, no chart failures
  - test_helm_template_renders            — both bundled + external modes render valid YAML
  - test_helm_networkpolicy_restrictive   — Ingress+Egress default, scoped ports, both components
  - test_helm_admin_networkpolicy_has_no_open_ingress — admin has no ingressCIDRs-equivalent
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_DELTA_ROOT = Path(__file__).resolve().parents[2]
_CHART = _DELTA_ROOT / "deploy" / "helm" / "delta"
_HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(_HELM is None, reason="helm CLI not on PATH")


def _helm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([_HELM, *args], capture_output=True, text=True)  # noqa: S603


def _networkpolicies(stdout: str) -> dict[str, dict]:
    """Map component label -> NetworkPolicy doc, from a --show-only render."""
    docs = [d for d in yaml.safe_load_all(stdout) if d]
    return {d["metadata"]["labels"]["app.kubernetes.io/component"]: d for d in docs}


def test_helm_lint_passes():
    r = _helm("lint", str(_CHART))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 chart(s) failed" in r.stdout


def test_helm_template_renders():
    # Default (bundled) mode.
    r = _helm("template", "t", str(_CHART))
    assert r.returncode == 0, r.stderr
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    kinds = {d["kind"] for d in docs}
    assert {"Deployment", "Service", "NetworkPolicy", "PodDisruptionBudget", "Job"}.issubset(kinds)
    assert "PersistentVolumeClaim" in kinds  # bundled postgres PVC

    deployments = {d["metadata"]["name"] for d in docs if d["kind"] == "Deployment"}
    assert any(name.endswith("-ingest") for name in deployments)
    assert any(name.endswith("-admin") for name in deployments)
    assert any(name.endswith("-postgres") for name in deployments)

    # Two NetworkPolicies (ingest + admin), two PDBs, two Services (+ postgres Service).
    netpols = [d for d in docs if d["kind"] == "NetworkPolicy"]
    assert len(netpols) == 2
    pdbs = [d for d in docs if d["kind"] == "PodDisruptionBudget"]
    assert len(pdbs) == 2

    # External mode: managed Postgres + ingest HPA, no bundled PVC.
    r2 = _helm(
        "template",
        "t",
        str(_CHART),
        "--set",
        "postgres.bundled=false",
        "--set",
        "envSecret=my-secret",
        "--set",
        "ingest.autoscaling.enabled=true",
    )
    assert r2.returncode == 0, r2.stderr
    docs2 = [d for d in yaml.safe_load_all(r2.stdout) if d]
    kinds2 = {d["kind"] for d in docs2}
    assert "HorizontalPodAutoscaler" in kinds2
    assert "PersistentVolumeClaim" not in kinds2, "external mode must not render the bundled PVC"


def test_helm_networkpolicy_restrictive():
    r = _helm("template", "t", str(_CHART), "--show-only", "templates/networkpolicy.yaml")
    assert r.returncode == 0, r.stderr
    netpols = _networkpolicies(r.stdout)
    assert set(netpols) == {"ingest", "admin"}
    for component, np in netpols.items():
        spec = np["spec"]
        assert "Egress" in spec["policyTypes"] and "Ingress" in spec["policyTypes"]
        assert spec["podSelector"]["matchLabels"]
        # EVERY egress rule must constrain ports — no open all-port rule.
        assert all(
            rule.get("ports") for rule in spec["egress"]
        ), f"{component}: every egress rule must specify ports"
        egress_ports = {p.get("port") for rule in spec["egress"] for p in rule["ports"]}
        assert egress_ports <= {53, 5432, 443}, f"{component}: unexpected egress ports"
        # Every ingress rule must also constrain ports.
        assert all(
            rule.get("ports") for rule in spec["ingress"]
        ), f"{component}: every ingress rule must specify ports"


def test_helm_admin_networkpolicy_has_no_open_ingress():
    # The admin console is internal-only: unlike the ingest component, its
    # ingress rules must NEVER include a bare (source-unrestricted) rule.
    r = _helm("template", "t", str(_CHART), "--show-only", "templates/networkpolicy.yaml")
    assert r.returncode == 0, r.stderr
    netpols = _networkpolicies(r.stdout)
    admin_ingress = netpols["admin"]["spec"]["ingress"]
    for rule in admin_ingress:
        assert rule.get("from"), "admin NetworkPolicy must not have a source-unrestricted rule"
    # No :443 admin egress (the admin app never calls the Orchestrator seam).
    admin_egress_ports = {
        p.get("port") for rule in netpols["admin"]["spec"]["egress"] for p in rule["ports"]
    }
    assert 443 not in admin_egress_ports


def test_helm_networkpolicy_restricted_cidrs_scope_rules():
    r = _helm(
        "template",
        "t",
        str(_CHART),
        "--show-only",
        "templates/networkpolicy.yaml",
        "--set",
        "networkPolicy.orchestratorEgressCIDRs={203.0.113.0/24}",
        "--set",
        "networkPolicy.ingressCIDRs={198.51.100.0/24}",
    )
    assert r.returncode == 0, r.stderr
    netpols = _networkpolicies(r.stdout)
    ingest_spec = netpols["ingest"]["spec"]
    egress_cidrs = {
        dest["ipBlock"]["cidr"]
        for rule in ingest_spec["egress"]
        for dest in rule.get("to", [])
        if "ipBlock" in dest
    }
    assert "203.0.113.0/24" in egress_cidrs
    ingress_cidrs = {
        src["ipBlock"]["cidr"]
        for rule in ingest_spec["ingress"]
        for src in rule.get("from", [])
        if "ipBlock" in src
    }
    assert "198.51.100.0/24" in ingress_cidrs


def test_helm_ingest_admin_serve_different_targets():
    r = _helm("template", "t", str(_CHART))
    assert r.returncode == 0, r.stderr
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    # Filter to just the app deployments (exclude bundled postgres).
    app_deployments = {
        d["metadata"]["labels"]["app.kubernetes.io/component"]: d
        for d in docs
        if d["kind"] == "Deployment"
        and d["metadata"]["labels"]["app.kubernetes.io/component"] in ("ingest", "admin")
    }
    ingest_args = app_deployments["ingest"]["spec"]["template"]["spec"]["containers"][0]["args"]
    admin_args = app_deployments["admin"]["spec"]["template"]["spec"]["containers"][0]["args"]
    assert "delta.ingest.app:create_app" in ingest_args
    assert "delta.allocation_admin.app:create_app" in admin_args
