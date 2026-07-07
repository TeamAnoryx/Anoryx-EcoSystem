"""Multi-region overlay tests (F-022, ADR-0028).

Two layers:

* **Parse-only** (no `helm` needed → run in the standard CI lane): assert the
  region overlay is OFF by default, every region template is gated on
  `region.enabled`, the replication SQL is append-only safe and scoped to only the
  two global stores, the example overlays are well-formed, and no secret material
  is committed.
* **helm-gated** (skipped where `helm` is absent, mirroring test_helm.py): render
  the chart and prove the DEFAULT render is byte-identical (no region resources),
  the active/passive overlays render the right resources, the bootstrap Job is
  gated, and enabling region does NOT loosen the restrictive NetworkPolicy.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_SENTINEL_ROOT = Path(__file__).resolve().parents[2]
_CHART = _SENTINEL_ROOT / "deploy" / "helm" / "sentinel"
_TEMPLATES = _CHART / "templates"
_VALUES = _CHART / "values.yaml"
_ACTIVE = _CHART / "values.region-active.example.yaml"
_PASSIVE = _CHART / "values.region-passive.example.yaml"
_REPL_CM = _TEMPLATES / "region-replication-configmap.yaml"
_REPL_JOB = _TEMPLATES / "region-replication-job.yaml"
_HELPERS = _TEMPLATES / "_helpers.tpl"
_GATEWAY_DEPLOY = _TEMPLATES / "deployment.yaml"
_WORKER_DEPLOY = _TEMPLATES / "worker-deployment.yaml"

# The two globally-uniform stores replicated across regions (ADR-0028 D3). The
# policy store must be uniform everywhere it is enforced; the audit log is one
# append-only, hash-chained record. Nothing residency-bound may be here.
_GLOBAL_STORES = {"policies", "policy_versions", "events_audit_log"}

# Destructive SQL statements that would break the append-only / read-only-replica
# invariant. Matched case-insensitively as whole phrases (so the prose word
# "drops" does not false-match "drop table").
_DESTRUCTIVE_SQL = ("drop table", "drop database", "delete from", "truncate", "alter table")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _noncomment(path: Path) -> str:
    """Template/script text with comment lines (YAML `#` and shell `#`) removed, so a
    substring assertion checks real directives, not prose that mentions the token."""
    return "\n".join(ln for ln in _text(path).splitlines() if not ln.lstrip().startswith("#"))


# --------------------------------------------------------------------------- #
# Parse-only — run everywhere (no helm binary).                               #
# --------------------------------------------------------------------------- #
def test_region_disabled_by_default():
    """values.yaml ships region OFF → the chart is byte-identical to ADR-0027."""
    values = yaml.safe_load(_text(_VALUES))
    region = values["region"]
    assert region["enabled"] is False, "region MUST default to disabled"
    assert region["role"] == "active"
    assert region["replication"]["enabled"] is False
    assert region["replication"]["bootstrapJob"]["enabled"] is False
    assert region["topologySpread"]["enabled"] is False
    assert region["geoRouting"]["annotations"] == {}


def test_replication_defaults_to_global_stores_only():
    """Default replicated table set is EXACTLY the two global stores — residency
    safety: physical replication (whole cluster) is deliberately avoided."""
    values = yaml.safe_load(_text(_VALUES))
    tables = set(values["region"]["replication"]["tables"])
    assert tables == _GLOBAL_STORES, f"unexpected replicated tables: {tables}"


def test_region_templates_are_gated():
    """Every region template guards on region.enabled so nothing renders by
    default; the replication Job additionally requires its own opt-in flag."""
    cm = _text(_REPL_CM)
    assert ".Values.region.enabled" in cm
    assert ".Values.region.replication.enabled" in cm

    job = _text(_REPL_JOB)
    assert ".Values.region.enabled" in job
    assert ".Values.region.replication.enabled" in job
    assert ".Values.region.replication.bootstrapJob.enabled" in job

    helpers = _text(_HELPERS)
    # The env + label partials self-gate on region.enabled.
    assert 'define "sentinel.regionEnv"' in helpers
    assert 'define "sentinel.regionLabels"' in helpers
    assert helpers.count("if .Values.region.enabled") >= 2


def test_replication_sql_is_append_only_safe():
    """The rendered SQL only CREATEs a publication/subscription — never drops,
    deletes, rewrites, or truncates data (the audit log is append-only; the
    passive copy is read-only)."""
    cm = _text(_REPL_CM).lower()
    assert "create publication" in cm
    assert "create subscription" in cm
    for stmt in _DESTRUCTIVE_SQL:
        assert stmt not in cm, f"replication SQL must not contain a destructive statement: {stmt!r}"


def test_replication_never_commits_a_password():
    """Any `password=` in a region file MUST be the ${REPLICATION_PASSWORD}
    placeholder, never a literal (R4 — no secrets in the repo). The passive
    subscription path references the placeholder; the active publisher has no
    password at all."""
    for path in (_REPL_CM, _ACTIVE, _PASSIVE):
        for line in _text(path).splitlines():
            low = line.lower()
            if "password=" in low:
                assert (
                    "${replication_password}" in low
                ), f"literal password in {path.name}: {line!r}"
    # Positive: the subscription template + passive overlay use the placeholder form.
    assert "${REPLICATION_PASSWORD}" in _text(_REPL_CM)


def test_example_overlays_are_wellformed():
    active = yaml.safe_load(_text(_ACTIVE))["region"]
    passive = yaml.safe_load(_text(_PASSIVE))["region"]

    assert active["enabled"] is True and active["role"] == "active"
    assert active["replication"]["enabled"] is True

    assert passive["enabled"] is True and passive["role"] == "passive"
    assert passive["replication"]["enabled"] is True
    # A passive region must know where the active primary is (sans password).
    conninfo = passive["replication"]["activePrimaryConninfo"]
    assert "host=" in conninfo and "password" not in conninfo.lower()


# --- F-022 audit remediation (parse-only, run in CI) ----------------------- #
def test_replication_table_allowlist_is_enforced_at_render():
    """Residency safety is ENFORCED, not conventional (audit H1 / code-review High):
    the ConfigMap fails the render if region.replication.tables includes anything
    outside the approved global stores."""
    cm = _text(_REPL_CM)
    assert "{{- fail" in cm, "configmap must fail-fast on a non-allowlisted table"
    # The guard iterates the tables and checks membership in the global-store list.
    assert 'has . (list "policies" "policy_versions" "events_audit_log")' in cm


def test_region_includes_are_call_site_gated():
    """Byte-identical-when-off (audit Info / code-review Medium): the region label +
    env includes must be wrapped in `if .Values.region.enabled` AT THE CALL SITE, not
    only self-gated inside the helper — `nindent` on an empty string still emits a
    whitespace-only line, so an unguarded call leaks into the default render."""
    for path in (_GATEWAY_DEPLOY, _WORKER_DEPLOY):
        text = _text(path)
        for include in ("sentinel.regionLabels", "sentinel.regionEnv"):
            idx = text.index(f'include "{include}"')
            # The 120 chars before the include must open an region.enabled guard.
            preceding = text[max(0, idx - 120) : idx]
            assert (
                "if .Values.region.enabled" in preceding
            ), f"{path.name}: include {include} is not call-site gated on region.enabled"


def test_bootstrap_job_uses_least_privilege_secret():
    """The replication Job must NOT envFrom the whole app Secret (audit Low): it
    injects only the single REPLICATION_PASSWORD key."""
    job = _noncomment(_REPL_JOB)
    assert "envFrom:" not in job, "replication Job must not mount the whole app Secret"
    assert "key: REPLICATION_PASSWORD" in job


def test_bootstrap_job_name_is_revision_suffixed():
    """A Job's spec.template is immutable → the name must be revision-suffixed like
    the migrate/seed/minio-init Jobs (audit/code-review Medium)."""
    job = _text(_REPL_JOB)
    assert "-region-replication-{{ .Release.Revision }}" in job


def test_bootstrap_job_has_no_silent_pipe_failopen():
    """The `sed | psql` pipe let a sed error leave psql to exit 0 on empty input
    (silent no-op). The fix substitutes into a temp file under `set -e` instead."""
    job = _noncomment(_REPL_JOB)
    assert "| psql" not in job, "no sed|psql pipe (it fails open on a sed error)"
    assert "psql -v ON_ERROR_STOP=1 -f" in job


def test_passive_example_pins_replication_tls():
    """Cross-region replication carries signed policies + the audit log → the example
    conninfo must verify the server cert, not merely encrypt (audit Medium)."""
    conninfo = yaml.safe_load(_text(_PASSIVE))["region"]["replication"]["activePrimaryConninfo"]
    assert "sslmode=verify-full" in conninfo
    assert "sslrootcert=" in conninfo


# --------------------------------------------------------------------------- #
# helm-gated — render + assert (skipped where helm is absent).                #
# --------------------------------------------------------------------------- #
_HELM = shutil.which("helm")
helm_only = pytest.mark.skipif(_HELM is None, reason="helm CLI not on PATH")


def _template(*args: str) -> str:
    r = subprocess.run(  # noqa: S603
        [_HELM, "template", "t", str(_CHART), *args], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


@helm_only
def test_default_render_has_no_region_resources():
    """region.enabled=false → NOT ONE region artifact renders (gated == byte
    identical to the single-cluster chart)."""
    out = _template()
    assert "region-replication" not in out
    assert "SENTINEL_REGION" not in out
    assert "topology.kubernetes.io/region" not in out
    assert "topologySpreadConstraints" not in out
    assert "anoryx.io/region-role" not in out


@helm_only
def test_active_overlay_renders_publication_and_identity():
    out = _template("-f", str(_ACTIVE))
    docs = [d for d in yaml.safe_load_all(out) if d]

    cms = [
        d
        for d in docs
        if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-region-replication")
    ]
    assert len(cms) == 1, "active region must render the replication ConfigMap"
    data = cms[0]["data"]
    assert "publication.sql" in data and "subscription.sql" not in data
    assert "CREATE PUBLICATION" in data["publication.sql"]
    # SQL replicates exactly the three global stores.
    for tbl in _GLOBAL_STORES:
        assert tbl in data["publication.sql"]

    # Region identity is on the gateway + worker pods (env + labels).
    workloads = [d for d in docs if d["kind"] == "Deployment"]
    region_pods = [
        d
        for d in workloads
        if d["spec"]["template"]["metadata"]["labels"].get("topology.kubernetes.io/region")
        == "us-east-1"
    ]
    assert len(region_pods) >= 2, "gateway + worker must carry the region label"

    # Gateway carries topology spread + the Service carries the geo annotation.
    assert "topologySpreadConstraints" in out
    svcs = [d for d in docs if d["kind"] == "Service"]
    assert any(
        (d["metadata"].get("annotations") or {}).get("external-dns.alpha.kubernetes.io/hostname")
        for d in svcs
    ), "geo-routing annotation must surface on a Service"


@helm_only
def test_passive_overlay_renders_subscription_only():
    out = _template("-f", str(_PASSIVE))
    docs = [d for d in yaml.safe_load_all(out) if d]
    cm = next(
        d
        for d in docs
        if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-region-replication")
    )
    data = cm["data"]
    assert "subscription.sql" in data and "publication.sql" not in data
    sub = data["subscription.sql"]
    assert "CREATE SUBSCRIPTION" in sub
    # Password is a placeholder, never a literal.
    assert "${REPLICATION_PASSWORD}" in sub
    # Passive role is labeled on the pods.
    assert 'anoryx.io/region-role: "passive"' in out or "region-role: passive" in out


def _render_result(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [_HELM, "template", "t", str(_CHART), *args], capture_output=True, text=True
    )


@helm_only
def test_invalid_region_role_fails_render():
    """An unrecognized region.role must FAIL rendering (fail-fast), not silently
    fall through to the passive/subscription branch."""
    r = _render_result(
        "--set", "region.enabled=true", "--set", "region.name=x", "--set", "region.role=bogus"
    )
    assert r.returncode != 0, "bad region.role must fail the render"
    assert "active" in r.stderr and "passive" in r.stderr


@helm_only
def test_region_name_required_when_enabled():
    """region.name is required once region.enabled=true (empty → hard fail)."""
    r = _render_result(
        "--set", "region.enabled=true", "--set", "region.role=active", "--set", "region.name="
    )
    assert r.returncode != 0, "empty region.name must fail the render"
    assert "region.name is required" in r.stderr


def _replication_jobs(rendered: str) -> list:
    """Only the region-replication Job (the base chart has its own migrate / seed /
    minio-init Jobs, which are irrelevant here). The Job name is revision-suffixed
    (immutability — matches migrate/seed/minio-init), so match by substring."""
    return [
        d
        for d in yaml.safe_load_all(rendered)
        if d and d["kind"] == "Job" and "-region-replication-" in d["metadata"]["name"]
    ]


@helm_only
def test_bootstrap_job_is_opt_in():
    """The replication Job renders ONLY when bootstrapJob.enabled=true, even with
    replication otherwise on."""
    without = _template("-f", str(_ACTIVE))
    assert _replication_jobs(without) == [], "bootstrap Job must be off by default"

    with_job = _template(
        "-f", str(_ACTIVE), "--set", "region.replication.bootstrapJob.enabled=true"
    )
    assert len(_replication_jobs(with_job)) == 1, "bootstrap Job must render when opted in"


@helm_only
def test_region_does_not_loosen_networkpolicy():
    """Enabling region must NOT loosen the default-deny NetworkPolicy — cross-region
    replication egress goes through networkPolicy.extraEgress (ADR-0028 D6). Compare
    the FULL egress rule set (peers + ports) with region off vs on, so a future
    change that broadens a `to:` peer on an already-allowed port is also caught
    (audit Info)."""

    def _np_egress(rendered: str):
        np = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "NetworkPolicy")
        # Canonical, order-independent representation of every egress rule.
        return sorted(yaml.safe_dump(rule, sort_keys=True) for rule in np["spec"].get("egress", []))

    off = _np_egress(_template("--show-only", "templates/networkpolicy.yaml"))
    on = _np_egress(_template("-f", str(_ACTIVE), "--show-only", "templates/networkpolicy.yaml"))
    assert off == on, "region overlay changed the default NetworkPolicy egress rules"


@helm_only
def test_non_global_table_fails_render():
    """A residency-bound / tenant-scoped table in region.replication.tables must FAIL
    the render (allowlist enforcement — audit H1 / code-review High), not silently
    replicate across regions."""
    r = _render_result(
        "-f",
        str(_ACTIVE),
        "--set",
        "region.replication.tables={policies,requests}",
    )
    assert r.returncode != 0, "a non-global table must fail the render"
    assert "not an approved global store" in r.stderr


@helm_only
def test_region_off_gate_dominates_subfields():
    """Fail-safe default (audit I1): nothing region-related renders unless
    region.enabled=true. Toggling replication / topologySpread / geoRouting while
    region.enabled stays false must leave the render byte-identical to the default —
    the master gate dominates. (Robust to the base chart's own whitespace, unlike a
    raw whitespace-line check, because both renders share it.)"""
    default = _template()
    with_subfields = _template(
        "--set",
        "region.replication.enabled=true",
        "--set",
        "region.topologySpread.enabled=true",
        "--set",
        "region.geoRouting.annotations.foo=bar",
    )
    assert default == with_subfields, "region sub-fields leaked with region.enabled=false"
    for token in ("SENTINEL_REGION", "topology.kubernetes.io/region", "region-replication"):
        assert token not in with_subfields
