"""F-024 disaster-recovery backup CronJob chart tests (ADR-0030).

Two layers, mirroring test_multiregion.py:

* Parse-only (no `helm` needed): backup is OFF by default, every backup
  template is gated on backup.enabled, and the Dockerfile's PGDG install adds
  no destructive SQL / secret material.
* helm-gated (skipped where `helm` is absent): the default render has zero
  backup resources (byte-identical to the chart before F-024), enabling
  backup renders exactly the CronJob + PVC (for the local sink), and the s3
  sink renders no PVC and pulls creds from the env Secret rather than a
  literal value.
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
_CRONJOB = _TEMPLATES / "backup-cronjob.yaml"
_PVC = _TEMPLATES / "backup-pvc.yaml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _noncomment(path: Path) -> str:
    return "\n".join(ln for ln in _text(path).splitlines() if not ln.lstrip().startswith("#"))


# --------------------------------------------------------------------------- #
# Parse-only — run everywhere (no helm binary).                               #
# --------------------------------------------------------------------------- #
def test_backup_disabled_by_default():
    values = yaml.safe_load(_text(_VALUES))
    backup = values["backup"]
    assert backup["enabled"] is False, "backup MUST default to disabled"
    assert backup["sink"] == "local"
    assert backup["retentionDays"] > 0


def test_cronjob_and_pvc_gated_on_backup_enabled():
    for tpl in (_CRONJOB, _PVC):
        first_line = _text(tpl).lstrip().splitlines()[0]
        assert ".Values.backup.enabled" in first_line, f"{tpl.name} must gate on backup.enabled"


def test_pvc_additionally_gated_on_local_sink():
    first_line = _text(_PVC).lstrip().splitlines()[0]
    assert 'eq .Values.backup.sink "local"' in first_line


def test_restore_is_not_wired_into_any_template():
    """Restore must NEVER be scheduled/automated (ADR-0030 §3) — no template
    invokes `sentinel-dr restore` anywhere in the chart."""
    for tpl in _TEMPLATES.glob("*.yaml"):
        collapsed = _text(tpl).replace(" ", "").replace("\n", "")
        assert '"sentinel-dr","restore"' not in collapsed, f"{tpl.name} must not invoke restore"


def test_cronjob_never_embeds_password_literal():
    body = _noncomment(_CRONJOB)
    assert "PGPASSWORD" not in body  # PGPASSWORD is set by pg_url.py at subprocess-call time
    assert "sentinel.pgEnv" in body, "DATABASE_URL must be assembled via the shared pgEnv helper"


def test_dockerfile_pgdg_install_has_no_secret_material():
    dockerfile = _text(_SENTINEL_ROOT / "Dockerfile")
    assert "postgresql-client-16" in dockerfile
    assert "password" not in dockerfile.lower()


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


def _render_result(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [_HELM, "template", "t", str(_CHART), *args], capture_output=True, text=True
    )


def _backup_pvcs(docs: list[dict]) -> list[dict]:
    return [
        d
        for d in docs
        if d["kind"] == "PersistentVolumeClaim" and "-backup" in d["metadata"]["name"]
    ]


@helm_only
def test_default_render_has_no_backup_resources():
    out = _template()
    assert "-backup" not in out
    assert "CronJob" not in out
    assert "sentinel-dr" not in out


@helm_only
def test_enabling_backup_renders_cronjob_and_local_pvc():
    out = _template("--set", "backup.enabled=true")
    docs = [d for d in yaml.safe_load_all(out) if d]

    cronjobs = [d for d in docs if d["kind"] == "CronJob"]
    assert len(cronjobs) == 1
    cj = cronjobs[0]
    assert cj["spec"]["schedule"] == "0 3 * * *"
    containers = cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    assert containers[0]["args"] == ["sentinel-dr", "backup"]
    assert containers[0]["command"] == ["/usr/local/bin/docker-entrypoint.sh"]

    pvcs = _backup_pvcs(docs)
    assert len(pvcs) == 1

    env_names = {e["name"] for e in containers[0]["env"]}
    assert "DR_BACKUP_SINK" in env_names
    assert "DR_LOCAL_BACKUP_DIR" in env_names
    assert "DR_S3_ACCESS_KEY" not in env_names  # local sink: no S3 creds emitted


@helm_only
def test_s3_sink_renders_no_pvc_and_pulls_creds_from_secret():
    out = _template(
        "--set",
        "backup.enabled=true",
        "--set",
        "backup.sink=s3",
        "--set",
        "createEnvSecret=true",
        "--set",
        "secretData.DR_S3_ACCESS_KEY=ak",
        "--set",
        "secretData.DR_S3_SECRET_KEY=sk",
    )
    docs = [d for d in yaml.safe_load_all(out) if d]

    pvcs = _backup_pvcs(docs)
    assert pvcs == [], "s3 sink must not render the local backup PVC"

    cronjob = next(d for d in docs if d["kind"] == "CronJob")
    container = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    env_by_name = {e["name"]: e for e in container["env"]}
    assert env_by_name["DR_BACKUP_SINK"]["value"] == "s3"
    access_key_env = env_by_name["DR_S3_ACCESS_KEY"]
    assert "valueFrom" in access_key_env, "S3 access key must come from a Secret, never a literal"
    assert "value" not in access_key_env


@helm_only
def test_cronjob_history_limits_and_concurrency_are_set():
    out = _template("--set", "backup.enabled=true")
    docs = [d for d in yaml.safe_load_all(out) if d]
    cj = next(d for d in docs if d["kind"] == "CronJob")
    assert cj["spec"]["concurrencyPolicy"] == "Forbid"
    assert cj["spec"]["successfulJobsHistoryLimit"] >= 1
    assert cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]["restartPolicy"] == "Never"


@helm_only
def test_helm_lint_passes_with_backup_enabled():
    r = subprocess.run(  # noqa: S603
        [_HELM, "lint", str(_CHART), "--set", "backup.enabled=true"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "0 chart(s) failed" in r.stdout
