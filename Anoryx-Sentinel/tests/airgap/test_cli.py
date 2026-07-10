"""sentinel-airgap CLI end-to-end (F-036, ADR-0041)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from airgap.cli import main


def _run(capsys, *argv) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_license_keygen_sign_verify_flow(tmp_path, capsys):
    priv = tmp_path / "license.key"
    pub = tmp_path / "license.pub"
    code, _, _ = _run(capsys, "keygen", "--priv", str(priv), "--pub", str(pub))
    assert code == 0
    assert oct(priv.stat().st_mode)[-3:] == "600"

    now = datetime.now(timezone.utc)
    claims = {
        "license_id": "LIC-42",
        "customer": "Beta LLC",
        "edition": "enterprise",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "features": ["hipaa"],
    }
    claims_path = tmp_path / "claims.json"
    claims_path.write_text(json.dumps(claims))
    jws = tmp_path / "license.jws"

    code, _, _ = _run(
        capsys, "sign-license", "--key", str(priv), "--in", str(claims_path), "--out", str(jws)
    )
    assert code == 0

    code, out, _ = _run(capsys, "verify-license", "--pub", str(pub), "--in", str(jws))
    assert code == 0
    assert "LIC-42" in out and "Beta LLC" in out


def test_verify_license_wrong_key_fails(tmp_path, capsys):
    priv = tmp_path / "a.key"
    pub = tmp_path / "a.pub"
    other_pub = tmp_path / "b.pub"
    _run(capsys, "keygen", "--priv", str(priv), "--pub", str(pub))
    _run(capsys, "keygen", "--priv", str(tmp_path / "b.key"), "--pub", str(other_pub))

    now = datetime.now(timezone.utc)
    claims = {
        "license_id": "LIC-1",
        "customer": "X",
        "edition": "std",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    (tmp_path / "c.json").write_text(json.dumps(claims))
    _run(
        capsys,
        "sign-license",
        "--key",
        str(priv),
        "--in",
        str(tmp_path / "c.json"),
        "--out",
        str(tmp_path / "c.jws"),
    )

    code, _, err = _run(
        capsys, "verify-license", "--pub", str(other_pub), "--in", str(tmp_path / "c.jws")
    )
    assert code == 1
    assert "LICENSE INVALID" in err


def test_bundle_build_and_verify_signed(tmp_path, capsys):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "x.whl").write_bytes(b"aaa")
    (root / "y.whl").write_bytes(b"bbb")
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    _run(capsys, "keygen", "--priv", str(priv), "--pub", str(pub))
    manifest = tmp_path / "manifest.json"

    code, _, _ = _run(
        capsys,
        "build-manifest",
        "--root",
        str(root),
        "--file",
        "x.whl",
        "--file",
        "y.whl",
        "--bundle-id",
        "2026.07",
        "--key",
        str(priv),
        "--out",
        str(manifest),
    )
    assert code == 0

    code, out, _ = _run(
        capsys, "verify-bundle", "--root", str(root), "--in", str(manifest), "--pub", str(pub)
    )
    assert code == 0
    assert "2 artifact(s) verified" in out


def test_check_mirror_rejects_public(tmp_path, capsys):
    cfg = {"internal_suffixes": [".internal"], "pip_index_url": "https://pypi.org/simple"}
    cfg_path = tmp_path / "mirror.json"
    cfg_path.write_text(json.dumps(cfg))
    code, _, err = _run(capsys, "check-mirror", "--in", str(cfg_path))
    assert code == 1
    assert "MIRROR CONFIG REJECTED" in err


def test_check_mirror_accepts_internal(tmp_path, capsys):
    cfg = {"internal_suffixes": [".internal"], "container_registries": ["registry.internal:5000"]}
    cfg_path = tmp_path / "mirror.json"
    cfg_path.write_text(json.dumps(cfg))
    code, out, _ = _run(capsys, "check-mirror", "--in", str(cfg_path))
    assert code == 0
    assert "internal" in out
