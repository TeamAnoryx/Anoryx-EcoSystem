"""sentinel-cli tests (ADR-0009 §11). keygen is real; push mocks intake_policy
so no DB write / verifying-key env is needed — we assert the CLI SIGNS correctly
and wires the typed result to the exit code.
"""

from __future__ import annotations

import json
import uuid

from policy import cli, crypto
from policy.results import Accepted, RejectedSignature


def _record() -> dict:
    return {
        "policy_type": "budget_limit",
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": "2026-06-17T00:00:00Z",
        "period": "daily",
        "scope": "tenant",
        "max_tokens_per_period": 100000,
    }


def test_keygen_writes_loadable_keypair(tmp_path):
    priv_p = tmp_path / "priv.pem"
    pub_p = tmp_path / "pub.pem"
    rc = cli.main(["policy", "keygen", "--out", str(priv_p), "--pub-out", str(pub_p)])
    assert rc == 0
    priv = crypto.load_private_key_pem(priv_p.read_bytes())
    pub = crypto.load_public_key_pem(pub_p.read_bytes())
    # The keypair round-trips a sign + verify.
    token = crypto.sign_claims({"x": "y"}, priv)
    assert crypto.verify_compact_jws(token, pub) == {"x": "y"}


def test_push_signs_and_invokes_intake(tmp_path, monkeypatch, capsys):
    priv, pub = crypto.generate_keypair()
    key_p = tmp_path / "priv.pem"
    key_p.write_bytes(crypto.private_key_to_pem(priv))
    rec = _record()
    file_p = tmp_path / "policy.json"
    file_p.write_text(json.dumps(rec))

    captured: dict = {}

    async def _fake_intake(signed, *, session=None):
        captured["signed"] = signed
        return Accepted(signed["policy_id"], signed["policy_version"], signed["policy_type"])

    monkeypatch.setattr(cli, "intake_policy", _fake_intake)
    rc = cli.main(["policy", "push", "--file", str(file_p), "--key", str(key_p)])

    assert rc == 0
    signed = captured["signed"]
    # The CLI attached a compact-JWS that verifies under the matching public key,
    # and the signed scope claims equal the record's IDs.
    claims = crypto.verify_compact_jws(signed["signature"], pub)
    assert claims["policy_id"] == rec["policy_id"]
    assert claims["policy_type"] == "budget_limit"
    assert "Accepted" in capsys.readouterr().out


def test_push_rejected_returns_nonzero(tmp_path, monkeypatch):
    priv, _ = crypto.generate_keypair()
    key_p = tmp_path / "priv.pem"
    key_p.write_bytes(crypto.private_key_to_pem(priv))
    file_p = tmp_path / "policy.json"
    file_p.write_text(json.dumps(_record()))

    async def _fake_intake(signed, *, session=None):
        return RejectedSignature()

    monkeypatch.setattr(cli, "intake_policy", _fake_intake)
    rc = cli.main(["policy", "push", "--file", str(file_p), "--key", str(key_p)])
    assert rc == 1


def test_push_bad_json_returns_nonzero(tmp_path):
    priv, _ = crypto.generate_keypair()
    key_p = tmp_path / "priv.pem"
    key_p.write_bytes(crypto.private_key_to_pem(priv))
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = cli.main(["policy", "push", "--file", str(bad), "--key", str(key_p)])
    assert rc == 1
