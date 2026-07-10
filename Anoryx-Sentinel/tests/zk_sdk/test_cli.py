"""End-to-end CLI tests for sentinel-zk (F-032)."""

from __future__ import annotations

import json

from zk_sdk import cli


def test_cli_keygen_encrypt_decrypt_round_trip(tmp_path, capsys):
    key_path = tmp_path / "master.key"
    assert cli.main(["keygen", "--out", str(key_path)]) == 0
    capsys.readouterr()

    payload = {"email": "a@b.com", "note": "hi"}
    rc = cli.main(
        [
            "encrypt",
            "--key",
            str(key_path),
            "--record-id",
            "r1",
            "--index",
            "email",
            "--json",
            json.dumps(payload),
        ]
    )
    assert rc == 0
    server_dict = json.loads(capsys.readouterr().out)
    # plaintext must not be in the printed server record
    assert "a@b.com" not in json.dumps(server_dict)

    rec_path = tmp_path / "record.json"
    rec_path.write_text(json.dumps(server_dict), encoding="utf-8")

    rc = cli.main(["decrypt", "--key", str(key_path), "--record-id", "r1", "--in", str(rec_path)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out == payload


def test_cli_query_tag_matches_stored_tag(tmp_path, capsys):
    key_path = tmp_path / "master.key"
    cli.main(["keygen", "--out", str(key_path)])
    capsys.readouterr()

    cli.main(
        [
            "encrypt",
            "--key",
            str(key_path),
            "--index",
            "email",
            "--json",
            json.dumps({"email": "x@y.com"}),
        ]
    )
    stored = json.loads(capsys.readouterr().out)["index_tags"]["email"]

    cli.main(["query-tag", "--key", str(key_path), "--field", "email", "--value", "x@y.com"])
    query_tag = capsys.readouterr().out.strip()
    assert query_tag == stored


def test_cli_verify_passes_on_ciphertext_only(tmp_path, capsys):
    key_path = tmp_path / "master.key"
    cli.main(["keygen", "--out", str(key_path)])
    capsys.readouterr()
    cli.main(["encrypt", "--key", str(key_path), "--json", json.dumps({"s": "topsecret"})])
    rec_path = tmp_path / "r.json"
    rec_path.write_text(capsys.readouterr().out, encoding="utf-8")

    rc = cli.main(["verify", "--in", str(rec_path), "--probe", "topsecret"])
    assert rc == 0
    assert "ciphertext-only" in capsys.readouterr().out


def test_cli_verify_fails_when_probe_present(tmp_path, capsys):
    # a hand-crafted record that leaks plaintext must be caught by verify
    rec_path = tmp_path / "leaky.json"
    rec_path.write_text(
        json.dumps(
            {
                "scheme": "x",
                "nonce_b64": "",
                "ciphertext_b64": "",
                "index_tags": {"note": "topsecret"},
            }
        ),
        encoding="utf-8",
    )
    rc = cli.main(["verify", "--in", str(rec_path), "--probe", "topsecret"])
    assert rc == 1
