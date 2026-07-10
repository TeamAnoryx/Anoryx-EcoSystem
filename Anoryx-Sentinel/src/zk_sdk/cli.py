"""sentinel-zk — dev/operator CLI for the F-032 ZK storage SDK (ADR-0038).

    sentinel-zk keygen --out master.key
    sentinel-zk encrypt --key master.key --record-id r1 --index email \\
                        --json '{"email":"a@b.com","note":"hi"}'
    sentinel-zk decrypt --key master.key --record-id r1 --in record.json
    sentinel-zk query-tag --key master.key --field email --value a@b.com

The master key is written to / read from a LOCAL file the operator controls; it
is never transmitted. `encrypt` prints the exact ciphertext-only record a server
would store — pipe it through `verify` to confirm it contains no plaintext.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys

from zk_sdk.envelope import EncryptedRecord
from zk_sdk.exceptions import ZkSdkError
from zk_sdk.keys import generate_master_key
from zk_sdk.sdk import ZkClient


def _load_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read().strip()
    # accept raw 32 bytes or base64 of 32 bytes
    if len(raw) == 32:
        return raw
    try:
        decoded = base64.b64decode(raw)
    except Exception:
        decoded = b""
    if len(decoded) == 32:
        return decoded
    raise ZkSdkError(f"key file {path!r} does not contain a 32-byte key")


def _cmd_keygen(out: str) -> int:
    key = generate_master_key()
    with open(out, "wb") as fh:
        fh.write(base64.b64encode(key))
    try:
        import os

        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"wrote 32-byte master key (base64) -> {out}")
    print("KEEP THIS LOCAL. It never leaves the client; losing it means losing the data.")
    return 0


def _cmd_encrypt(key_path: str, record_id: str | None, index_csv: str, payload_json: str) -> int:
    try:
        key = _load_key(key_path)
        payload = json.loads(payload_json)
    except (ZkSdkError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    index_fields = [f for f in index_csv.split(",") if f.strip()]
    client = ZkClient(key)
    record = client.encrypt(payload, record_id=record_id, index_fields=index_fields)
    print(json.dumps(record.to_server_dict(), indent=2))
    return 0


def _cmd_decrypt(key_path: str, record_id: str | None, in_path: str) -> int:
    try:
        key = _load_key(key_path)
        with open(in_path, encoding="utf-8") as fh:
            record = EncryptedRecord.from_server_dict(json.load(fh))
        client = ZkClient(key)
        payload = client.decrypt(record, record_id=record_id)
    except (ZkSdkError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_query_tag(key_path: str, field: str, value: str) -> int:
    try:
        key = _load_key(key_path)
    except ZkSdkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(ZkClient(key).query_tag(field, value))
    return 0


def _cmd_verify(in_path: str, plaintext_probe: str | None) -> int:
    """Confirm a stored record dict is ciphertext-only (no plaintext/keys)."""
    try:
        with open(in_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    keys = set(data.keys())
    expected = {"scheme", "nonce_b64", "ciphertext_b64", "index_tags"}
    extraneous = keys - expected
    if extraneous:
        print(f"FAIL: record has unexpected keys (possible leak): {sorted(extraneous)}")
        return 1
    if plaintext_probe:
        blob = json.dumps(data)
        if plaintext_probe in blob:
            print(f"FAIL: probe string {plaintext_probe!r} appears in the stored record!")
            return 1
    print("OK: record is ciphertext-only (scheme/nonce/ciphertext/index_tags; no plaintext).")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel-zk", description="Anoryx ZK storage SDK CLI (F-032)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="Generate a 32-byte master key to a local file.")
    kg.add_argument("--out", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a JSON payload into a ciphertext-only record.")
    enc.add_argument("--key", required=True)
    enc.add_argument("--record-id", default=None)
    enc.add_argument("--index", default="", help="Comma-separated fields to blind-index.")
    enc.add_argument("--json", required=True, dest="payload_json")

    dec = sub.add_parser("decrypt", help="Decrypt a stored record back to its payload.")
    dec.add_argument("--key", required=True)
    dec.add_argument("--record-id", default=None)
    dec.add_argument("--in", required=True, dest="in_path")

    qt = sub.add_parser("query-tag", help="Compute the blind-index tag for field==value.")
    qt.add_argument("--key", required=True)
    qt.add_argument("--field", required=True)
    qt.add_argument("--value", required=True)

    vf = sub.add_parser("verify", help="Confirm a stored record is ciphertext-only.")
    vf.add_argument("--in", required=True, dest="in_path")
    vf.add_argument("--probe", default=None, help="Plaintext string that must NOT appear.")

    args = p.parse_args(argv)
    if args.cmd == "keygen":
        return _cmd_keygen(args.out)
    if args.cmd == "encrypt":
        return _cmd_encrypt(args.key, args.record_id, args.index, args.payload_json)
    if args.cmd == "decrypt":
        return _cmd_decrypt(args.key, args.record_id, args.in_path)
    if args.cmd == "query-tag":
        return _cmd_query_tag(args.key, args.field, args.value)
    if args.cmd == "verify":
        return _cmd_verify(args.in_path, args.probe)
    p.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
