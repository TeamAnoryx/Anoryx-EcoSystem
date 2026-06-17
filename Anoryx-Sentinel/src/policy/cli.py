"""sentinel-cli — operator CLI for F-008 policy intake (ADR-0009 §11).

Internal-only (no HTTP — R1). `push` loads the SAME intake_policy() the gateway
uses and calls it directly with the signed record. Exposed as the `sentinel-cli`
console entry point in pyproject.toml.

    sentinel-cli policy keygen --out private.pem --pub-out public.pem
    sentinel-cli policy push   --file policy.json --key private.pem

`keygen` produces a dev/test ECDSA P-256 keypair (PEM). Production signing keys
MUST be HSM-managed (key rotation / HSM is deferred — ADR-0009 §12). `push` signs
the record's scope claims with the private key and runs intake; intake verifies
against the public key configured at POLICY_SIGNING_PUBKEY_PATH, so a push is only
Accepted when that public key matches the signing private key.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path

from policy import crypto
from policy.intake import intake_policy
from policy.results import Accepted


def _cmd_keygen(out: str, pub_out: str) -> int:
    private_key, public_key = crypto.generate_keypair()
    Path(out).write_bytes(crypto.private_key_to_pem(private_key))
    Path(pub_out).write_bytes(crypto.public_key_to_pem(public_key))
    with contextlib.suppress(OSError):
        os.chmod(out, 0o600)  # best-effort: restrict private-key read perms (POSIX)
    if sys.platform == "win32":
        print(f"WARNING: file permissions are not enforced on Windows — protect {out} manually.")
    print(f"wrote private key -> {out}")
    print(f"wrote public  key -> {pub_out}")
    print("NOTE: dev/test keypair only. Production keys MUST be HSM-managed.")
    return 0


def _cmd_push(file: str, key: str) -> int:
    try:
        record = json.loads(Path(file).read_text(encoding="utf-8"))
        private_key = crypto.load_private_key_pem(Path(key).read_bytes())
        signed = crypto.sign_policy_record(record, private_key)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: could not load/sign the record: {exc}", file=sys.stderr)
        return 1

    result = asyncio.run(intake_policy(signed))
    print(f"intake result: {type(result).__name__}")
    if isinstance(result, Accepted):
        print(
            f"  policy_id={result.policy_id} "
            f"version={result.policy_version} type={result.policy_type}"
        )
        return 0
    print(f"  rejected: {getattr(result, 'detail', '')}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-cli",
        description="Anoryx Sentinel operator CLI (F-008 policy intake).",
    )
    groups = parser.add_subparsers(dest="group", required=True)
    policy_p = groups.add_parser("policy", help="Policy intake operations")
    cmds = policy_p.add_subparsers(dest="cmd", required=True)

    kg = cmds.add_parser("keygen", help="Generate a dev/test ECDSA P-256 keypair (PEM).")
    kg.add_argument("--out", required=True, help="Path to write the PKCS#8 private key PEM.")
    kg.add_argument("--pub-out", required=True, help="Path to write the SPKI public key PEM.")

    ph = cmds.add_parser("push", help="Sign a policy record and run intake.")
    ph.add_argument("--file", required=True, help="Path to the policy JSON record to sign + push.")
    ph.add_argument("--key", required=True, help="Path to the ECDSA P-256 private key PEM.")

    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        return _cmd_keygen(args.out, args.pub_out)
    if args.cmd == "push":
        return _cmd_push(args.file, args.key)
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
