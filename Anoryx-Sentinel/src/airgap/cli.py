"""sentinel-airgap — operator CLI for air-gapped deployment (F-036, ADR-0041).

    # (issuer, online) mint a license keypair + sign a license
    sentinel-airgap keygen --priv license.key --pub license.pub
    sentinel-airgap sign-license --key license.key --in claims.json --out license.jws

    # (air-gapped install) validate the license OFFLINE
    sentinel-airgap verify-license --pub license.pub --in license.jws

    # build + verify an offline install bundle
    sentinel-airgap build-manifest --root ./bundle --files-from files.txt \\
                    --bundle-id 2026.07 --key license.key --out manifest.json
    sentinel-airgap verify-bundle --root ./bundle --in manifest.json --pub license.pub

    # lint a mirror config for internet leaks
    sentinel-airgap check-mirror --in mirror.json

`verify-license` / `verify-bundle` need only the PUBLIC key and never touch the
network. Private keys belong to the license issuer (Vault/KMS in prod); keygen's
on-disk PEM is dev/bootstrap only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from airgap.bundle import build_manifest, sign_manifest, verify_bundle
from airgap.exceptions import AirgapError
from airgap.license import sign_license, verify_license
from airgap.mirror import MirrorConfigError, validate_mirror_config
from policy.crypto import (
    PolicyKeyError,
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    private_key_to_pem,
    public_key_to_pem,
)


def _write(path: str, data: bytes, *, secret: bool) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
    if secret:
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover
            pass


def _cmd_keygen(priv: str, pub: str) -> int:
    private_key, public_key = generate_keypair()
    _write(priv, private_key_to_pem(private_key), secret=True)
    _write(pub, public_key_to_pem(public_key), secret=False)
    print(f"wrote ES256 license keypair -> {priv} (0600), {pub}")
    print("KEEP the private key SECRET (Vault/KMS in production). Ship only the public key.")
    return 0


def _cmd_sign_license(key_path: str, in_path: str, out_path: str) -> int:
    try:
        with open(key_path, "rb") as fh:
            private_key = load_private_key_pem(fh.read())
        with open(in_path, encoding="utf-8") as fh:
            claims = json.load(fh)
        token = sign_license(claims, private_key)
    except (AirgapError, PolicyKeyError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _write(out_path, token.encode("ascii"), secret=False)
    print(f"signed license -> {out_path}")
    return 0


def _cmd_verify_license(pub_path: str, in_path: str) -> int:
    try:
        with open(pub_path, "rb") as fh:
            public_key = load_public_key_pem(fh.read())
        with open(in_path, encoding="utf-8") as fh:
            token = fh.read().strip()
        lic = verify_license(token, public_key)
    except (AirgapError, PolicyKeyError, OSError, ValueError) as exc:
        print(f"LICENSE INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"OK: license {lic.license_id} for {lic.customer!r} ({lic.edition})")
    print(f"    valid {lic.not_before.isoformat()} .. {lic.expires_at.isoformat()}")
    print(f"    features={sorted(lic.features)} max_tenants={lic.max_tenants}")
    return 0


def _read_files_list(files_from: str | None, files: list[str] | None) -> list[str]:
    out = list(files or [])
    if files_from:
        with open(files_from, encoding="utf-8") as fh:
            out.extend(line.strip() for line in fh if line.strip())
    return out


def _cmd_build_manifest(
    root: str,
    files_from: str | None,
    files: list[str] | None,
    bundle_id: str,
    key_path: str | None,
    out_path: str,
) -> int:
    try:
        rel_files = _read_files_list(files_from, files)
        manifest = build_manifest(root, rel_files, bundle_id=bundle_id)
        if key_path:
            with open(key_path, "rb") as fh:
                manifest = sign_manifest(manifest, load_private_key_pem(fh.read()))
    except (AirgapError, PolicyKeyError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _write(out_path, json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"), secret=False)
    n = len(manifest["artifacts"])
    print(f"built manifest for {n} artifact(s){' (signed)' if key_path else ''} -> {out_path}")
    return 0


def _cmd_verify_bundle(root: str, in_path: str, pub_path: str | None) -> int:
    try:
        with open(in_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        public_key = None
        if pub_path:
            with open(pub_path, "rb") as fh:
                public_key = load_public_key_pem(fh.read())
        verified = verify_bundle(manifest, root, public_key=public_key)
    except (AirgapError, PolicyKeyError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"BUNDLE INVALID: {exc}", file=sys.stderr)
        return 1
    signed = " + signature" if pub_path else ""
    print(f"OK: {len(verified)} artifact(s) verified{signed}.")
    return 0


def _cmd_check_mirror(in_path: str) -> int:
    try:
        with open(in_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        hosts = validate_mirror_config(cfg)
    except (MirrorConfigError, OSError, json.JSONDecodeError) as exc:
        print(f"MIRROR CONFIG REJECTED: {exc}", file=sys.stderr)
        return 1
    print(f"OK: all {len(hosts)} mirror host(s) are internal: {sorted(set(hosts))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel-airgap", description="Anoryx Sentinel air-gapped deployment CLI (F-036)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="Generate an ES256 license keypair (dev/bootstrap).")
    kg.add_argument("--priv", required=True)
    kg.add_argument("--pub", required=True)

    sl = sub.add_parser("sign-license", help="Sign a license claims JSON (issuer).")
    sl.add_argument("--key", required=True)
    sl.add_argument("--in", required=True, dest="in_path")
    sl.add_argument("--out", required=True, dest="out_path")

    vl = sub.add_parser("verify-license", help="Verify a license OFFLINE against the public key.")
    vl.add_argument("--pub", required=True)
    vl.add_argument("--in", required=True, dest="in_path")

    bm = sub.add_parser("build-manifest", help="Build (and optionally sign) a bundle manifest.")
    bm.add_argument("--root", required=True)
    bm.add_argument("--files-from", default=None)
    bm.add_argument("--file", action="append", dest="files", default=None)
    bm.add_argument("--bundle-id", required=True)
    bm.add_argument("--key", default=None, help="Sign the manifest with this private key.")
    bm.add_argument("--out", required=True, dest="out_path")

    vb = sub.add_parser("verify-bundle", help="Verify a bundle's artifacts (and signature).")
    vb.add_argument("--root", required=True)
    vb.add_argument("--in", required=True, dest="in_path")
    vb.add_argument("--pub", default=None, help="Also verify the manifest signature.")

    cm = sub.add_parser("check-mirror", help="Lint a mirror config for public-internet hosts.")
    cm.add_argument("--in", required=True, dest="in_path")

    args = p.parse_args(argv)
    if args.cmd == "keygen":
        return _cmd_keygen(args.priv, args.pub)
    if args.cmd == "sign-license":
        return _cmd_sign_license(args.key, args.in_path, args.out_path)
    if args.cmd == "verify-license":
        return _cmd_verify_license(args.pub, args.in_path)
    if args.cmd == "build-manifest":
        return _cmd_build_manifest(
            args.root, args.files_from, args.files, args.bundle_id, args.key, args.out_path
        )
    if args.cmd == "verify-bundle":
        return _cmd_verify_bundle(args.root, args.in_path, args.pub)
    if args.cmd == "check-mirror":
        return _cmd_check_mirror(args.in_path)
    p.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
