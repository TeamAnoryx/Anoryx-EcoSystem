"""sentinel-mesh — operator CLI for the F-034 internal mTLS mesh (ADR-0040).

    # 1. create the mesh CA (once)
    sentinel-mesh init-ca --trust-domain sentinel.mesh --out-dir ./mesh-ca

    # 2. issue a short-lived leaf for a component
    sentinel-mesh issue --ca-dir ./mesh-ca --component gateway \\
                        --ttl-hours 24 --out-dir ./certs/gateway

    # 3. inspect / verify a leaf against the mesh CA
    sentinel-mesh inspect --cert ./certs/gateway/cert.pem
    sentinel-mesh verify  --ca ./mesh-ca/ca.pem --cert ./certs/gateway/cert.pem

    # 4. is a leaf due for rotation?
    sentinel-mesh rotation-status --cert ./certs/gateway/cert.pem

CA/leaf private keys are written 0600. In production the CA key belongs in
Vault/KMS, not on disk (CLAUDE.md #4) — this CLI is the local/dev + bootstrap
workflow. The scheduler that acts on `rotation-status` is cert-manager in
Kubernetes (docs/followups/f-034-cert-manager-wiring.md).
"""

from __future__ import annotations

import argparse
import os
import sys

from cryptography import x509

from service_mesh.ca import MeshCa
from service_mesh.exceptions import MeshError
from service_mesh.identity import ComponentIdentity
from service_mesh.rotation import evaluate
from service_mesh.verify import verify_peer


def _write(path: str, data: bytes, *, secret: bool) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
    if secret:
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass


def _cmd_init_ca(trust_domain: str, out_dir: str) -> int:
    try:
        ca = MeshCa.generate(trust_domain)
    except MeshError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    os.makedirs(out_dir, exist_ok=True)
    _write(os.path.join(out_dir, "ca.pem"), ca.cert_pem(), secret=False)
    _write(os.path.join(out_dir, "ca.key"), ca.key_pem(), secret=True)
    print(f"wrote mesh CA for trust domain {trust_domain!r} -> {out_dir}/ca.pem, {out_dir}/ca.key")
    print("KEEP ca.key SECRET (Vault/KMS in production). ca.pem is the mesh trust bundle.")
    return 0


def _cmd_issue(ca_dir: str, component: str, ttl_hours: int, out_dir: str) -> int:
    try:
        with open(os.path.join(ca_dir, "ca.key"), "rb") as fh:
            key_pem = fh.read()
        with open(os.path.join(ca_dir, "ca.pem"), "rb") as fh:
            cert_pem = fh.read()
        ca = MeshCa.load(key_pem, cert_pem)
        identity = ComponentIdentity(trust_domain=ca.trust_domain, component=component)
        cred = ca.issue(identity, ttl_hours=ttl_hours)
    except (MeshError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    os.makedirs(out_dir, exist_ok=True)
    _write(os.path.join(out_dir, "cert.pem"), cred.cert_pem, secret=False)
    _write(os.path.join(out_dir, "key.pem"), cred.key_pem, secret=True)
    _write(os.path.join(out_dir, "ca.pem"), ca.cert_pem(), secret=False)
    print(f"issued leaf for {identity.uri} (ttl {ttl_hours}h) -> {out_dir}/cert.pem")
    return 0


def _cmd_inspect(cert_path: str) -> int:
    try:
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        identity = uris[0] if uris else "(none)"
    except x509.ExtensionNotFound:
        identity = "(none)"
    print(f"identity        : {identity}")
    print(f"serial          : {cert.serial_number:x}")
    print(f"not_valid_before: {cert.not_valid_before_utc.isoformat()}")
    print(f"not_valid_after : {cert.not_valid_after_utc.isoformat()}")
    return 0


def _cmd_verify(ca_path: str, cert_path: str) -> int:
    try:
        with open(ca_path, "rb") as fh:
            ca_pem = fh.read()
        with open(cert_path, "rb") as fh:
            leaf_pem = fh.read()
        peer = verify_peer(leaf_pem, ca_pem)
    except (MeshError, OSError) as exc:
        print(f"VERIFY FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {peer.identity.uri} verified (expires {peer.not_valid_after.isoformat()})")
    return 0


def _cmd_rotation_status(cert_path: str) -> int:
    try:
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    status = evaluate(cert)
    hours = status.seconds_until_expiry / 3600.0
    print(f"state           : {status.state.value}")
    print(f"renew_at        : {status.renew_at.isoformat()}")
    print(f"expires         : {status.not_valid_after.isoformat()} ({hours:.1f}h)")
    print(f"needs_renewal   : {status.needs_renewal}")
    # Non-zero exit when renewal is due, so a cron/operator can gate on it.
    return 0 if not status.needs_renewal else 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel-mesh", description="Anoryx Sentinel internal mTLS mesh CLI (F-034)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    ic = sub.add_parser("init-ca", help="Generate the mesh CA.")
    ic.add_argument("--trust-domain", required=True)
    ic.add_argument("--out-dir", required=True)

    iss = sub.add_parser("issue", help="Issue a short-lived component leaf.")
    iss.add_argument("--ca-dir", required=True)
    iss.add_argument("--component", required=True)
    iss.add_argument("--ttl-hours", type=int, default=24)
    iss.add_argument("--out-dir", required=True)

    ins = sub.add_parser("inspect", help="Print a certificate's identity + validity.")
    ins.add_argument("--cert", required=True)

    vf = sub.add_parser("verify", help="Verify a leaf against the mesh CA.")
    vf.add_argument("--ca", required=True)
    vf.add_argument("--cert", required=True)

    rs = sub.add_parser("rotation-status", help="Report a leaf's rotation state (exit 2 if due).")
    rs.add_argument("--cert", required=True)

    args = p.parse_args(argv)
    if args.cmd == "init-ca":
        return _cmd_init_ca(args.trust_domain, args.out_dir)
    if args.cmd == "issue":
        return _cmd_issue(args.ca_dir, args.component, args.ttl_hours, args.out_dir)
    if args.cmd == "inspect":
        return _cmd_inspect(args.cert)
    if args.cmd == "verify":
        return _cmd_verify(args.ca, args.cert)
    if args.cmd == "rotation-status":
        return _cmd_rotation_status(args.cert)
    p.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
