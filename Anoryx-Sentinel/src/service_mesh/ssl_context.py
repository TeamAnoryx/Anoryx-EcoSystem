"""Mutual-TLS ssl.SSLContext builders (F-034, ADR-0040).

Turn a component's on-disk mesh credentials (leaf cert + private key + the mesh
CA bundle) into an `ssl.SSLContext` that enforces MUTUAL TLS:

- server side: `verify_mode = CERT_REQUIRED` — the server demands and verifies a
  client certificate, so an unauthenticated client cannot connect.
- client side: `check_hostname = False` + `CERT_REQUIRED` against the mesh CA —
  we authenticate the peer by its mesh IDENTITY (URI SAN, checked in `verify`),
  NOT by DNS hostname, because mesh peers are reached by service name / pod IP,
  not by a hostname matching the cert CN. Hostname checking is therefore
  disabled here and identity is enforced at the app layer via `verify_peer`.

Both directions load ONLY the mesh CA as trust anchor (`load_verify_locations`),
so only mesh-issued certs are accepted. Fail-closed: missing/unreadable files
raise (ssl / OSError propagate) rather than silently producing a permissive
context.

`ssl.SSLContext.load_cert_chain` requires filesystem paths (it does not accept
PEM bytes), so these builders take paths. The CLI writes issued credentials to
disk with restrictive permissions; in Kubernetes the paths are a mounted
cert-manager secret.
"""

from __future__ import annotations

import ssl


def server_context(*, cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """Build a server-side mTLS context that REQUIRES a mesh client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED  # demand + verify the peer's client cert
    return ctx


def client_context(*, cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """Build a client-side mTLS context that presents our leaf and verifies the peer.

    Hostname checking is disabled by design (see module docstring): mesh peer
    identity is the URI SAN, enforced by `verify_peer`, not the DNS name. The
    context still requires the peer cert to chain to the mesh CA.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=ca_path)
    ctx.check_hostname = False  # identity is the URI SAN, not the hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
