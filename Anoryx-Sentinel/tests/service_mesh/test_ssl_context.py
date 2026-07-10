"""Mutual-TLS SSLContext builders (F-034, ADR-0040).

Confirms the built contexts enforce mutual auth (CERT_REQUIRED both directions)
and that a real client<->server mTLS handshake over the mesh CA succeeds while an
un-carded client is rejected.
"""

from __future__ import annotations

import socket
import ssl
import threading

from service_mesh.ca import MeshCa
from service_mesh.identity import ComponentIdentity
from service_mesh.ssl_context import client_context, server_context

DOMAIN = "sentinel.mesh"


def _issue(tmp_path, ca: MeshCa, component: str, subdir: str) -> dict[str, str]:
    d = tmp_path / subdir
    d.mkdir()
    cred = ca.issue(ComponentIdentity(trust_domain=DOMAIN, component=component))
    (d / "cert.pem").write_bytes(cred.cert_pem)
    (d / "key.pem").write_bytes(cred.key_pem)
    ca_path = d / "ca.pem"
    ca_path.write_bytes(ca.cert_pem())
    return {
        "cert_path": str(d / "cert.pem"),
        "key_path": str(d / "key.pem"),
        "ca_path": str(ca_path),
    }


def test_server_context_requires_client_cert(tmp_path):
    ca = MeshCa.generate(DOMAIN)
    paths = _issue(tmp_path, ca, "gateway", "gw")
    ctx = server_context(**paths)
    assert ctx.verify_mode is ssl.CERT_REQUIRED


def test_client_context_verifies_peer_not_hostname(tmp_path):
    ca = MeshCa.generate(DOMAIN)
    paths = _issue(tmp_path, ca, "orchestration-emitter", "oe")
    ctx = client_context(**paths)
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is False


def test_mutual_tls_handshake_succeeds(tmp_path):
    """A full mesh mTLS handshake between two mesh components completes."""
    ca = MeshCa.generate(DOMAIN)
    server_paths = _issue(tmp_path, ca, "admin-api", "srv")
    client_paths = _issue(tmp_path, ca, "gateway", "cli")

    s_ctx = server_context(**server_paths)
    c_ctx = client_context(**client_paths)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    result: dict[str, object] = {}

    def _serve():
        conn, _ = lsock.accept()
        try:
            with s_ctx.wrap_socket(conn, server_side=True) as tls:
                result["peer_cert"] = tls.getpeercert()
        except ssl.SSLError as exc:  # pragma: no cover - failure path
            result["error"] = str(exc)

    t = threading.Thread(target=_serve)
    t.start()
    try:
        raw = socket.create_connection(("127.0.0.1", port))
        with c_ctx.wrap_socket(raw, server_hostname=None) as tls:
            tls.do_handshake()
    finally:
        t.join(timeout=5)
        lsock.close()

    assert "error" not in result
    # The server received and verified the client's mesh leaf.
    assert result.get("peer_cert") is not None


def test_mutual_tls_rejects_client_without_cert(tmp_path):
    """A plain (non-mTLS) client is rejected by the mesh server context."""
    ca = MeshCa.generate(DOMAIN)
    server_paths = _issue(tmp_path, ca, "admin-api", "srv")
    s_ctx = server_context(**server_paths)

    # Plain client context that does NOT verify and presents no cert.
    plain = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    plain.check_hostname = False
    plain.verify_mode = ssl.CERT_NONE

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    result: dict[str, object] = {}

    def _serve():
        conn, _ = lsock.accept()
        try:
            with s_ctx.wrap_socket(conn, server_side=True):
                result["ok"] = True
        except ssl.SSLError as exc:
            result["error"] = str(exc)

    t = threading.Thread(target=_serve)
    t.start()
    try:
        raw = socket.create_connection(("127.0.0.1", port))
        try:
            with plain.wrap_socket(raw, server_hostname="admin-api"):
                pass
        except ssl.SSLError:
            pass
    finally:
        t.join(timeout=5)
        lsock.close()

    # The server rejected the certless client (no successful session).
    assert result.get("ok") is not True
    assert "error" in result
