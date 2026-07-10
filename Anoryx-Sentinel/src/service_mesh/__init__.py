"""Internal service-mesh mutual-TLS identity for Sentinel components (F-034).

Sentinel is a multi-component system (gateway, orchestration emitter, bulk
workers, admin API) that also talks to sibling ecosystem products
(Anoryx-AI-Orchestrator, Delta). Every internal hop should be mutually
authenticated: the caller proves who it is AND verifies the callee, so a
compromised network position is not enough to impersonate a component.

This package provides the app-layer primitives for that:

- `identity`   — a mesh-scoped SPIFFE-style component identity
                 (`spiffe://<trust-domain>/component/<name>`), the value carried
                 in each leaf certificate's URI SAN.
- `ca`         — an INTERNAL mesh certificate authority: generate the CA, issue
                 SHORT-LIVED component leaf certs (EC P-256, serverAuth+clientAuth
                 EKU, the identity URI SAN). Not a public PKI — trust is
                 mesh-scoped.
- `verify`     — verify a peer leaf chains to the mesh CA, is in its validity
                 window, and carries a mesh identity; plus an app-layer
                 authorization allow-list (which caller identity may reach which
                 callee) that complements mTLS authentication.
- `rotation`   — short-TTL renewal logic: given a leaf, is it inside the renewal
                 window / already expired. The scheduler that acts on this is a
                 deploy concern (see honest scope below).
- `ssl_context`— build a mutual-TLS `ssl.SSLContext` (server and client side,
                 CERT_REQUIRED both directions) from a component's cert/key + the
                 mesh CA bundle.

Honest scope (ADR-0040): this ships the mTLS IDENTITY, ISSUANCE, VERIFICATION,
AUTHORIZATION and ROTATION logic as a tested library + `sentinel-mesh` operator
CLI. It is NOT a live service mesh (Istio/Linkerd) and NOT a running
cert-manager deployment — the Kubernetes cert-manager `Certificate`/`Issuer`
wiring and the sidecar enrollment are infra follow-ups
(docs/followups/f-034-cert-manager-wiring.md). In production the CA private key
lives in Vault/KMS (CLAUDE.md #4), never on disk.
"""

from __future__ import annotations

from service_mesh.identity import ComponentIdentity
from service_mesh.verify import MeshAuthorizationPolicy, VerifiedPeer

__all__ = ["ComponentIdentity", "MeshAuthorizationPolicy", "VerifiedPeer"]
