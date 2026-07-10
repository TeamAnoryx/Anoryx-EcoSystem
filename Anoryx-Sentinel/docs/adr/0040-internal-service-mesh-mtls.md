# ADR-0040 — Internal Service Mesh Auth (mTLS) (F-034)

- Status: Accepted (implemented)
- Date: 2026-07-10
- Builds on: F-010 (deployable Sentinel — the components this mesh authenticates
  between), the `cryptography` dependency already used for AES-256-GCM
  (F-014/F-032/F-033), ADR-0038 (F-032, the same "honest threat model" framing).
- Scope: `src/service_mesh/` (new) + `sentinel-mesh` CLI. **No `contracts/`
  change, no HTTP surface.**

## Context

Roadmap F-034: "mTLS between Sentinel components + ecosystem products,
cert-manager, auto-rotation. Depends on F-010." Sentinel is multi-component
(gateway, orchestration emitter, bulk workers, admin API) and talks to sibling
products (Anoryx-AI-Orchestrator, Delta). Every internal hop should be *mutually*
authenticated so that a network foothold is not enough to impersonate a
component or eavesdrop.

`src/orchestration/__init__.py` has long noted an "internal mTLS channel" as a
future deliverable — this is it.

## Decision — an app-layer mTLS identity toolkit, not a running mesh

F-034 ships the *identity and verification primitives* for a mutual-TLS mesh as a
tested library + operator CLI. It deliberately does NOT ship a running service
mesh (Istio/Linkerd) or a live cert-manager deployment — those are
infrastructure that belongs in `infra/helm` and a cluster, gated behind a real
deployment (see honest scope + follow-up).

### Modules (`src/service_mesh/`)

- `identity.py` — `ComponentIdentity`, a SPIFFE-style
  `spiffe://<trust-domain>/component/<name>` URI. We use the SPIFFE shape so a
  later migration onto SPIRE/Istio does not require re-minting identities.
- `ca.py` — `MeshCa`: an INTERNAL mesh CA (EC P-256). Generates the CA and issues
  SHORT-LIVED leaves (default 24h) carrying the identity as a **URI SAN** (the
  only identity verifiers trust — no CN reliance), with EKU serverAuth +
  clientAuth (a component is both). Fail-closed key loading: a key that does not
  match its cert, or a non-CA cert, raises.
- `verify.py` — `verify_peer()` (AUTHENTICATION: leaf is CA-signed, issued by the
  CA, inside its validity window, carries one in-domain mesh identity) and
  `MeshAuthorizationPolicy` (AUTHORIZATION: a default-deny allow-list of
  caller→callee components — mTLS says *who*, the policy says *may they call
  this*).
- `rotation.py` — `evaluate()` classifies a leaf FRESH / DUE / EXPIRED using the
  standard "renew at 2/3 of TTL" heuristic, so a scheduler knows when to re-issue.
- `ssl_context.py` — builds server-side and client-side `ssl.SSLContext`s that
  enforce mutual TLS (`CERT_REQUIRED` both directions) against the mesh CA.
  Client-side hostname checking is OFF by design: mesh peers are reached by
  service name / pod IP, and identity is the URI SAN (enforced by `verify_peer`),
  not a DNS hostname.
- `cli.py` — `sentinel-mesh init-ca | issue | inspect | verify | rotation-status`.
  `rotation-status` exits non-zero when a leaf is due, so a cron/operator can gate
  on it.

### Why a small explicit verifier

The mesh CA signs leaves directly (BasicConstraints path-length 0), so the trust
chain is always leaf → CA. `verify_peer` checks exactly that one hop rather than
pulling in a general path builder — smaller, auditable, and it is the
authoritative app-layer re-check that authorization decisions read. TLS-layer
verification still runs in `ssl_context` (`CERT_REQUIRED`).

## Honest scope / limitations

- **Toolkit, not a live mesh.** This is the identity/issuance/verification/
  rotation logic + CLI. Istio/Linkerd, sidecar injection, and a running
  cert-manager `Issuer`/`Certificate` are NOT included — see
  `docs/followups/f-034-cert-manager-wiring.md`.
- **Internal CA, mesh-scoped trust.** Not a public PKI. Trust is whoever holds
  the mesh CA cert; there is no external anchor. Cross-mesh (Sentinel ↔ Delta ↔
  Orchestrator) federation would need a shared/federated trust domain, deferred.
- **CA key is a secret.** The CLI writes `ca.key`/`key.pem` 0600 for local/dev
  and bootstrap. In production the CA private key MUST live in Vault/KMS
  (CLAUDE.md #4), never on disk; leaf keys should be issued to a mounted secret.
- **No revocation list.** Revocation is achieved by short TTL + rotation, not a
  CRL/OCSP. A compromised leaf is valid only for its short remaining window. A
  CRL/OCSP responder is out of scope.
- **No wiring into the live request path yet.** `ssl_context` is ready for the
  gateway / orchestration emitter to adopt, but flipping existing internal HTTP
  clients/servers onto these contexts is a separate integration (touches
  `src/gateway/`, `src/orchestration/`) deferred to the cert-manager follow-up so
  it lands with real deploy config.
