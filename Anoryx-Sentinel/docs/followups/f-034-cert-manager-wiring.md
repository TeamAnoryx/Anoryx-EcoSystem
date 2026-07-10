# Follow-up — F-034: cert-manager wiring + live-path mTLS adoption

**Status:** deferred (documented, not built)
**Owner track:** platform-infra (CRDs/Helm) + gateway-core / orchestration-hooks
(live-path adoption)
**Blocked on:** a real Kubernetes deployment target with cert-manager installed.

## What F-034 shipped

F-034 (ADR-0040) shipped the app-layer mTLS toolkit in `src/service_mesh/`: a
mesh CA + short-lived leaf issuance (`ca.py`), peer authentication +
authorization allow-list (`verify.py`), rotation classification (`rotation.py`),
mutual-TLS `ssl.SSLContext` builders (`ssl_context.py`), and the `sentinel-mesh`
operator CLI. It is a library, not a running mesh.

## What is deferred here, and why

### 1. cert-manager `Issuer` / `Certificate` CRDs

In production the CA and leaves should be managed by cert-manager, not the CLI:

- Model the mesh CA as a cert-manager `Issuer` (or a CA `Certificate` backing a
  `CA` issuer). The CA private key belongs in Vault/KMS — use the
  cert-manager-vault issuer or an external-secrets-synced secret, NOT an on-disk
  `ca.key` (ADR-0040 honest scope, CLAUDE.md #4).
- One `Certificate` per component, `duration: 24h`, `renewBefore: 8h` (matching
  the 2/3-of-TTL renewal heuristic in `rotation.py`), `uris:` set to the
  component's `spiffe://…` identity so the issued leaf matches what `verify_peer`
  expects.

**To pick this up:** add the CRD manifests under `infra/helm` (currently just a
`.gitkeep`), templated per component, plus a values block for the trust domain
and per-component `uris`.

### 2. Adopting the mTLS contexts on the live path

`ssl_context.server_context()` / `client_context()` are ready but not yet wired
into running components. Adoption means:

- Gateway / admin API servers: serve internal endpoints under `server_context`
  (mounted cert-manager secret paths) so peers must present a mesh leaf.
- Orchestration emitter + any internal HTTP client: dial peers with
  `client_context`, then call `verify_peer` on the negotiated peer cert and
  `MeshAuthorizationPolicy.enforce(caller, callee)` before trusting the call.
- Load the `MeshAuthorizationPolicy` allow-list from config (which component may
  call which) rather than hard-coding it.

This touches `src/gateway/` and `src/orchestration/`, so it is deferred to land
together with the deploy config (otherwise the contexts would reference secret
paths that don't exist yet).

### 3. Cross-product federation (Sentinel ↔ Orchestrator ↔ Delta)

F-034's trust domain is a single mesh. Mutual TLS *between products* needs a
shared or federated trust domain (a common root, or a SPIFFE trust-bundle
exchange). That is an ecosystem-level decision co-owned with the Orchestrator
track (O-001 already names "mTLS between products") and is deferred until those
products deploy.

### 4. Revocation

F-034 relies on short TTL + rotation instead of a CRL/OCSP. If a use case needs
sub-TTL revocation (immediate kill of a specific leaf), add an OCSP responder or
a short-lived deny-list checked in `verify_peer`. Documented as an option, not
built.
