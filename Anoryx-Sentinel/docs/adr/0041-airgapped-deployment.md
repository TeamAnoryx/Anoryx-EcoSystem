# ADR-0041 — Self-Hosted / Air-Gapped Enterprise Deployment (F-036)

- Status: Accepted (implemented)
- Date: 2026-07-10
- Builds on: F-008 (`policy/crypto.py` — the ES256 compact-JWS signing scheme this
  reuses verbatim for licenses and bundle manifests), F-010 (deployable Sentinel),
  F-027 (secret handling — the license/signing private key is a deploy-injected
  secret).
- Scope: `src/airgap/` (new) + `sentinel-airgap` CLI. **No `contracts/` change, no
  HTTP surface.**

## Context

Roadmap F-036: "Air-gapped (no internet): offline install packages, internal
mirrors, offline license validation. Depends on F-010, F-027." Some enterprises
run Sentinel with NO outbound internet. Three things that normally assume
connectivity must work offline: license validation (no phone-home), install
artifact delivery (no PyPI/registry pull), and mirror configuration (nothing may
silently reach the internet).

## Decision — offline validation/integrity primitives + CLI

F-036 ships the three offline primitives as a tested library + operator CLI. It
does NOT build the actual release wheelhouse/registry mirror or ship a specific
customer license — those are release-engineering + commercial concerns (see
follow-up).

### Modules (`src/airgap/`)

- `license.py` — OFFLINE license validation. A license is a signed claim set
  (`license_id, customer, edition, issued_at, not_before, expires_at`, optional
  `features`, `max_tenants`) signed with **the exact ES256 compact-JWS scheme from
  F-008** (`policy.crypto`) — no new/hand-rolled crypto (R3), same
  algorithm-confusion defence. The deployed Sentinel ships only the PUBLIC key
  (`SENTINEL_LICENSE_PUBKEY_PATH`, fail-closed if unset) and validates signature +
  validity window locally. Zero network.
- `bundle.py` — OFFLINE install-bundle integrity. `build_manifest` records a
  SHA-256 per artifact; `sign_manifest` signs the canonical manifest digest
  (single-signature trust root); `verify_bundle` recomputes every digest and
  checks the signature. Fail-closed on any mismatch/missing file/bad signature.
- `mirror.py` — OFFLINE mirror-config lint. `validate_mirror_config` rejects any
  pip index / container registry host that is not internal (a private/loopback IP
  or an allow-listed internal suffix), and hard-rejects known public hosts
  (pypi.org, ghcr.io, docker.io, …). A config lint, not a running mirror.
- `cli.py` — `sentinel-airgap keygen | sign-license | verify-license |
  build-manifest | verify-bundle | check-mirror`. `verify-*` need only the public
  key and never touch the network.

### Why reuse `policy.crypto`

A license and a signed policy are the same shape of problem: a signed,
tamper-evident claim set verified by a public key. Reusing F-008's vetted ES256
implementation (with its `alg` pinning) keeps the crypto surface small and avoids
a second signing format to audit.

## Honest scope / limitations

- **Validation toolkit, not the release pipeline.** F-036 verifies bundles and
  licenses; it does NOT build the offline wheelhouse, mirror the container
  registry, or generate customer licenses. Those live in release-engineering
  (`infra/`) and the commercial/licensing system — see
  `docs/followups/f-036-release-bundle-build.md`.
- **License enforcement wiring is out of scope here.** `verify_license` returns a
  `ValidatedLicense` (edition, features, max_tenants); actually GATING features /
  tenant counts on it at startup/runtime is a separate integration (touches app
  bootstrap) deferred to the follow-up. F-036 provides the honest validator; it
  does not yet turn the gateway off when the license is invalid.
- **Signing key is a secret.** The license/manifest private key belongs in
  Vault/KMS (CLAUDE.md #4); `keygen`'s on-disk PEM is dev/bootstrap only. The
  deployed install holds only the public key.
- **Mirror lint reasons about config, not live traffic.** It confirms the config
  names only internal hosts; it cannot prove the network is truly air-gapped
  (that is an infra/firewall control). It catches the common "leftover public
  fallback" mistake, not a deliberately hostile config.
- **No revocation.** A license is valid for its signed window; there is no CRL /
  online revocation (by definition — the install is offline). Short-dated
  licenses + re-issue are the revocation story.
