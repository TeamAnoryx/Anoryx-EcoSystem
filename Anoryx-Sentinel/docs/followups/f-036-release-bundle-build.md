# Follow-up — F-036: offline release pipeline + license enforcement wiring

**Status:** deferred (documented, not built)
**Owner track:** platform-infra (release pipeline / mirrors) + gateway-core (license
enforcement wiring) + commercial/licensing (license issuance)
**Blocked on:** a real release pipeline + a licensing system of record.

## What F-036 shipped

F-036 (ADR-0041) shipped the offline VALIDATION/INTEGRITY toolkit in
`src/airgap/`: offline license validation (`license.py`), signed install-bundle
integrity (`bundle.py`), mirror-config lint (`mirror.py`), and the
`sentinel-airgap` CLI. It verifies bundles/licenses; it does not build them or
enforce them.

## What is deferred here, and why

### 1. Building the actual offline install bundle

F-036 verifies a bundle against a manifest; it does not produce the bundle. To
pick this up:

- A CI/release job that assembles the wheelhouse (`pip download` of the pinned
  lockfile incl. the spacy `en_core_web_lg` model that currently fails to fetch in
  sandbox CI — see the known-failures note), exports the container images
  (`docker save` / image digests), and collects the Alembic migrations + default
  config, then runs `sentinel-airgap build-manifest --key <release-key>` to
  produce the signed manifest that ships alongside.
- Store the release signing key in Vault/KMS; publish only the public key with the
  install.

### 2. Internal mirror provisioning

`mirror.py` LINTS a mirror config; it does not stand up the mirror. Deferred:
Helm/infra manifests under `infra/` for an internal PyPI mirror (devpi / bandersnatch)
and a registry mirror (Harbor / registry:2), plus the generated pip.conf /
containerd config that references them — which `check-mirror` then validates.

### 3. License enforcement at runtime

`verify_license` returns a `ValidatedLicense` (edition, `features`,
`max_tenants`), but nothing yet GATES on it. To pick this up:

- At app bootstrap, load `SENTINEL_LICENSE_PUBKEY_PATH` + the license file, call
  `verify_license`, and fail startup (fail-closed) if invalid/expired.
- Gate feature modules (e.g. HIPAA/EU-AI-Act exports, ZK SDK) on
  `license.has_feature(...)`, and enforce `max_tenants` at tenant-provisioning
  time.
- Emit a clear operator error (not a silent degrade) when the license is missing
  or expired.

This touches app startup + several feature entry points, so it is deferred to
land as one coherent change rather than piecemeal.

### 4. License issuance system

F-036's `sign-license` is a CLI convenience. A real deployment needs a licensing
system of record (who has which edition/features, expiry, renewal, revocation via
short-dating). That is a commercial-systems concern, out of scope for Sentinel's
codebase.
