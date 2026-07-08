# ADR-0033 — Provider Key Vaulting (F-027)

- Status: Accepted (implemented)
- Date: 2026-07-08
- Builds on: ADR-0008 (F-006 multi-provider router — the
  `GatewaySettings`/`ProviderRegistry`/adapter shape this ADR extends, not
  replaces), ADR-0009 (F-008 `secret_box.py` — the closest existing
  encrypt-at-rest pattern, referenced but not reused directly since the
  vaulted material here never touches the DB), ADR-0002 (virtual API keys —
  a DIFFERENT thing from provider keys; see "Not in scope" below).
- Scope: `src/gateway/keyvault/` (new), `src/gateway/config.py`,
  `src/gateway/router/registry.py`, `src/gateway/router/providers/
  {anthropic,bedrock}_provider.py`, `src/gateway/main.py`. **No `contracts/`
  change** — this is internal plumbing, not a new HTTP surface.

## Context

Roadmap F-027: "Vault/KMS for upstream provider keys (currently env-var).
Runtime fetch + rotation." Research (see conversation history) confirmed:

- Anthropic/Bedrock keys are read once, at `ProviderRegistry.init()`
  (`gateway/main.py::_lifespan`), from `GatewaySettings` env fields, and
  baked into the adapter's constructor. Rotating a key today requires a
  process restart. OpenAI has no key handling at all yet (`OpenAiAdapter`
  passes `upstream_api_key=None` — a pre-existing Phase-0 gap, not
  something this ADR fixes; see "Not in scope").
- No Vault/KMS SDK integration exists anywhere in the codebase — only
  aspirational comments ("Vault/KMS-injected at deploy," CLAUDE.md
  non-negotiable #4) describing env-var injection as a DEPLOY-TIME
  convention, not a runtime client integration.
- No DB table stores provider credentials, and none should — keeping key
  material out of Postgres entirely (no migration, no RLS table) is a
  strictly safer default than adding one, so F-027 doesn't.
- Unlike F-026, this feature needs **no new HTTP endpoint** and **no
  `contracts/` change** — it's an internal registry/adapter concern. The
  `ANORYX_ACTIVE_AGENT`/api-architect gap that shaped F-025/F-026 doesn't
  apply here.

## Decision

### Pluggable `ProviderKeySource` (`src/gateway/keyvault/`)

`base.py` defines `ProviderKeySource.fetch_credentials(provider) ->
ProviderCredentials` (async, fail-closed — `KeyNotConfigured` or
`KeyFetchError`, never a silent stale/partial result). Three backends:

- `env_source.py` — reads the SAME `GatewaySettings` fields
  `registry.py` already read directly. This is the **default**
  (`keyvault_backend="env"`), so a deployment that never touches F-027
  config sees byte-identical behavior to before this feature — proven by
  the existing `tests/gateway/router/test_registry.py` suite passing
  unchanged, plus a `create_app()` + `TestClient` smoke test showing
  `app.state.keyvault_refresh_task is None` on the env backend (no fetch,
  no task, zero added runtime cost).
- `vault_source.py` — HashiCorp Vault KV-v2, reads
  `secret/data/sentinel/providers/{provider}`. `hvac` is LAZY-imported
  (ships in the new `[vault]` extra) so the slim image / any
  `keyvault_backend="env"` deploy never needs it installed.
- `kms_source.py` — AWS KMS envelope decryption: an operator runs
  `aws kms encrypt` on the real credential (a bare string for Anthropic, a
  small JSON object for Bedrock) once, stores the base64 ciphertext in an
  env var (`SENTINEL_KMS_CIPHERTEXT_ANTHROPIC` / `_BEDROCK`), and the
  running gateway calls `kms:Decrypt` at fetch time — the plaintext key
  never touches disk or the DB, only process memory. `boto3` is
  LAZY-imported (new `[kms]` extra, same discipline as `[bedrock]`/`[dr-s3]`).

Both `vault_source.py` and `kms_source.py` take an injectable `client` —
the full unit-test suite (`tests/gateway/keyvault/`) never touches a live
Vault server or AWS, mirroring `mcp_gateway/url_guard.py`'s injected-
resolver discipline.

### Runtime fetch + rotation = TTL cache, not push-based

`cache.py::CachedKeySource` wraps any backend with a per-provider TTL
cache (default 300s, `keyvault_cache_ttl_seconds`) + an `asyncio.Lock` per
provider (no thundering herd on a cold cache under concurrent requests).
**This is the honest framing of "rotation" here: BOUNDED-LAG, not
instant-push.** An operator rotating a secret in Vault/KMS sees it land in
the live gateway within one TTL window (default ≤5 min), automatically,
no restart — proven end-to-end in this session's manual smoke test (a fake
Vault client returning an incrementing fake key; the adapter's live
`_api_key` attribute changed value across two refresh cycles while the
app was serving `/health`). An instant-push design (an admin endpoint the
operator calls to force every live gateway pod to refresh NOW) would need
a new `contracts/openapi.yaml` route — same gap as F-025/F-026, out of
scope, noted in the followup doc for when that gap closes.

### Wiring — additive, not a rewrite (`registry.py`, `main.py`)

`ProviderRegistry.init()` is **completely unchanged** — same signature,
same fail-closed `configured_providers()` gate, same adapter construction.
`refresh_credentials(key_source, *, strict)` is a NEW method:
`AnthropicAdapter._headers()` and `BedrockAdapter._client_cm()` already
read `self._api_key` / `self._region` etc. FRESH on every call (not cached
into a header dict at construction) — so adding `set_api_key()` /
`set_credentials()` mutator methods and calling them from
`refresh_credentials()` swaps the live credential in place, with **no
adapter or httpx-client recreation**, and no in-flight request is
affected. `main.py::_lifespan` calls `registry.init(settings)` exactly as
before, THEN (only when `keyvault_backend != "env"`) does one `strict=True`
refresh before `yield` (a startup fetch failure removes that provider —
fail-closed, matching `init()`'s own posture for "no key") and starts a
background task doing `strict=False` refreshes every TTL window
(a transient Vault/KMS blip on an already-serving gateway logs an error
and KEEPS the last-known-good credential rather than cutting off a working
provider — availability over instant-revoke, an explicit tradeoff of a
polling design).

`GatewaySettings.configured_providers()` gained one branch: when
`keyvault_backend != "env"`, "configured" means "declared in
`router_default_providers`" instead of "raw env secret present" (since a
vault/kms deploy intentionally leaves `ANTHROPIC_API_KEY` etc. unset) —
the real credential-presence check happens at the `strict=True` startup
refresh instead. The `keyvault_backend="env"` branch (default) is
untouched.

### `sentinel-keyvault` CLI (`src/gateway/keyvault/cli.py`)

`status` / `verify --provider X` — runs in a SEPARATE process from the
gateway, so it CANNOT push a rotated key into a live gateway's cache
(same "no admin endpoint yet" gap). Its role: let an operator confirm a
backend has a fresh, fetchable credential for a provider, independent of
any running gateway — useful in a deploy pipeline before/after rotating a
secret in Vault/KMS. Never prints a credential value, even on `status`
(boolean presence only) — proven by `tests/gateway/keyvault/test_cli.py`
asserting the real secret string never appears in captured stdout/stderr.

## Not in scope

- **OpenAI key auth.** `OpenAiAdapter` has never authenticated to its
  upstream (`upstream_api_key=None`, a pre-existing Phase-0 gap per
  ADR-0008 §10's own docstring) — F-027 doesn't touch this. The
  `ProviderKeySource` abstraction is ready to serve an OpenAI key once
  that gap is closed as its own change (adding the setting field + header
  injection in the adapter is a separate, independent diff from vaulting
  the value once it exists).
- **Virtual API keys** (ADR-0002) are unrelated — those are the
  client-facing Bearer tokens Sentinel issues per team; F-027 vaults the
  UPSTREAM provider credentials Sentinel itself uses to call OpenAI/
  Anthropic/Bedrock. No overlap in code or table.
- **Instant-push rotation** (an admin endpoint to force-refresh every live
  pod immediately) needs a new `contracts/openapi.yaml` route — deferred,
  see `docs/followups/f-027-instant-rotation-endpoint.md`.
- **Per-tenant BYOK** (a tenant supplying their own provider key instead
  of using Sentinel's) is a materially different, bigger feature — not
  attempted here; F-027 vaults Sentinel's OWN platform-level provider
  credentials only.
