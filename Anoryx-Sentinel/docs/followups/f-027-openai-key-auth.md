# Follow-up: OpenAI provider key authentication (pre-existing gap, not F-027)

**Context:** while researching F-027 (provider key vaulting, ADR-0033), it
became clear `OpenAiAdapter` has never authenticated to its upstream —
`src/gateway/router/providers/openai_provider.py` explicitly passes
`upstream_api_key=None`, with an existing comment "Phase 0: no upstream key
vaulting yet" (predates F-027). This is a **pre-existing gap in F-006**, not
something F-027 introduced or fixed.

**Why F-027 doesn't fix it:** F-027's scope is the VAULTING mechanism
(Vault/KMS-backed fetch + rotation) for keys that already have a place to
plug into an adapter — Anthropic (`x-api-key` header) and Bedrock (SigV4
credentials) both already had that plug-in point (a constructor field read
per-request). OpenAI doesn't yet, and adding one is a materially different
change: it needs a new `openai_api_key` `GatewaySettings` field, header
injection wired into whatever HTTP call `OpenAiAdapter` makes (need to
confirm exactly where — it may currently rely on the shared upstream
proxy's own request forwarding rather than a Messages/Completions-style
adapter call, which changes where auth would be injected), and its own
test coverage — a separate, focused diff, not a rider on F-027.

**What's ready for it:** `gateway/keyvault/` (F-027) already has everything
an OpenAI vaulting path would need — `ProviderKeySource.fetch_credentials
("openai")` just needs a case added to `EnvProviderKeySource`/
`VaultProviderKeySource`/`KmsProviderKeySource` (all three are structured
generically enough that this is a small addition, not a redesign) once the
adapter itself has somewhere to put the key.
