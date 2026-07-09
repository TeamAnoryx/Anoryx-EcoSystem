# Follow-up: instant-push credential rotation endpoint

**Context:** F-027 (ADR-0033) ships bounded-lag rotation — a live gateway
picks up a rotated Vault/KMS secret automatically within one
`keyvault_cache_ttl_seconds` window (default 300s), no restart needed. What
it does NOT ship is a way to force every live gateway pod to refresh
**immediately** — e.g. an operator who just discovered a leaked provider
key wants it gone from every pod's memory now, not in up to 5 minutes.

**Why deferred:** an instant-push design needs a new admin-facing HTTP
route (e.g. `POST /admin/keyvault/rotate`) — `contracts/openapi.yaml` is
api-architect-owned, and that agent path was unreachable this session for
the same `ANORYX_ACTIVE_AGENT` propagation-gap reason documented in
ADR-0031 (F-025) and ADR-0032 (F-026).

**What it would look like once the contract gap closes** (not a hard
design decision the way F-026's proxy was — this is a small, well-scoped
addition to the existing admin surface):

1. `POST /admin/keyvault/rotate` — an authenticated admin-only route that:
   - Calls `app.state.provider_registry.refresh_credentials(key_source,
     strict=False)` on the CURRENT process (works today, in-process).
   - For multi-pod deployments, needs a broadcast mechanism — the simplest
     option is a Redis pub/sub channel every pod subscribes to at startup
     (Redis is already a hard dependency, F-009), publishing a
     `{"event": "rotate", "provider": "anthropic"}` message; each pod's
     subscriber calls the same in-process `refresh_credentials()`.
2. Lower `keyvault_cache_ttl_seconds` from its 300s default is a zero-code
   mitigation available TODAY for anyone who wants tighter bounded-lag
   rotation without waiting for this endpoint (tradeoff: more Vault/KMS
   API calls per pod).
3. A genuine incident-response "kill this key everywhere NOW" is a
   different, stronger requirement than "rotate" — for that, revoking the
   credential AT THE PROVIDER (Anthropic/AWS) is the actual fix regardless
   of Sentinel's cache TTL; this endpoint would shorten Sentinel's OWN
   window of continuing to present a since-revoked key, which the
   provider-side 401 would surface as `ProviderError(kind="auth")` on the
   next request either way (the router's existing fallback logic already
   handles a provider auth failure).
