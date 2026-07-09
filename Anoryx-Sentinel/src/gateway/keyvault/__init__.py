"""Provider key vaulting (F-027, ADR-0033).

Replaces static env-var provider credentials with a pluggable
ProviderKeySource: env (today's exact behavior, default), vault (HashiCorp
Vault KV v2), or kms (AWS KMS envelope-decrypted ciphertext). Wired into
gateway/router/registry.py::ProviderRegistry additively — the default env
backend is byte-identical to pre-F-027 behavior. Runtime fetch + rotation
comes from a short-TTL cache (bounded-lag, not push-based — see ADR-0033 for
why an instant-push rotation would need a new admin HTTP endpoint, which is
out of scope here for the same contract-ownership reason as F-026).
"""
