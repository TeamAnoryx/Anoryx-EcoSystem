"""Custom client-defined PII engine (F-028, ADR-0034).

Per-tenant regex PII patterns, matched by a standalone `regex`-module engine
(ReDoS-safe via per-match timeout) — NOT Presidio, so it runs on the slim
image without spacy. Patterns are validated at registration, stored RLS-scoped
in tenant_custom_pii_patterns, hot-reloaded via a short-TTL cache, and applied
by CustomPiiHook (a PreRequestHook inserted after the built-in F-005 PIIHook).
"""
