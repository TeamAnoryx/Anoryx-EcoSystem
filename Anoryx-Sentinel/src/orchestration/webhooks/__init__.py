"""F-020 outbound webhook dispatch subpackage (ADR-0023).

Provides:
  - url_guard    — SSRF-hardened URL validation + resolve-and-pin
  - adapters     — per-provider (Slack / Jira / Splunk) body builders
  - signer       — HMAC-SHA256 timestamp-in-body signing for generic/Splunk
  - audit_events — webhook_delivered / webhook_delivery_failed emit primitives
  - queue        — Redis Streams consumer-group plumbing for the dispatcher
  - worker       — webhook-dispatcher consumer-loop entrypoint
"""
