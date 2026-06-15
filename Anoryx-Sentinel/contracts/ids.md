# Sentinel — Stable Identifier Schema (Phase 0 — LOCKED)

These four IDs travel on every request, event, and log entry across the entire
Anoryx ecosystem. They are the join key between Sentinel events and Delta records.
DO NOT rename these fields without an ADR and a full migration plan.

| Field      | Type   | Format          | Example                                  |
|------------|--------|-----------------|------------------------------------------|
| tenant_id  | string | UUID v4         | "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6" |
| team_id    | string | UUID v4         | "7d9e2f3a-1234-5c6b-8def-0123456789ab" |
| project_id | string | UUID v4         | "b3c4d5e6-abcd-1234-ef01-234567890abc" |
| agent_id   | string | slug, lowercase | "gateway-core", "data-protection"       |

Rules:
- All four REQUIRED on every inbound request. Missing any = 400 Bad Request.
- All four propagated onto every outbound event on the Redis Streams bus.
- agent_id = internal Sentinel component name, not the end-user's AI model name.
- These IDs are set in Phase 0 and treated as IMMUTABLE across the Anoryx ecosystem.
