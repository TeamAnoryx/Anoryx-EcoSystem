# Rendly — Stable Identifier Schema (Phase 0 — LOCKED)

These identifiers travel on every request, real-time message, and archival record across
Rendly. `tenant_id` is shape-compatible with the Anoryx ecosystem join key defined in
`Anoryx-Sentinel/contracts/ids.md`, so a future unified-identity / cross-product archival
join (O-010, post-investment) can correlate Rendly records with Sentinel/Delta records
without a migration. DO NOT rename these fields without an ADR and a full migration plan.

| Field        | Type   | Format          | Example                                  |
|--------------|--------|-----------------|------------------------------------------|
| `tenant_id`  | string | UUID v4         | "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6" |
| `user_id`    | string | UUID v4         | "7d9e2f3a-1234-5c6b-8def-0123456789ab" |
| `channel_id` | string | UUID v4         | "b3c4d5e6-abcd-1234-ef01-234567890abc" |
| `message_id` | string | UUID v4         | "c4d5e6f7-bcde-2345-f012-34567890abcd" |
| `huddle_id`  | string | UUID v4         | "d5e6f7a8-cdef-3456-0123-4567890abcde" |

## Rules

- `tenant_id` is REQUIRED on every resource, every real-time message envelope, and every
  archival record.
- **JWT → ID binding (security-critical).** `tenant_id` and the acting `user_id` are
  resolved AUTHORITATIVELY and SERVER-SIDE from the verified Rendly access token (see
  `contracts/openapi.yaml` `bearerAuth`). They are NEVER read from a client-supplied body
  field or header. A token may act only within its bound `tenant_id`; a request that names a
  different tenant in a path/body is rejected with 403 (`tenant_context_mismatch`). This is
  the Rendly analog of Sentinel's virtual-API-key → ID binding — the credential, never the
  client payload, is the source of truth for identity and tenant scope.
- `channel_id`, `message_id`, and `huddle_id` identify resources WITHIN a tenant. Every
  read/write is tenant-scoped: a resource id that resolves to another tenant is treated as
  not-found (404), never cross-tenant readable.
- `message_id` doubles as the **archival record id** for a chat message; `huddle_id` doubles
  as the archival record id for a huddle session (see the `archival` object in
  `contracts/messages.schema.json`).
- These IDs are set in Phase 0 and treated as IMMUTABLE across Rendly and the ecosystem.

## `user_id` is an opaque surrogate — never PII

`user_id` is an internal UUID. It is NEVER the raw IdP subject, email, employee number, or
any credential. The token's `sub` claim carries this `user_id`; the human-readable profile
(display name, etc.) lives behind the profile resource and is never used as a join key.
(Mirrors the Sentinel `actor_id` non-PII discipline.)

## Reserved / future seams (NOT used in R-001 — documented only)

- **O-010 unified identity (post-investment).** A future cross-product identity layer may
  federate an external IdP subject onto a Rendly `user_id`. R-001 reserves the *shape* for
  this — `tenant_id` is already ecosystem-compatible and the access-token claim set leaves
  room for an `idp_subject` surrogate — but R-001 issues Rendly's own self-contained tokens
  and takes NO dependency on Sentinel F-014 or any Orchestrator/Delta contract. See
  ADR-0001 §D2.
- **Reserved zero-UUID.** Rendly does not emit system-scoped records in the MVP surface, so
  the Sentinel `WILDCARD_UUID` convention is NOT in use here. It is reserved for a future
  system-attribution need (e.g. archival of a system-generated record) and would require an
  ADR before adoption.
