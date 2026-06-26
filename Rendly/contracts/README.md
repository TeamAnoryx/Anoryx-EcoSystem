# Rendly Contracts — Phase 0 (R-001)

The **single source of truth** for the Rendly secure-comms MVP API surface. The Rendly
analog of Sentinel's F-001 contract lock. Downstream builds (R-002 → R-010) conform to
these files and never invent endpoints or frames.

| File | What it governs |
|------|-----------------|
| `openapi.yaml` | REST surface (OpenAPI 3.1): auth (OAuth2 + JWT), profiles, channels + membership, message history, the `/realtime` WebSocket upgrade, ICE config, liveness. |
| `messages.schema.json` | Real-time WebSocket message catalog (JSON Schema Draft 2020-12): team chat + 1-on-1 huddle signaling. `oneOf` + unique `msg_type` const dispatch. |
| `ids.md` | Stable identifier schema (`tenant_id`/`user_id`/`channel_id`/`message_id`/`huddle_id`), LOCKED/IMMUTABLE. |

ADR for the decisions: [`../docs/adr/0001-rendly-core-contract.md`](../docs/adr/0001-rendly-core-contract.md).

## Design at a glance

- **Self-contained identity.** Rendly issues its own OAuth2 + JWT (R-003). No dependency
  on Sentinel F-014 SSO or any Orchestrator/Delta contract → R-001 is parallel-safe. The
  token is the authoritative, server-resolved source of truth for `tenant_id` + `user_id`.
- **One real-time transport.** Chat and 1-on-1 huddle signaling share a single WebSocket
  (`GET /realtime`); frames are governed by `messages.schema.json`.
- **Fail-closed safety seam.** Message content is inspected synchronously and fail-closed
  before delivery (403 `message_blocked` on REST; `chat.ack status:"blocked"` on the WS).
- **Sentinel-aligned discipline.** Closed schemas (`additionalProperties:false`), bounded
  fields, a fixed-message no-PII `Error` envelope, and hash-chain-ready archival fields —
  all mirror the shipped Sentinel contracts so the ecosystem stays coherent.

## Honesty boundaries (the MVP is narrower than the product name)

These are stated verbatim in the specs and are non-removable:

1. **Huddles are 1-on-1 ONLY.** Group/multi-party huddles are R-011 (post-investment).
2. **The Sentinel inspection integration is a SEAM ONLY** — result fields + fail-closed
   error codes are reserved; detection is R-008. Huddle media is never content-inspected.
3. **The Delta-team → channel auto-mapping is a SEAM ONLY** — the channel `source` /
   `external_ref` fields document it; the mapping is R-006 vs D-016 (manual fallback).
4. **Archival fields are defined ONLY** — immutable archiving is R-009.

## Validate locally

```bash
cd Rendly
python -m venv .venv && . .venv/Scripts/activate   # Git Bash on Windows
pip install -e ".[dev]"
pytest -q                                            # validates spec + every example
```

The same checks run in CI via `.github/workflows/rendly-ci.yml` (path filter `Rendly/**`).
