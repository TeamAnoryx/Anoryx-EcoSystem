# ADR-0016 — Dashboards: Security / Compliance / Governance (F-013)

- **Status:** Proposed
- **Date:** 2026-06-21
- **Deciders:** (frontend owner / implementer), api-architect (no contract change —
  consumes the existing `openapi.yaml` `/admin/*` surface), security-auditor (frontend
  red-team gate — dashboards render cross-tenant operator data), Affu (solo founder &
  product owner — resolved the STEP-0 forks during planning: **Fork 1 feed = polling**,
  **Fork 2 data-gaps = ship partial / defer the panels the admin API does not back**,
  **Fork 3 per-team source = audit-log client aggregate**, **Fork 4 charting = plain
  SVG/CSS, zero deps**; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0015 (F-012
  console shell — F-013 fills the three dashboard stubs it left ready and reuses its
  BFF/session/CSP spine unchanged) and ADR-0014 (F-012a admin API — consumed read-only,
  never changed). Consumes F-011 (ADR-0013 compliance engine) via the F-012a operator
  evidence path and F-007 (ADR-0010) shadow-AI egress events. **No `contracts/` change.**
  Governed by `contracts/openapi.yaml`; **the contract wins over this ADR on any conflict.**
- **Feature:** F-013 — three operator dashboards (Security, Compliance, Governance) in the
  admin console that consume **existing** `/admin/*` endpoints through the **existing** BFF
  + session auth. Frontend-only: **no new backend endpoint, no new auth path** (R1/R2).

---

## 1. Context

The F-012 console (ADR-0015) shipped three stubbed dashboard routes
(`src/app/(admin)/dashboards/{security,compliance,governance}/page.tsx` +
`dashboard-stub.tsx`), their nav slots, the `(admin)` layout `getSession()` guard, the
BFF (`lib/bff.ts` + `app/api/admin/[...path]/route.ts`, JSON-only, token server-side),
the strict nonce CSP (`middleware.ts`), and the typed client layers (`admin-client.ts`
server, `client-api.ts` client). F-013 replaces the stubs without touching that spine.

The F-012a admin API (ADR-0014) exposes, per target tenant: keyset audit read
(`GET /admin/tenants/{id}/audit` → events + `chain_verified` + `chain_rows_checked`),
config read/adjust (`GET|PATCH .../config`), policy status, tenant list (the picker
source), and the F-011 operator evidence path (`POST .../compliance/evidence`).

**Two structural constraints shape every decision below:**

1. **The audit projection is metadata-only.** `AuditEventResponse` carries
   `event_type`, `action_taken`, `agent_id`, the four IDs, `event_timestamp`,
   `sequence_number`, and the chain hashes — **no per-event payload** (no `model`,
   `severity`, `detected_endpoint`, score). This is deliberate (ADR-0014 "identity +
   chain metadata only, no payload dump").
2. **The BFF proxies JSON only** (`bff.ts` calls `upstream.json()`), so it cannot stream
   binary byte-for-byte.

## 2. Decisions

### D1 — Feed mechanism: POLLING (Fork 1)
The security feed and shadow-AI feed poll `GET /admin/tenants/{id}/audit` through the
existing BFF: 5s interval, paused on `document.hidden` (`visibilitychange`), one
`AbortController` per request, no overlap (skip a tick while a prior request is
in-flight), cleanup on unmount and on tenant switch (R7). **Rejected: WebSocket** —
requires a new backend WS endpoint + its own auth + new threat vectors, which violates
the frontend-only scope (R1/R2).

### D2 — Tenant scoping: query-param, fresh fetch per switch (R3)
Dashboards have no tenant in their route. Each dashboard is a server component that reads
`?tenant=`; with none selected it renders a tenant picker (reuse `adminApi.listTenants()`).
A tenant switch is a new URL → a fresh server fetch → no prior-tenant state survives.
The polling feed islands key their state on the selected tenant and reset on change.

### D3 — Charting: plain SVG/CSS, zero new deps (Fork 4)
Breakdowns are simple horizontal count bars rendered with Tailwind/SVG. No charting
library is added (F-010 slim-bundle discipline).

### D4 — Per-team source: audit-log client aggregate (Fork 3)
Per-team counts are aggregated client-side from loaded audit events (each carries
`team_id`). **Rejected: `/metrics`** — it is unauthenticated, not behind the BFF,
aggregate-by-default with per-tenant labels flag-gated (γ), Prometheus text format, and
exposes **no per-model labels** (ADR-0011 D4). It cannot back a tenant-scoped,
auth-gated dashboard panel.

## 3. Per-panel data-source map

| Dashboard | Panel | Source | Status |
|---|---|---|---|
| Security | Event feed | `GET .../audit`, client-filtered to security event types | ✅ ship (windowed to recent pages; metadata-only) |
| Security | Per-team breakdown | audit `team_id`, client aggregate | ✅ ship (partial — over loaded events) |
| Security | Per-model breakdown | — | ❌ **deferred** (no `model` in projection) |
| Security | Chain/signature status | `chain_verified` + `chain_rows_checked` | ✅ ship (reuse badge) |
| Compliance | Readiness + totals | `POST .../compliance/evidence` | ✅ ship |
| Compliance | Per-control gap list | endpoint returns totals only; `gap.results` discarded `control.py:170` | ❌ **deferred** |
| Compliance | Evidence pack ZIP download | `pack.export_pack_zip` wired to no route + JSON-only BFF | ❌ **deferred** |
| Governance | Classifier select (view+adjust) | `GET\|PATCH .../config` + reuse `config-form.tsx` | ✅ ship |
| Governance | Model inventory | no inventory endpoint; static provider enum + configured classifier | ⚠️ ship partial |
| Governance | Shadow-AI feed | `GET .../audit`, filter `shadow_ai_detected_outbound` | ⚠️ ship occurrence-only |

## 4. Deferrals (honest scope — gaps flagged to Affu, not silently filled — R2)

- **Per-model breakdown** — needs `model` on the audit projection or a usage-aggregate
  endpoint (backend).
- **Compliance per-control list** — needs the operator evidence endpoint to surface
  `gap.results` (small backend change).
- **Evidence pack ZIP download** — needs a signed-ZIP route **and** a binary-safe proxy
  path (the JSON BFF cannot satisfy R4 byte-integrity). Backend + new proxy surface.
- **Full model inventory** — needs a model/provider inventory endpoint (backend).
- **Shadow-AI endpoint detail** — `detected_endpoint`/`selected_provider` are omitted by
  the audit projection; the feed shows occurrence only.

**Correction to the dispatch:** the dispatch states "F-018 completes the shadow-AI feed."
The roadmap (lines 33, 169) records **F-018 was folded into F-007 (shipped, detect-only)**;
no separate F-018 task remains. The feed is progressive because detection is
detect-and-audit only — not because a future task finishes it. The UI labels it as such.

## 5. Honest rendering (R6, carried from F-011 R8)

The compliance dashboard renders **"audit-ready, not compliant"** framing and the
mandatory disclaimer; gaps are shown as gaps, never styled to imply coverage. The
shadow-AI feed is labeled progressive. Partial panels state their limitation in the UI.

## 6. Threat model (frontend, tested — vitest + Playwright)

1. `dashboards_require_session` — all 3 routes, no session → `/login`, zero data (inherits
   `(admin)/layout.tsx` guard; e2e).
2. `dashboard_calls_go_through_bff` — no browser→Sentinel `/admin/*` direct; all via
   `/api/admin/*` (unit on fetchers; e2e network assert).
3. `no_cross_tenant_data` — tenant switch drops prior-tenant state/DOM (unit on feed reset;
   e2e param switch).
4. `evidence_pack_bytes_unaltered` — pack download deferred this PR; documented. The JSON
   evidence path is unaltered pass-through (no re-encode of evidence values).
5. `no_xss_in_event_feed` — a crafted event payload (`<script>` in a text field) renders as
   inert text; no `dangerouslySetInnerHTML` anywhere (unit on row render).
6. `compliance_ui_honest` — readiness shows audit-ready (not "compliant"); gaps shown as
   gaps; disclaimer present (unit on `gap-summary`).
7. `polling_pauses_when_hidden` — feed stops on `document.hidden`, resumes on show, no
   request stacking (unit on `use-poll`).

CSP stays the F-012 strict nonce policy unchanged; no new inline scripts. All API errors
render through `toFriendlyError` (never raw upstream bodies). WCAG 2.1 AA: keyboard nav,
focus, contrast, aria (R8).

## 7. Consequences

- Operators get real security/compliance/governance visibility reusing one auth/BFF spine;
  no new trust surface, no contract change, frontend CI lane only.
- Five panels ship partial or deferred against documented backend gaps; each is labeled in
  the UI and listed in the PR DO-NOT-MERGE checklist. Closing them is backend follow-up
  work (api-architect + its own review), explicitly out of F-013.
