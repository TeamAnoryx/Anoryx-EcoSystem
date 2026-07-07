# ADR-0007 — Admin API + Minimal Operator UI

- Status: Accepted
- Date: 2026-07-07
- Task: O-007 (seventh Orchestrator task, fifth runtime task)
- Builds on: ADR-0003 (O-003 ingest persistence), ADR-0004 (O-004 policy distribution),
  ADR-0005 (O-005 multi-Sentinel coordination), ADR-0006 (O-006 persistence consolidation +
  tenant-scoped read seams)
- Supersedes: nothing. Adds two NEW read seams and a static UI; does not alter the O-003
  ingest pipeline, O-004 distribution engine, O-005 registry/coordination, or the O-006
  per-tenant read seams.

## Context

O-007 is "Admin API + minimal UI (registry, recent events, distribution status)." Two of
those three are already served:

- **Registry** — `GET /v1/registry/sentinels` (O-005, ADR-0005) already returns every
  registered Sentinel, gated by the operator bearer (`ORCH_ADMIN_TOKEN`). Nothing new is
  needed here; the UI simply calls it.
- **Distribution status** — `GET /v1/policies/distributions/{distribution_id}` (O-004/O-006)
  returns one distribution's full per-target status, but there is no seam to list *recent*
  distributions across tenants, and it is gated by the peer service token
  (`ORCH_SERVICE_TOKEN`), not the operator token — the wrong principal for an operator
  console.
- **Recent events** — `GET /v1/events` (O-006) is per-tenant (a `query_service_tokens`
  principal), the opposite scope an operator fleet view needs; there is no cross-tenant
  "recent events" seam at all.

So O-007's actual net-new surface is: one cross-tenant "recent events" read, one cross-tenant
"recent distributions" read, and a UI shell that ties all three together.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — new-seam auth principal | **A1**: reuse the EXISTING operator bearer (`ORCH_ADMIN_TOKEN` / `CoordinationSettings.admin_token`) that already fronts the O-005 registry. The admin API is operator-fleet infra, same trust tier as the registry — not a new trust root, not per-tenant (`query_service_tokens` is the wrong principal for a cross-tenant view by construction). |
| **B** — read scope | **B1**: deliberately CROSS-TENANT, mirroring the registry's own operator-global scope. This is the honesty-boundary INVERSE of O-006 (which tenant-scoped `/v1/events`/`/v1/bus/dlq`): an operator fleet view needs to see all tenants; a per-tenant token cannot answer "what happened recently across the fleet." |
| **C** — pagination | **C1**: NO cursor. Each read is a single DESC-ordered, `Limit`-bounded (1..200, default 50) page — "recent N," not a paginated archive. Full cursor pagination exists on the tenant-scoped seams already (`/v1/events`, `/v1/bus/dlq`); duplicating that machinery for an operator glance-view is unnecessary scope. Deferred if an operator ever needs to page deeper than 200 rows back. |
| **D** — distribution projection | **D1**: a NEW `AdminDistributionSummary` (distribution_id, policy_id, tenant_id, policy_type, state, created_at) — never `signed_record` / `content_hash` (no policy body on a fleet-overview read, mirroring the "no payload" rule on events). Per-target detail is NOT duplicated here; an operator drills into one distribution via the existing `GET /v1/policies/distributions/{id}` seam. |
| **E** — UI technology | **E1**: a single dependency-free static HTML/JS page served by the existing FastAPI app (`GET /admin`), NOT a Next.js app. The Anoryx-Sentinel frontend convention (Next.js + TypeScript + Tailwind) exists for Sentinel's `frontend/` package; the Orchestrator has no such scaffold, no npm toolchain, and no other JS anywhere in this subproject. Standing up an entire Next.js build pipeline (package.json, node_modules, a build step, a second CI lane) for what the roadmap itself calls a "**minimal** UI" is a scope expansion this task does not require. The page is honest about this trade-off (see below) rather than silently deviating from the roadmap's Next.js mention. |
| **F** — UI auth | **F1**: the static shell (`GET /admin`) is UNAUTHENTICATED (it carries no data, no secret, no server-rendered content) — the operator pastes the bearer token client-side, held only in an in-page JS variable (never `localStorage`/`sessionStorage`/cookies, so it does not outlive the tab). The token is attached as an `Authorization` header to the three admin-gated `fetch()` calls, which are the only seams touching real data. |

## API additions

### `GET /v1/admin/events/recent`

Cross-tenant, `limit`-bounded (1..200, default 50), newest-first, metadata-only projection —
identical `EventMetadata` shape to `/v1/events` (join keys + type + time; never `payload`).
Gated by `operatorBearer` (same as the registry seams).

### `GET /v1/admin/distributions/recent`

Cross-tenant, `limit`-bounded (1..200, default 50), newest-first `AdminDistributionSummary`
list. Gated by `operatorBearer`.

### `GET /admin`

Serves the static operator console (`admin/static/index.html`): a token field, a "Load all"
button, and three tables (registry, recent events, recent distributions) that `fetch()` the
seams above plus the existing `GET /v1/registry/sentinels`. `include_in_schema=False` (not
part of the versioned JSON API contract).

## Data access

Both new reads run on the caller-owned PRIVILEGED session (`get_privileged_session`, no
tenant GUC set) — the same pattern the registry already uses, since neither read has a
single tenant to scope to. `repositories.list_recent_events_admin` /
`list_recent_distributions_admin` are thin, explicit projections (allow-listed columns only)
so a future column addition to `ingest_events` / `policy_distributions` cannot silently widen
what an operator sees.

## Honesty boundaries (verbatim — non-removable)

- **This is a cross-tenant, operator-scoped view — the deliberate opposite of O-006's
  per-tenant reads.** A holder of `ORCH_ADMIN_TOKEN` sees every tenant's recent events and
  distributions. This is the same trust tier the O-005 registry already grants that token;
  O-007 does not widen it, it reuses it.
- **No cursor pagination.** "Recent" is a single bounded page (max 200 rows); an operator
  cannot page further back through this seam. The existing tenant-scoped, cursor-paginated
  seams remain the way to walk a full history.
- **The UI is a static HTML/JS page, not the Next.js console the Sentinel convention
  describes.** There is no Next.js/npm toolchain in this subproject; building one for a
  roadmap-labeled "minimal UI" was judged out of scope for this task. A richer console (if
  ever needed) is a future task, not a silent scope-narrowing here.
- **The static shell is unauthenticated; the JSON reads are not.** `GET /admin` returns the
  same page to anyone who can reach it, but it contains no tenant data — only the three
  `fetch()`-driven reads require the operator bearer.
- **Distribution summaries never include the signed policy body** (`signed_record` /
  `content_hash`) — same "no payload" discipline as events.
- **Static assets are served from the source tree** (`admin/static/index.html`, opened by
  path at request time) — this works under the editable install CI/dev already uses
  (`pip install -e`). Packaging static assets into a built wheel/distribution is an O-008
  deployment concern, not addressed here.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Cross-tenant read exposure | Accepted, documented (Fork B) — the SAME trust tier as the existing registry seam; not a new exposure, a consistent one. |
| Operator token theft | Unchanged from O-005: constant-time compare, fail-closed on absent/misconfigured token, never logged. The static UI never persists the token to browser storage, limiting exposure to the active tab. |
| Policy-body / event-payload leak via the new reads | Allow-listed column projections in the repo layer, re-asserted at the response boundary (`_distribution_summary_body`); covered by unit tests (leak canaries) and the integration e2e. |
| Unbounded result set / resource exhaustion | `Limit` clamped server-side to [1, 200] regardless of client input (identical clamp to O-006's `_clamp_limit`). |
| XSS via the static page | The page renders all fetched values through `textContent` (never `innerHTML`), so no field value is interpreted as markup. |

## Residual risk (known, deferred)

- **No cursor pagination on the two new reads** — an operator investigating an incident more
  than 200 events/distributions deep must use the DB directly or the existing per-tenant
  cursor-paginated seams. Deferred; add if operationally needed.
- **No Next.js console** — the roadmap's "minimal Next.js UI" phrasing is not literally met;
  a dependency-free static page is substituted (Fork E). Revisit if the Orchestrator later
  grows a real frontend toolchain (e.g., alongside O-014's command dashboard).
- **No new operator-token issuance/rotation tooling** — `ORCH_ADMIN_TOKEN` is unchanged,
  single shared operator secret (O-005 residual risk, not reintroduced here).
- **Static file packaging for a real deployment** is O-008 territory; unaddressed here.

## Configuration

No new environment variable. `ORCH_ADMIN_TOKEN` (already resolved by
`get_coordination_settings()`) gates the two new reads; the app already resolves
`coordination_settings` unconditionally (non-fatally) at construction.

## Testing

- **Unit** (`tests/unit/test_admin_router.py`): operator-auth boundary (missing/wrong/
  unconfigured token → 401/403/401, mirroring `test_coordination_router_auth.py`);
  `Limit` clamp; cross-tenant response shape; leak-canary assertions (`payload`,
  `signed_record`, `content_hash` never present); the static shell serves 200 and never
  echoes the configured token.
- **Integration** (`tests/integration/test_admin_e2e.py`, `pytest.mark.integration`):
  non-stubbed, real Postgres. Seeds `ingest_events` (two tenants, privileged conn) and
  `policy_distributions` (two tenants, real `get_tenant_session` insert path), then proves
  `list_recent_events_admin` / `list_recent_distributions_admin` return rows across BOTH
  tenants (cross-tenant by design), newest-first, `limit`-bounded, and metadata-only.

## Out of scope (do not build here)

O-008 deployment (Helm, mTLS provisioning, static-asset packaging); a Next.js console;
cursor pagination on the two new admin reads; operator-token issuance/rotation; any change
to the O-003/O-004/O-005/O-006 seams, engines, or schemas.

## Consequences

- The Orchestrator gains a genuinely usable operator glance-view (registry + recent events +
  recent distributions) behind the existing operator credential, closing out the Orchestrator
  MVP task list through O-007 (only O-008 deployment remains).
- The cross-tenant scope of the two new reads is a deliberate, documented trust decision
  consistent with the registry's existing scope — not a new exposure class.
- The static-page choice over Next.js is a documented, reversible scope decision, not a
  silent shortcut.
