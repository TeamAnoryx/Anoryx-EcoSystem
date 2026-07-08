# ADR-0010 — Cross-Product Identity-Event Correlation (not federation)

- Status: Accepted
- Date: 2026-07-08
- Task: O-010 (tenth Orchestrator task, second task from the Phase 2 ecosystem-integration
  layer)
- Builds on: ADR-0003 (O-003 ingest — the tenant-scoped RLS ingest-table pattern this
  reuses), ADR-0006 (O-006 per-tenant query principal — the `query_service_tokens` read
  credential this reuses verbatim), ADR-0009 (O-009 relay — the per-source-product bearer
  + hash-chain-audit pattern this reuses)
- Supersedes: nothing. Adds one new ingest+read seam, one new tenant-scoped table, one new
  global hash chain, and one new admin read; does not alter any existing seam, engine, or
  schema.

## Context

The roadmap lists O-010 as **"Unified identity + cross-platform access management"** —
"One identity/access protocol across Delta, Rendly, Sentinel. SSO federation, cross-product
RBAC, single audit of who-accessed-what-where" — marked 🏦 POST-INVESTMENT, in the same
Phase-2 ecosystem-integration tier as O-009. As with O-009, this run's default posture is to
stop in front of the post-investment gate; the task owner has explicitly authorized
proceeding with post-investment tasks in this run, which is the authorization this ADR
records.

The literal ask — "one identity/access protocol," "SSO federation," "cross-product RBAC" —
is unbuildable as a single honest PR, and for a sharper reason than O-009's missing data
plane: **there is no shared identity substrate to unify, and each product's own credential
system is real, live, and doing real work.**

- **Sentinel's F-014 SSO** (`Anoryx-Sentinel/src/admin/sso/`) is a tenant-scoped **operator
  console login** system (OIDC/SAML → `AdminUser`/`AdminRole`/`IdpGroupRoleMap`), not a
  general identity provider. Its session tokens are verified only by Sentinel's own admin
  middleware; there is no API another product can call to obtain or verify a Sentinel
  identity.
- **Delta has no user/session/RBAC system at all** — its only credential is a single static
  `DELTA_ADMIN_TOKEN` bearer resolving to one fixed principal slug. There is no per-user
  identity to federate.
- **Rendly's R-003** (`Rendly/src/rendly/auth/`) is the one real prior art: a self-contained
  OAuth2 + ES256 JWT service, per-user, with an explicitly **reserved, always-null**
  `idp_subject` claim and matching contract language: "R-001 issues Rendly's own
  self-contained tokens and takes NO dependency on Sentinel F-014 or any Orchestrator/Delta
  contract" (`docs/adr/0003-rendly-auth.md`). Rendly's own `tenant_id` is deliberately
  shape-compatible with Sentinel's ID contract specifically so a *future* correlation join
  could work — but no federation logic exists anywhere, and Rendly's tokens are verified
  only by Rendly.
- **The Orchestrator itself already has SIX unrelated trust tiers** (`ORCH_ADMIN_TOKEN`,
  `ORCH_INGEST_HMAC_SECRET`, the legacy unused `ORCH_SERVICE_TOKEN`, `query_service_tokens`,
  `ORCH_RELAY_SOURCE_TOKENS`, and the pass-through Sentinel virtual API key the O-009 relay
  forwards) — the fragmentation O-010's own text names, with no shared principal shape and
  no cross-tier correlation key beyond an inconsistently-asserted `tenant_id`.

Building "one protocol" or federating SSO across systems this different, with no consuming
task ready and no dedicated security review cycle, is exactly the kind of unreviewed,
first-of-its-kind infrastructure ADR-0008 and ADR-0009 already declined to build under
ambiguity. This ADR takes the same move: ship the one piece of O-010's text that is
genuinely buildable today — **"a single audit of who-accessed-what-where"** — as a
correlation seam, and name everything else as an explicit, honest deferral.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "unified identity" means without a shared substrate | **A1**: a governed CORRELATION seam, not federation. Each product keeps its own credential type, its own verification logic, and its own identity model; the Orchestrator does not issue, verify, or translate any of them. It only durably records, in one place, that a (product-verified) access happened — the literal "single audit of who-accessed-what-where," nothing more. |
| **B** — who calls the seam | **B1**: all THREE products (Sentinel, Delta, Rendly) may push identity events — unlike O-009's relay, where Sentinel is only ever the target. Each already has its own auth-boundary moment worth recording (Sentinel's SSO login, Delta's admin-token use, Rendly's JWT verification) — the seam is symmetric across products, even though today only Sentinel has a rich enough auth system to make its own emission genuinely meaningful. |
| **C** — auth model for the ingest side | **C1**: a per-source-product bearer (`ORCH_IDENTITY_SOURCE_TOKENS`, keyed `sentinel`/`delta`/`rendly`) mirrors the O-009 relay's `source_tokens` pattern exactly — source_product is SERVER-RESOLVED from the matched token, never accepted from the body. A dedicated credential, not a reuse of any existing token (the existing tokens all authorize a DIFFERENT action — this is a new one: "report an identity event"). |
| **D** — auth model for the tenant-read side | **D1**: REUSE the existing O-006 per-tenant principal (`query_service_tokens` / `require_tenant_principal`) verbatim — the SAME credential that already gates `GET /v1/events`. No new tenant-read trust root; a tenant's existing read credential now also sees its own cross-product identity trail. |
| **E** — principal identity shape | **E1**: `principal_id` is an OPAQUE string in the SOURCE PRODUCT's own namespace (an `admin_user_id`, an `idp_subject`, a static admin slug) — no cross-product principal-identity mapping is implied or performed. Two different `principal_id` values from two different products are never asserted to be "the same person," even if a human reader might guess so. |
| **F** — data-table scope (RLS vs. global) | **F1**: `identity_events` is TENANT-SCOPED with RLS (mirrors `ingest_events`, 0001) — a tenant's own access trail is tenant data, unlike the O-005 registry or O-009 relay's dispatch metadata (which are genuinely cross-tenant fleet infrastructure). The audit CHAIN (`identity_audit_log`) is separately GLOBAL/privileged-only (mirrors `relay_audit_log`), because a hash chain's `prev_hash` linkage is inherently a single, total order — sharding it per-tenant would defeat "one chain proves nothing was deleted." |
| **G** — idempotency | **G1**: `UNIQUE(source_product, idempotency_key)` with `ON CONFLICT DO NOTHING` — a retried push is a no-op (`disposition: duplicate`), never a duplicate row, never an error. Simpler than O-003's ingest pipeline (no content-hash comparison, no DLQ): identity events are audit-visibility records, not enforcement-critical, so a plain dedup-by-key is proportionate; a genuine `idempotency_conflict` state machine (same key, different content) is not built here. |
| **H** — what gets chain-audited | **H1**: BOTH a fresh accept and an idempotent duplicate are hash-chain audited (unlike, say, the registry chain, which does not audit plain validation failures) — because a duplicate delivery is itself a meaningful, tamper-evident fact about the ingest attempt. A pre-persistence 401/422 (bad auth, malformed body) is NOT chain-audited, matching every other chain's precedent (only business-level dispositions are chain-audited, not generic client errors). |
| **I** — admin read | **I1**: `GET /v1/admin/identity/events/recent` mirrors the O-007 admin reads exactly (same operator bearer, same bounded "recent N, no cursor" shape) — cheap and consistent to add given the identical, already-twice-established pattern; not scope creep. |

## API additions

- `POST /v1/identity/events` — ingest (identitySourceBearer + mTLS). Body:
  `{tenant_id, principal_type, principal_id, action, target?, idempotency_key, occurred_at}`.
  Returns `202 {status: "accepted", disposition: "accepted"|"duplicate"}`.
- `GET /v1/identity/events` — tenant-scoped, cursor-paginated read (reuses `serviceToken` /
  `query_service_tokens`, mirrors `/v1/events`'s cursor discipline exactly).
- `GET /v1/admin/identity/events/recent` — operator cross-tenant bounded read (reuses
  `operatorBearer`, mirrors the two existing O-007 admin reads).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT "one identity/access protocol across Delta, Rendly, Sentinel."** Each
  product's own credential system (Sentinel's F-014 SSO, Delta's static admin token,
  Rendly's per-user ES256 JWT) is completely unchanged and untouched by this seam.
- **This is NOT SSO federation.** No product can use another product's credential to
  authenticate anywhere as a result of this task. Rendly's reserved `idp_subject` claim
  remains null; this ADR does not populate it or build the federation logic it was reserved
  for.
- **This is NOT cross-product RBAC.** There is no shared role/permission model here. Each
  product's own authorization decisions are unaffected; this seam only records that a
  decision point was reached, not what it granted.
- **`principal_id` values are NOT correlated across products.** The seam stores them
  side-by-side per tenant; it does not assert, infer, or verify that a `principal_id` from
  Sentinel and a `principal_id` from Rendly refer to the same human or agent.
- **Only Sentinel has a rich auth system to meaningfully emit from today.** Delta's single
  static admin token and Rendly's own internal JWT verification CAN emit events here (the
  seam is symmetric, Fork B), but no code in Delta or Rendly has been changed by this PR to
  actually call it — that is each product's own follow-up work, not implied as already done.
- **Dispatched only via this run's explicit authorization to build post-investment tasks**
  (mirrors ADR-0009's identical disclosure) — the roadmap's own 🏦 label means this was not
  scheduled as next-buildable MVP work.

## Threat model

| Threat | Mitigation |
|--------|------------|
| A compromised source-product token forges another product's identity events | Per-source-product bearer, constant-time compare; source_product is resolved FROM the matched token, never claimed by the caller — a token holding Delta's credential cannot claim to be Sentinel. |
| Cross-tenant identity-event leakage | `identity_events` is RLS-scoped exactly like `ingest_events` (FORCE ROW LEVEL SECURITY + the same fail-closed NULLIF predicate); the tenant read runs under `get_tenant_session(principal)`, never an explicit tenant filter a caller could widen. |
| Principal-identity confusion (assuming two products' `principal_id`s are the same entity) | Explicitly named as OUT OF SCOPE (Fork E, Honesty boundaries) — the schema stores them as opaque, unrelated strings; no code anywhere computes or asserts equivalence. |
| Tamper on the identity audit chain | Append-only via BEFORE UPDATE/DELETE deny-triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_identity_chain` re-verifies the full chain. |
| Duplicate/replayed ingest inflating the audit trail | `UNIQUE(source_product, idempotency_key)` + `ON CONFLICT DO NOTHING` — a replay is recorded once as data, though every ATTEMPT (including duplicates) is still chain-audited for tamper-evidence (Fork H). |
| Resource exhaustion via oversized/high-volume ingest | `ORCH_IDENTITY_MAX_BODY_BYTES` cap (default 8 KiB, generous for this record shape) enforced before JSON parsing; per-field length caps re-asserted at the router boundary (defense-in-depth against a DB constraint violation turning into a 503). |

## Residual risk (known, deferred)

- **No product has been changed to actually call this seam.** Sentinel/Delta/Rendly emitting
  real identity events here is real follow-up work in each product's own codebase, not part
  of this Orchestrator-side task.
- **No cross-product principal correlation.** If a future task wants to answer "did the same
  human touch Sentinel and Rendly," that requires a genuine identity-linking decision (with
  its own privacy/consent considerations) this ADR deliberately does not make.
- **No genuine `idempotency_conflict` detection** (Fork G) — a same-key-different-content
  replay is silently treated as a duplicate (the first write wins), unlike O-003's ingest
  pipeline, which distinguishes the two via content-hash comparison. Acceptable for an
  audit-visibility record; would need revisiting if this seam ever gates an enforcement
  decision.
- **This is not SSO federation or cross-product RBAC** (repeated from Honesty boundaries
  because it is the single most likely misreading of "O-010 shipped").

## Configuration

New environment variables (both resolved NON-FATALLY — absence is not fatal; an
unconfigured seam fail-closed-401s every ingest request since no source token can match):

- `ORCH_IDENTITY_SOURCE_TOKENS` — JSON object `{"sentinel"|"delta"|"rendly": bearer_token}`
  (`{}` if unset).
- `ORCH_IDENTITY_MAX_BODY_BYTES` — request-body size cap in bytes (default 8192).

## Testing

- **Unit** (`tests/unit/test_identity_config.py`, `test_identity_router.py`,
  `test_hash_chain_identity.py`): env-parsing (defaults, misconfiguration ConfigErrors,
  known-source-product validation); the auth/schema boundary (missing/wrong source bearer →
  401, unknown fields / bad principal_type / missing occurred_at timezone / oversized body →
  422/413) — all return before any DB call; the identity hash chain's
  opt-in-when-present + tamper-evidence properties.
- **Integration** (`tests/integration/test_identity_e2e.py`, `pytest.mark.integration`): a
  non-stubbed e2e on a real Postgres proving: a fresh ingest is durably recorded and
  RLS-isolated from another tenant's read; a retried ingest with the same
  (source_product, idempotency_key) is `duplicate`, not a second row; the tenant read is
  cursor-paginated and newest-first bounded on the admin read; the identity chain validates
  in full, including both `accepted` and `duplicate` links.

## Out of scope (do not build here)

SSO federation of any kind; cross-product RBAC / a shared role model; any change to
Sentinel's F-014, Delta's admin auth, or Rendly's R-003 JWT service; populating Rendly's
reserved `idp_subject` claim; cross-product principal-identity linking/correlation;
genuine idempotency-conflict detection (content-hash comparison); mTLS provisioning (O-008);
the remaining O-011→O-014 ecosystem-integration-layer tasks.

## Consequences

- The Orchestrator gains a real, working, tamper-evident cross-product access log that any
  product can start writing to today (Sentinel's SSO login is the first genuinely rich
  candidate) and that a tenant can already query via its existing O-006 credential.
- The gap between this slice and the roadmap's fuller "unified identity" vision (federation,
  RBAC, principal correlation) is named explicitly (Honesty boundaries, Residual risk, Out of
  scope) rather than implied away, consistent with CLAUDE.md's mandatory honest-language rule
  and ADR-0009's identical precedent for O-009.
- No existing seam, engine, schema, or product credential changed — this PR is purely
  additive.
