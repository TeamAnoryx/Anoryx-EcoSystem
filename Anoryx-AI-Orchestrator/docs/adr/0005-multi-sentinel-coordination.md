# ADR-0005 — Multi-Sentinel Coordination (registry + health + coordinated push)

- Status: Accepted
- Date: 2026-06-30
- Task: O-005 (fifth Orchestrator task, third runtime task)
- Builds on: ADR-0003 (O-003 ingest persistence), ADR-0004 (O-004 policy distribution)
- Supersedes: nothing. Extends the static `ORCH_DISTRIBUTION_TARGETS` map with a dynamic registry.

## Context

O-004 (ADR-0004, merged) distributes a tenant's signed policy to a **minimal explicit
target list**, resolving each `sentinel_id → endpoint` only through a static environment map
(`ORCH_DISTRIBUTION_TARGETS`). The engine fans out per-target, best-effort, and aggregates
honestly to `distributed | partial | failed`. `config.py` explicitly reserved the *dynamic
registry resolver* for O-005.

O-005 builds that resolver: a **registry of Sentinel instances** (validated endpoint,
peer-auth reference, declared capabilities, health status), a **health-check subsystem**
(poll → status transitions → staleness), and a **coordinated push** that fans O-004's
existing per-target distribution across all **healthy + capable** registered targets.

O-005 **consumes O-004's distribution engine unchanged.** The engine resolves endpoints only
through `DistributionSettings.targets` (`distribution/engine.py:150`). The coordinated push
selects healthy+capable `sentinel_id`s, builds a `DistributionSettings` whose `.targets` is
the registry's `{sentinel_id: endpoint}` for the selected set, persists the parent +
per-target rows exactly as the O-004 router does, then calls `drive_distribution(...)`. The
registry becomes the dynamic resolver; the distribution semantics are untouched.

### The load-bearing security property: SSRF defense

Introducing a **data-driven** `sentinel_id → endpoint` registry breaks O-004's implicit trust
assumption ("endpoints are operator-vetted static env config"). A registry row's endpoint
feeds directly into outbound `httpx` calls (health probes + distribution POSTs). An
unvalidated registry is therefore an SSRF / amplification vector: a malicious or mistaken
endpoint could direct the Orchestrator at internal services, cloud metadata
(`169.254.169.254`), or arbitrary hosts. **Every endpoint is validated/allowlisted at
registration AND re-validated before every outbound use.** This is the load-bearing property
of O-005; the engine had no such defense.

## Decision — resolved forks (STEP 0)

| Fork | Decision |
|------|----------|
| A — health execution | **A1**: periodic poll cycle → `healthy / degraded / unreachable` transitions + staleness timeout. Exposed as a callable `run_health_cycle()` (scheduler-driven in production; awaited directly in the e2e for deterministic real transitions — mirrors how `drive_distribution` is a `BackgroundTask` in prod but awaited in tests). |
| B — push targeting | **B1**: push only to registered + healthy + capable; skip the rest, per-target status; reuse O-004's best-effort per-target fan-out. |
| C — capability | **C1**: static declared capabilities recorded at registration; no live probe. |
| D — authz / tenancy | **D1 + new `ORCH_ADMIN_TOKEN`**: operator-scoped registry (per-tenant authz → O-006); inbound CRUD gated by a **new dedicated** fail-closed operator token, distinct from the peer `ORCH_SERVICE_TOKEN`. |
| E — health honesty | **E1**: "healthy" = reachable per the documented contract via the O-004 shim; **not** verified-enforcing. |

### Locked (not forks)

- Consume O-004's engine unchanged (no re-decode of distribution semantics).
- Registry is operator-global infra → accessed via `get_privileged_session()`; registry +
  registry-audit tables carry **no RLS** (no tenant dimension). RLS is exercised on the
  tenant-scoped distribution rows the coordinated push still produces (reuse O-004 RLS).
- Migration extends the live head `0003_merge_o004_d004`; converge with a no-op merge
  migration (tuple `down_revision`) if a second head appears — never rebase.
- Hash-chained registry-mutation audit (reuse O-003 hash_chain) with a distinct domain.
- `get_tenant_session` autobegins — no `session.begin()` wrapping reads (ADR-0026).

## Schema (migration `0004_sentinel_registry`, `down_revision = "0003_merge_o004_d004"`)

### `sentinel_registry` (operator-global, no RLS)

| column | type | notes |
|--------|------|-------|
| `sentinel_id` | `String(128)` PK | logical id, pattern `^[A-Za-z0-9._-]{1,128}$` (matches O-004 router) |
| `endpoint` | `Text NOT NULL` | SSRF-validated base URL |
| `peer_auth_ref` | `String(128) NOT NULL` default `'global'` | **non-secret** label for the peer-auth credential (interim `'global'` = use shared `SENTINEL_ADMIN_TOKEN`; per-target creds → O-008). Never stores a secret. |
| `capabilities` | `JSONB NOT NULL` | declared list of supported `policy_type`s (static, Fork C1) |
| `health_status` | `String(16) NOT NULL` default `'unknown'` | `unknown \| healthy \| degraded \| unreachable` |
| `consecutive_failures` | `Integer NOT NULL` default 0 | |
| `last_checked_at` / `last_healthy_at` | `TIMESTAMP(tz)` nullable | |
| `enabled` | `Boolean NOT NULL` default true | operator pause without deregister |
| `created_at` / `updated_at` | `TIMESTAMP(tz) NOT NULL` server_default `now()` | |

CHECK constraints: `health_status IN (...)`. `capabilities` is validated as a JSON array of
known policy_type strings at the application boundary (registry repo), not by a CHECK.

### `sentinel_registry_audit_log` (global, append-only, hash-chained — mirrors `distribution_audit_log`)

| column | type | notes |
|--------|------|-------|
| `sequence_number` | `BigInteger` PK autoincrement | chain order |
| `sentinel_id` | `String(128) NOT NULL` | |
| `action` | `String(16) NOT NULL` | `register \| modify \| deregister \| enable \| disable` |
| `disposition` | `String(16) NOT NULL` | `accepted \| rejected` (a **rejected** SSRF-blocked registration is recorded — tamper-evident proof of the attempt) |
| `endpoint` | `Text` nullable | opt-in-when-present |
| `capabilities` | `Text` nullable | opt-in-when-present (canonical JSON) |
| `error_reason` | `Text` nullable | opt-in-when-present (e.g. `ssrf_blocked_private_ip`) |
| `prev_hash` / `row_hash` | `String(64) NOT NULL` (`row_hash` UNIQUE) | hash chain |
| `created_at` | `TIMESTAMP(tz) NOT NULL` server_default `now()` | |

Append-only via a `deny_registry_audit_modification()` BEFORE UPDATE/DELETE trigger pair
(mirrors `distribution_audit_log`). **No RLS, no `orchestrator_app` grants** — these tables
are owned and used by the privileged role only (operator infra). The migration's
`downgrade()` drops triggers/function/tables FK-safe; the `orchestrator_app` role (created in
0001) is untouched.

## SSRF endpoint-validation policy (`coordination/endpoint_validation.py`)

`validate_endpoint(url) -> str` (normalized) | raises `EndpointValidationError`:

1. Parse via `urlsplit`. Scheme must be `https`; `http` allowed **only** if the host is
   allowlisted **and** `ORCH_REGISTRY_ALLOW_HTTP=1`.
2. Reject embedded credentials (`user:pass@`), a fragment, or a missing hostname.
3. IP literal → reject if private / loopback / link-local (incl. the `169.254.169.254`
   cloud-metadata address) / multicast / reserved / unspecified, **unless** the host is in the
   allowlist.
4. DNS name → `getaddrinfo` resolve; reject if **any** resolved address is in those ranges,
   unless the host or a resolved IP is allowlisted (DNS-rebinding defense).
5. Allowlist `ORCH_REGISTRY_ENDPOINT_ALLOWLIST` = comma-separated `host` / `host:port`
   (exact host match). Empty default ⇒ only public `https` passes (fail-closed).
6. **Re-validate at every outbound use** (each health poll + each push target build) — the
   stored endpoint is never trusted blindly (allowlist may change; DNS may rebind).

The e2e sets the allowlist to `127.0.0.1` + `ORCH_REGISTRY_ALLOW_HTTP=1` so the loopback test
shim passes, while the production default stays SSRF-safe.

## Registry CRUD (`coordination/registry.py`, privileged session)

`register_sentinel`, `modify_sentinel`, `deregister_sentinel`, `get_sentinel`,
`list_sentinels`, `set_health_status`. Each mutation `validate_endpoint` (register/modify)
**before** persist; on success appends an `accepted` audit link; on validation failure appends
a `rejected` link with `error_reason` then raises — all in one privileged transaction.
Capabilities are validated to be a JSON array of known policy_type strings.

## Health subsystem (`coordination/health.py`)

`run_health_cycle(*, settings) -> HealthCycleResult`: list enabled sentinels → re-validate
endpoint (invalid ⇒ `unreachable`) → probe `GET {endpoint}{ORCH_SENTINEL_HEALTH_PATH}`
(default `/healthz`): a 2xx ⇒ `healthy` + `last_healthy_at`, reset failures; a non-2xx but
reachable response ⇒ `degraded`; a connection error / timeout / DNS failure ⇒ increment
`consecutive_failures`, `degraded` then `unreachable` at `ORCH_HEALTH_UNREACHABLE_THRESHOLD`.
Staleness: a `last_checked_at` older than `ORCH_HEALTH_STALENESS_SECONDS` is demoted from
`healthy`. Transitions persist via `set_health_status`.

## Coordinated push (`coordination/coordinator.py`)

`coordinate_push(signed_policy, tenant_id, *, settings) -> CoordinationResult`:

1. `list_sentinels()` (privileged).
2. Filter: `enabled` AND `health_status == healthy` AND `policy_type ∈ capabilities` AND
   endpoint re-validates. Record a skip reason per excluded target
   (`unhealthy | incapable | invalid_endpoint | disabled`).
3. Build `{sentinel_id: endpoint}` for the selected set; clone `get_distribution_settings()`
   with `.targets` overridden to that map.
4. Persist the parent `policy_distributions` row + per-target `policy_distribution_targets`
   (state `pending`) under `get_tenant_session(tenant_id)` (RLS-enforced), exactly as the
   O-004 router does.
5. `await drive_distribution(distribution_id, tenant_id, settings=...)` — **unchanged engine**.
6. Read per-target results from `list_distribution_targets`; merge with the skip list →
   per-target coordination status (`distributed | failed | skipped:<reason>`).

## HTTP router (`coordination/router.py`, gated by `ORCH_ADMIN_TOKEN`)

Reuses the O-004 `_require_bearer` shape + `_error` envelope, keyed on the new operator token
(fail-closed: unconfigured ⇒ 401; missing/empty ⇒ 401; mismatch ⇒ 403; constant-time).
Routes: `POST/GET /v1/registry/sentinels`, `GET/PATCH/DELETE /v1/registry/sentinels/{id}`,
`POST /v1/registry/health-check`, `POST /v1/policies/coordinate`. Mounted in `app.py`.

## Hash-chain registry audit (reuse O-003)

New domain in `hash_chain.py`: `REGISTRY_GENESIS_HASH =
sha256("anoryx-orchestrator:registry-audit:genesis:v1")`, `REGISTRY_CANONICAL_FIELDS =
(sentinel_id, action, disposition, prev_hash)`, `_REGISTRY_OPTIONAL_FIELDS = (endpoint,
capabilities, error_reason)` (opt-in-when-present), plus `canonical_registry_json` /
`compute_registry_row_hash` / `verify_registry_row_hash`. In `repositories.py`:
`registry_chain_tip_hash`, `append_registry_audit_link`, `validate_registry_chain` (distinct
advisory-lock label `anoryx-orchestrator:registry-audit-chain`; copies the BYPASSRLS
fail-loud guard so a non-bypass role cannot vacuously "pass" over a hidden chain).

## Honesty boundaries (verbatim — non-removable)

- **"healthy" = reachable per the documented contract** (an HTTP reachability probe to the
  registered endpoint's health path, via the O-004 shim stand-in); **NOT verified-enforcing.**
- The registry is **operator-scoped** (per-tenant authz → O-006).
- **Capability = declared at registration, not probed** (Fork C1).
- The coordinated push is **best-effort per-target** (reuses O-004 semantics).
- **mTLS → O-008** (interim Bearer now: outbound `SENTINEL_ADMIN_TOKEN` to Sentinel; inbound
  `ORCH_ADMIN_TOKEN` for operator CRUD).
- **Real Sentinel intake/health routes are a separate Sentinel task**; the test shim stands in
  for the documented contract.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Malicious registry entry → policy pushed to an attacker-controlled Sentinel | SSRF validation + allowlist at register AND re-validation at push/health; a rejected registration is recorded in the tamper-evident chain |
| SSRF via the health endpoint | the same validation gates health probes; private/loopback/link-local/metadata-IP rejected unless allowlisted; DNS-rebind mitigated by re-resolve + re-validate on every outbound use |
| Capability spoofing → silent non-enforcement | capabilities are operator-declared (operator-trusted), not peer-supplied; `reachable ≠ enforcing` is surfaced, not hidden; a `policy_type` mismatch is skipped + surfaced |
| Stale-health distribution | staleness TTL demotes stale `healthy` targets; the healthy-only filter excludes them; health is read at push time |
| Authz bypass | registry CRUD + coordinate + health-check are gated by the fail-closed `ORCH_ADMIN_TOKEN`, constant-time, distinct from the peer `ORCH_SERVICE_TOKEN` |
| Fan-out amplification | targets bounded by the operator-controlled registry + the per-target O-004 retry ceiling (`max_attempts`); unhealthy targets are excluded so the fan-out never hammers them; the allowlist bounds destinations |
| Audit tampering | the registry-mutation chain is append-only (deny-triggers) and validated with the BYPASSRLS fail-loud guard; the opt-in-when-present rule keeps nullable columns backward-compatible and tamper-evident when set |

## Configuration

`ORCH_ADMIN_TOKEN` (None → fail-closed), `ORCH_REGISTRY_ENDPOINT_ALLOWLIST` (""),
`ORCH_REGISTRY_ALLOW_HTTP` (false), `ORCH_SENTINEL_HEALTH_PATH` (`/healthz`),
`ORCH_HEALTH_STALENESS_SECONDS` (300), `ORCH_HEALTH_UNREACHABLE_THRESHOLD` (3). Reuses
`SENTINEL_ADMIN_TOKEN` (outbound) and `ORCH_DISTRIBUTION_*` unchanged.

## Testing

- **Unit**: SSRF matrix (reject http / private / loopback / link-local / metadata-IP /
  creds-in-URL / DNS-rebind; accept public https + allowlisted loopback); capability+health
  selection logic (pure); registry hash-chain compute/verify + opt-in-when-present + tamper.
- **Integration (non-stubbed, the gate)** — `test_coordination_e2e.py`: ≥3 Sentinel shims on
  distinct loopback ports sharing `sentinel_ci`; A healthy+capable, B healthy+incapable, C
  unreachable (shim stopped). Health cycle → real transitions (A/B healthy, C unreachable).
  Coordinated push of `policy_type` X via the router → fans to A only; B `skipped:incapable`,
  C `skipped:unhealthy`; A `distributed`, with A's shim driving Sentinel's REAL `intake_policy`
  persist + `evaluate_model_policies` enforcement. Tenant RLS asserted on the distribution
  rows. Registry audit chain validates + tamper-evident. `ORCH_REQUIRE_COORDINATION_E2E=1`
  flips the skip-gate to `pytest.fail` so the gate provably executes on CI.
- **`test_registry_crud.py`**: register/modify/deregister chain links; SSRF-rejected
  registration → `rejected` chain link; chain validates + tamper-evident.

## Out of scope (do not build here)

O-006 (persistence consolidation, query/bus read seams, coarse-GET-authz fix, per-tenant
registry authz, O-002 LOW-2 DLQ-metadata fix); O-007 (UI); O-008 (deploy + real mTLS
provisioning); Sentinel's real HTTP intake/health routes (a separate Sentinel task). O-005
does not reimplement O-004's distribution engine.

## Consequences

- The static `ORCH_DISTRIBUTION_TARGETS` map remains supported for the direct O-004 per-target
  POST seam; O-005 adds the registry-resolved coordinated path alongside it. The registry is
  the authoritative `sentinel_id → endpoint` source for coordinated pushes.
- SSRF validation is now a first-class boundary the Orchestrator owns; future outbound seams
  should route through `validate_endpoint`.
- The registry is operator-global; per-tenant scoping (so a tenant could constrain which
  Sentinels its policies reach) is deferred to O-006.
