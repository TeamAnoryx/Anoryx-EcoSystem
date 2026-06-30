# O-005 Security Audit — Multi-Sentinel Coordination

- Task: O-005 (registry + health + coordinated push), ADR-0005
- Branch: `task/O-005-coordination` · PR #43 · base `main`
- Gate: penultimate (independent code-review + arms-length security audit), blocking
- Verdict: **CLEAN** (no High/Critical). Code-review findings and audit findings addressed or explicitly deferred with rationale below.

## Method

Two independent reviewers, neither of which wrote the code:

- **code-reviewer** — correctness, contract-conformance, maintainability. Read the full
  `origin/main..HEAD` diff.
- **security-auditor** — arms-length red-team. Verified the SSRF control **by direct execution**
  (ran the validator against an IP-literal bypass matrix incl. `169.254.169.254`, IPv4-mapped
  `::ffff:169.254.169.254`, NAT64 `64:ff9b::169.254.169.254`, 6to4, ULA, `::`, `::1`; a full URL
  battery with embedded creds / fragment / decimal-hex-octal IP forms / `127.0.0.1.nip.io` /
  scheme-relative / credential tricks; and a urlsplit-vs-httpx parser-differential). Ran
  `semgrep p/python p/security-audit p/secrets --severity=ERROR` over all changed source files
  (0 findings). Traced every outbound path + trust boundary.

## Fresh-DB execution (authority)

Per the task, **CI on a fresh Postgres is the authority** ("local green proves nothing"). The
author's host could not run the DB suite (Docker-Desktop-Windows host→container port-forward
failure); both reviewers also could not stand up a local Postgres here. The authoritative
fresh-DB run is therefore CI:

- **Integration lane (fresh Postgres): 214 passed, 0 skipped**, with
  `ORCH_REQUIRE_COORDINATION_E2E=1`. That flag turns the coordination e2e's skip-gate into a hard
  failure, so the non-stubbed coordination + health e2e, registry-CRUD, and migration round-trip
  **provably executed** on a fresh DB.
- The auditor confirmed the e2e is **genuinely non-stubbed** by reading it: real uvicorn loopback
  servers on ephemeral TCP ports, real httpx calls into Sentinel's REAL `intake_policy` (ES256
  verify + persist) and `evaluate_model_policies`, real health-state transitions across ≥3
  instances, and tenant RLS asserted via a raw `orchestrator_app` (NOBYPASSRLS) connection.
- The load-bearing SSRF property was validated by direct execution (above), which is stronger
  than a DB run for that control.

## What both reviewers verified CLEAN

- **SSRF** holds against every concrete bypass thrown at it. Re-validation occurs before every
  outbound use (`health._probe_one`, `coordinator._select_targets`) against the live allowlist,
  so a post-registration row mutation or allowlist change is re-checked at use.
- **AuthZ** — `router._require_admin` is fail-closed (unconfigured `ORCH_ADMIN_TOKEN` → 401
  before any compare; missing/empty → 401; mismatch → 403), constant-time, keyed on a token
  distinct from the peer `ORCH_SERVICE_TOKEN`. All seven routes gate before any work.
- **Audit integrity** — BEFORE UPDATE *and* DELETE deny-triggers; `validate_registry_chain` has
  the BYPASSRLS fail-loud guard; SSRF-rejected registrations are recorded `disposition='rejected'`
  with the attempted endpoint + reason; opt-in-when-present hashing is correct.
- **Tenant isolation** — coordinated-push distribution rows are written under
  `get_tenant_session` (RLS); `tenant_id` is server-resolved, never a client header; the registry
  is operator-global and holds no tenant data.
- **Consumes O-004 unchanged** — `distribution/engine.py` and `distribution/router.py` are
  byte-identical to `main`; no double-begin under `get_tenant_session` (ADR-0026).

## Findings + disposition

### Code-review

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| CR-1 | High | The seven new runtime routes were absent from the Orchestrator `contracts/openapi.yaml` (O-003/O-004 routes are present there — precedent). | **FIXED** — added the 7 paths + `SentinelRegistryEntry` schema + an operator bearer securityScheme to `contracts/openapi.yaml`; the contract lane validates it. |
| CR-2 | Med | `socket.getaddrinfo` (sync, blocking) called inside async coroutines. | **FIXED** — added `validate_endpoint_async` (offloads to the thread-pool executor); `health` + `registry` use it, and `coordinate_push` offloads `_select_targets` via `run_in_executor`. The sync `validate_endpoint` is kept for the unit matrix. |
| CR-3 | Med | `assert created/updated is not None` post-commit is `-O`-strippable. | **FIXED** — replaced with explicit `if … is None: raise RuntimeError(...)` in register + modify. |
| CR-4 | Low | `deregister_sentinel` took an unused `settings` arg. | **FIXED** — removed (deregistration makes no outbound call). |
| CR-5 | Low | No per-route request-body size cap. | **FIXED** — `_parse_object_body` caps at 64 KiB → 413 `request_too_large`. |

### Security audit

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| SA-1 | Med | DNS-rebinding connect-time TOCTOU: `validate_endpoint` resolves + checks, but returns the hostname URL and httpx re-resolves at connect — the validated IP is not pinned, so a public→internal rebind between validation and connect could bypass the block (and leak `SENTINEL_ADMIN_TOKEN` to the rebind target on the distribution path). | **PARTIALLY ADDRESSED + DEFERRED.** Re-validation closes the steady-state case. The connect-time IP-pinning fix touches the outbound httpx call sites — and the distribution POST lives in **O-004's `engine.py`, which O-005 consumes UNCHANGED** (out of scope). Deferred to **O-008** (owns outbound transport security / mTLS). The ADR-0005 threat table was corrected (the "mitigated" claim was overstated) and a Residual-Risk section added. Operationally constrained: registration is operator-gated, the prod default allowlist is empty (only public https registers), and it requires DNS control over an operator-chosen host plus a sub-second race. Operators should prefer IP-literal endpoints. |
| SA-2 | Low | O-004's static-targets outbound path (`ORCH_DISTRIBUTION_TARGETS`) is not routed through `validate_endpoint`. | **DEFERRED** (pre-existing O-004 behaviour, operator-config-controlled; O-004 is consumed unchanged). Note for O-006/O-008. Documented in ADR Residual Risk. |
| SA-3 | Low | Append-only audit relies on the runtime DB role not being a SUPERUSER (a superuser could disable the deny-triggers). | **DEFERRED** to deploy/O-008 (role provisioning). Consistent with the existing ingest/distribution chains. Documented in ADR Residual Risk. |

No High or Critical findings → no human-escalation trigger.

## Post-fix verification

- 160 unit tests pass (SSRF matrix incl. the async wrapper; selection + staleness; registry
  hash-chain; config parsing; router auth 401/403/fail-closed + 413 body cap); ruff clean;
  black (CI's `<26`) clean; single migration head `0004_sentinel_registry`.
- The fix batch re-runs both CI lanes on the PR (fresh Postgres); the integration lane re-executes
  the non-stubbed coordination e2e under `ORCH_REQUIRE_COORDINATION_E2E=1`.
