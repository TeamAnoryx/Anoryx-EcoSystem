# ADR-0016 — Sentinel ↔ Orchestrator Wiring Validated (X-001, non-stubbed)

- Status: Accepted
- Date: 2026-07-09
- Task: X-001 (Cross-product integration, first of the X-001→X-003 killer-loop MVP;
  untagged in the roadmap checklist — not 🔮/🏦, so next-buildable)
- Depends on: F-005 (Sentinel orchestration hooks/detectors), O-003 (Orchestrator event
  ingest pipeline)
- Builds on: ADR-0002 (O-002 event-envelope contract), ADR-0003 (O-003 ingest pipeline —
  the HMAC scheme this ADR reuses verbatim, documented there as "mirrors the F-020
  outbound signer contract")
- Supersedes: nothing. Adds one new test file; zero new tables, zero new migration, zero
  new endpoint, zero new production code.

## Context

Every existing O-003 ingest test (`tests/integration/test_ingest_e2e.py`) drives the real
receiver → pipeline → Postgres path with a HAND-TYPED envelope from the `make_valid_envelope`
fixture. That fixture is useful for pipeline-internals coverage (dedup, DLQ reasons, RLS,
hash-chain tamper-evidence — see ADR-0003), but it is not itself Sentinel code: nothing in
the existing suite proves that an event Sentinel's own F-005 detectors and `HookContext`
stamping logic actually *produce* is shaped the way this fixture assumes, or that Sentinel's
own F-020/ADR-0002 HMAC signer (`orchestration.webhooks.signer.sign_body`) produces a
signature Orchestrator's receiver (`hmac_verify.verify_ingest_signature`) actually accepts.
The reverse direction (Orchestrator driving Sentinel's real `intake_policy()` over a genuine
loopback shim) has exactly this proof for O-004/O-009/O-011 (`sentinel_shim_server`,
`test_distribution_e2e.py`); X-001 closes the same gap for the ingest direction.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — how to obtain a "genuine" Sentinel event without a live Sentinel deployment | **A1**: drive Sentinel's REAL, installed F-005 code in-process — `SecretInboundHook.inspect()` (regex + Shannon-entropy detector, no ML/network dependency) against an OpenAI-key-shaped string, then `HookContext._stamp_event()` (the exact stamping logic `HookContext.emit()` runs before appending to the audit log) — imported unmodified from the `anoryx-sentinel` package the orchestrator-integration CI lane already installs (`pip install -e ../Anoryx-Sentinel[dev]`, per `.github/workflows/orchestrator-ci.yml`). Nothing about the event shape is hand-typed by the test. |
| **B** — which detector to drive | **B1**: `SecretInboundHook`, not the PII detector. The PII detector's Presidio/spaCy backend lives in the optional `pii-spacy` extra, which the `[dev]` install this CI lane uses does not pull in; the secret detector is pure regex + math and has zero optional-dependency risk. |
| **C** — signing | **C1**: Sentinel's REAL `orchestration.webhooks.signer.sign_body`, not a hand-rolled HMAC in the test. ADR-0003 already documents this as the mirrored contract for this seam (`HMAC-SHA256(secret, f"{ts}.{body}")`, `X-Sentinel-Signature`/`X-Sentinel-Timestamp`); this test is the first thing in the repo that actually calls it against Orchestrator's real verifier rather than asserting the two implementations *should* agree. |
| **D** — scope boundary (what this does NOT re-prove) | **D1**: this suite does not re-drive Sentinel's own audit-log append / hash-chain path. Sentinel's own non-stubbed suite (`Anoryx-Sentinel/tests/orchestration/test_integration.py`) already proves that in-product path exists and is correct; re-proving it here (which would require standing up Sentinel's own DB and privileged session inside this repo's test run) would duplicate coverage without validating anything new about the *wiring* — X-001's actual subject. Stated here per the roadmap's "Done means... (7) demoable end-to-end" bar and this codebase's honesty-boundary convention (F-018/F-020/O-009→O-014 precedent): the boundary is named, not implied away. |
| **E** — engine-cache hygiene | **E1**: the new `app` fixture calls `orchestrator.persistence.database.reset_engines()` before constructing the app. This test file collects alphabetically after `test_migration_roundtrip.py`, whose downgrade/upgrade cycle drops and recreates every table; a connection pool populated before that cycle (by an earlier test in the same session) is reused by SQLAlchemy's engine-singleton cache otherwise, surfacing as an intermittent `permission denied for table ingest_events` 503 that is unrelated to any real grant defect (verified empirically: `has_table_privilege` on a fresh connection returns true throughout). This mirrors the "ENGINE RESET (ADR-0026 / F-007 lesson)" discipline already documented in `tests/integration/conftest.py`. |

## What this proves (and what it doesn't)

**Proves:** a genuinely Sentinel-produced `secret_leaked` event — real detector output, real
`HookContext` stamping, real four-stable-ID resolution, real F-020 HMAC signature — wrapped
in the real O-002 envelope, is accepted end-to-end by Orchestrator's real receiver → pipeline
→ Postgres, with `tenant_id`/`team_id`/`project_id`/`event_id`/`request_id` preserved
byte-for-byte across the product boundary; that RLS scopes the resulting row to the tenant_id
Sentinel's own code resolved (not a test double); and that a byte tampered after Sentinel's
real signature is computed is rejected (403) before anything is persisted.

**Does not prove (honesty boundary, non-removable):** Sentinel's own audit-log append/hash-chain
correctness (Sentinel's own suite proves that); that mTLS peer authentication works (deferred to
O-008, per ADR-0003's own honesty boundary — the interim HMAC secret-holder is the authenticated
peer); that a live Sentinel deployment actually calls this signer against Orchestrator's real
`/v1/ingest/events` URL in production today (no such caller exists yet — F-005's description
still reads "Redis Streams emission deferred (webhook config path)"; wiring an actual Sentinel→
Orchestrator emitter into production traffic is calling-code work, not proven or attempted here).

## Testing

`Anoryx-AI-Orchestrator/tests/integration/test_sentinel_wiring_e2e.py`
(`pytest.mark.integration`, gated on Postgres reachability like every sibling e2e in this
suite — no new `ORCH_REQUIRE_*` env flag, since this proves an existing seam's compatibility
rather than gating a new autonomous behavior):

- `test_real_sentinel_event_ingested_end_to_end` — accept, persist, chain-valid.
- `test_real_sentinel_event_rls_isolated_by_its_own_tenant_id` — RLS scoped to Sentinel's
  own resolved tenant_id, live via the `orchestrator_app` (NOBYPASSRLS) role.
- `test_tampered_real_sentinel_event_rejected_before_persist` — a post-signature byte flip
  is rejected (403), nothing persisted.

Verified locally against a real Postgres 16 instance (CI's exact `orchestrator-integration`
env/role/migration setup, both `[dev]` extras installed): the new file passes in isolation,
and the full `pytest tests` suite (613 tests) passes with it included, run three times to
rule out the flake this ADR's Fork E fixes.

## Out of scope (do not build here)

An actual Sentinel→Orchestrator production emitter/adapter (F-005's own deferred webhook-config
path); mTLS peer provisioning (O-008); PII-detector-driven coverage (Fork B); any change to
`Anoryx-Sentinel/contracts/` or `policy.schema.json` (neither is touched — this test only
imports already-shipped Sentinel code and reads the existing `events.schema.json`/
`event-envelope.schema.json` contracts).

## Consequences

- X-001 is proven, not merely asserted: the roadmap's first Cross-product task closes with a
  concrete, non-stubbed demonstration that Sentinel's real event shape and real signer are
  wire-compatible with Orchestrator's real ingest pipeline — the prerequisite the roadmap
  names for X-003 (the budget-enforcement killer loop) to be trustworthy in the other
  direction too.
- The engine-reset fix (Fork E) is a general hygiene improvement any future ingest-path test
  file sorting after `test_migration_roundtrip.py` benefits from, not a special case.
