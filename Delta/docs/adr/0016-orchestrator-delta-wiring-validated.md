# ADR-0016 — Orchestrator ↔ Delta Wiring Validated (X-002, non-stubbed)

- Status: Accepted
- Date: 2026-07-09
- Task: X-002 (Cross-product integration, second of the X-001→X-003 killer-loop MVP;
  untagged in the roadmap checklist — not 🔮/🏦, so next-buildable)
- Depends on: O-003 (Orchestrator event ingest pipeline), D-004 (Delta event ingest)
- Builds on: Delta ADR-0004 (the consume seam: Orchestrator `forward_outbox` dispatcher →
  Delta `POST /v1/ingest/usage`, HMAC-authenticated, idempotent on `event_id`);
  Anoryx-AI-Orchestrator ADR-0016 (X-001, the sibling closure for the other cross-product
  pair — same shape of finding, opposite root cause)
- Delta-scoped numbering: this is Delta ADR **0016** (0001–0015 already assigned; see
  `docs/adr/` index). Delta does not extend the Orchestrator's or Sentinel's global ADR
  sequence.
- Supersedes: nothing. Adds one CI step; zero new tables, zero new migration, zero new
  endpoint, zero new production code, zero new test file.

## Context

Unlike X-001 (Sentinel→Orchestrator), where the non-stubbed proof did not exist and had to
be written, the Orchestrator→Delta direction already has one:
`Delta/tests/ingest/test_seam_e2e.py::test_real_orchestrator_to_delta_seam`, added under
D-004 (PR #41). It is fully non-stubbed — it HMAC-signs a usage envelope and POSTs it into
the REAL Orchestrator O-003 receiver, drains the REAL `orchestrator.dispatch.dispatcher.
dispatch_pending()` against the REAL Delta ingest app over an ASGI client, and asserts
exactly one balanced debit lands in the Delta ledger, twice (to prove the redelivery leg is
idempotent).

**The gap is not the proof — it is that CI never runs it.** The file's own
`pytestmark = pytest.mark.skipif(...)` self-skips unless BOTH `APP_DATABASE_URL` (Delta) and
`ORCH_APP_DATABASE_URL` (Orchestrator) are set. Auditing every job across
`.github/workflows/delta-ci.yml` and `orchestrator-ci.yml`:

- `ledger-db` sets `APP_DATABASE_URL` only → `test_seam_e2e.py` skips (silently, exit 0).
- `delta-o004-integration` sets **both** URLs (it stands up `orch_dev` for the *reverse*
  direction, D-005/O-004) but its one `run:` step names `tests/budget_engine/
  test_o004_e2e.py` explicitly — `test_seam_e2e.py` is never invoked, let alone collected.
- `orchestrator-ci.yml` has no reference to Delta at all.

So this specific non-stubbed, already-written proof of the X-002 seam has never once
executed in CI since it was merged. This is exactly the failure mode the roadmap's banked
rule #11 names ("gate new test lanes in CI — verified to execute, not skip") and the one
CRIT-2/F-018 nearly shipped inert on: a real assertion that silently never runs is
indistinguishable from green until someone reads the job list line by line.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — write a new test, or gate the existing one | **A1**: gate the existing one. `test_seam_e2e.py` already drives the real dispatcher and the real Delta ingest app with no shortcuts (verified by reading it end-to-end); writing a second, near-identical file would duplicate coverage without closing the actual gap, which is purely CI wiring. |
| **B** — which job hosts the new step | **B1**: add a step to the existing `delta-o004-integration` job rather than standing up a new job. That job already provisions the exact two-DB harness (`delta_dev` + `orch_dev`, both app roles SCRAM-provisioned, both packages installed) `test_seam_e2e.py` needs — duplicating the `services:`/`env:`/install block in a sibling job would be pure copy-paste with no isolation benefit (both directions target the same two ephemeral DBs in the same CI run). The job's header comment is updated to describe both directions it now proves rather than renaming it (a rename would change the CI check name a branch-protection rule may reference). |
| **C** — prove the step itself doesn't silently skip | **C1**: the new step greps the pytest summary line for the literal `^1 passed` and fails the step if absent, instead of trusting pytest's exit code alone. `pytest.mark.skipif` exits 0 on an all-skipped run — the same trap this ADR exists to close. A future accidental unset of `ORCH_APP_DATABASE_URL` in this job now fails loudly instead of returning to silent-green. |
| **D** — scope boundary (what this does NOT newly prove) | **D1**: this ADR gates an existing proof; it does not extend what `test_seam_e2e.py` asserts. It does not prove Delta's budget engine (D-005) or kill-switch (D-006) evaluation — those consume the ledger this seam posts to, and are tested independently. It does not prove mTLS (deferred to O-008, same honesty boundary as ADR-0004 §3.3 — the interim HMAC secret-holder is the authenticated peer). |

## What this proves (and what it doesn't)

**Proves:** a usage event accepted by the real Orchestrator O-003 receiver is durably
persisted, marked `forward_outbox.status='pending'`, drained by the real D-004 dispatcher,
HMAC-signed, and POSTed into the real Delta ingest app — landing as exactly one balanced
double-entry debit (2 entries, `Σdebit == Σcredit`) in that tenant's ledger; that the
`forward_outbox` row flips to `'forwarded'` only after a verified 2xx ack; and that
redelivering the identical envelope (Orchestrator-side dedup + a second drain) is
end-to-end idempotent — the ledger still holds exactly one debit, not two. And — the actual
subject of this ADR — that this proof now **executes** in CI on every PR touching
`Delta/**`, `Anoryx-AI-Orchestrator/**`, or `Anoryx-Sentinel/contracts/**`, rather than
existing in the tree unexercised.

**Does not prove (honesty boundary, non-removable):** Delta's D-005 budget engine or D-006
kill-switch correctness (tested independently against the ledger this seam populates); that
mTLS peer authentication works (deferred to O-008, per ADR-0004 §3.3 — until then the HMAC
secret-holder is the authenticated peer); that a live Orchestrator deployment actually drains
`forward_outbox` on a running schedule in production today (the dispatcher is a single-pass
drain, `dispatch_pending(limit)`, "not a long-running daemon" by ADR-0004 §3.1 §1 — scheduling
it as a recurring job in a real deployment is O-008/D-010 infra work, not attempted here).

## Testing

`Delta/tests/ingest/test_seam_e2e.py::test_real_orchestrator_to_delta_seam` (pre-existing,
D-004/PR #41 — unchanged by this ADR) now runs as a new step in the `delta-o004-integration`
job in `.github/workflows/delta-ci.yml`:

- Verified locally against a real Postgres 16 instance (migrated to head for both `delta_dev`
  and `orch_dev`, both app roles SCRAM-provisioned exactly as the CI job provisions them): the
  test passes in isolation.
- The new CI step's exact command (`pytest ... | tee ...; grep -qE "^1 passed" ...`) was run
  locally byte-for-byte and confirmed to both pass the test and satisfy the anti-silent-skip
  grep.
- `ruff check Delta` and `black --check Delta` — clean (only the workflow YAML and this ADR
  are new; no Python source changed).

## Out of scope (do not build here)

A second, hand-authored ingest-seam test (Fork A); a new/renamed CI job (Fork B); any change
to `Delta/src/`, `Anoryx-AI-Orchestrator/src/`, `Anoryx-Sentinel/contracts/`, or
`policy.schema.json` (none are touched — this closes a CI-gating gap only); scheduling the
dispatcher as a recurring production job (O-008/D-010); mTLS (O-008).

## Consequences

- X-002 is proven, not merely asserted: the already-written, already-correct
  Orchestrator→Delta seam test now actually executes on every relevant PR, closing the same
  class of gap X-001 closed for the other direction (a real proof that silently never ran).
- This narrows what's left for X-003 (the budget-enforcement killer loop) to genuinely new
  work: X-001 and X-002 both now demonstrably prove their respective legs of
  `Sentinel → Orchestrator → Delta` are wire-compatible and continuously verified.
