# O-001 Orchestrator Internal API Contract — Independent Security Audit

**Verdict: CLEAN** (design-level, contract-only). Date: 2026-06-26.

## Scope of review (threat-modeled)

O-001 is **contract-only**: an OpenAPI 3.1 spec for three Anoryx-AI-Orchestrator seams plus
the transport security scheme. There is no runtime, persistence, or enforcement code yet
(O-003/O-004), so this is a **design-level** review of the contract against its own threat
model — the heavyweight independent-auditor *re-run* gate attaches when O-003/O-004 add
runnable enforcement.

Artifacts reviewed:
- `Anoryx-AI-Orchestrator/contracts/openapi.yaml` (3 seams + mutualTLS/HMAC/serviceToken)
- `Anoryx-AI-Orchestrator/docs/adr/0001-orchestrator-internal-api-contract.md` (forks + threat model)
- `Anoryx-AI-Orchestrator/tests/test_contract.py` + `pyproject.toml`
- `.github/workflows/orchestrator-ci.yml`

Locked references (must not be widened/copied): `Anoryx-Sentinel/contracts/events.schema.json`
(`sentinel:events:v1`), `policy.schema.json` (`sentinel:policy:v1`, F-008 `a9e2344`).

## Method

Arms-length: the security reviewer (separate from the author) re-read the files and
**re-validated each gate against the locked schemas independently**, not on the
coordinator's relayed claims. Empirical probing: confirmed `sign_on_behalf: true` is
schema-rejected; confirmed an unknown `policy_type` is rejected by the locked schema (no
widening); confirmed a structurally-valid-but-forged JWS passes schema (presence/format
only) and correctly relies on Sentinel `intake.py` to reject. The full O-001 contract
suite (13 tests) was executed by the reviewer: **13 passed**.

## Attack-surface findings

### 1. Peer spoofing — NO FINDING
mTLS authenticates the peer product on every operation; provisioning deferred to O-008
(boundary a, stated verbatim). Interim peer-auth (HMAC + service token) honestly disclosed;
the contract does not imply a live mTLS channel it does not have.

### 2. Replay — NO FINDING
Ingest HMAC binds `X-Sentinel-Timestamp` into the signed payload with a ±300s window
(F-020). In-window replay + durable cross-product dedup explicitly deferred to O-002;
`event_id` named as the dedup key and echoed on the 202.

### 3. Policy tampering / forged-signature pass-through — NO FINDING
The Orchestrator does NOT re-verify the compact-JWS at this seam; Sentinel `intake.py` is
the verifying authority that resolves authoritative scope from the signature and rejects
body-ID disagreement. Stated plainly in `info.description`, the path description, and ADR
#3. The schema enforces signature **presence/format only**; 202 means schema-valid-and-
accepted, NOT signature-verified. No path invites a forged policy to be treated as verified.

### 4. Unauthorized Delta read — NO FINDING (deferral disclosed)
Query seams require mTLS + service token and return **read-only metadata only**. The
service token is **coarse-grained** (no per-tenant read authz yet, deferred to O-006) — now
disclosed IN the contract (honesty boundary d) plus a per-operation caveat on both query
seams, not only in the ADR.

### 5. mTLS-not-yet-provisioned gap — NO FINDING (largest honesty boundary)
Declared but inert until O-008; stated verbatim (boundary a, ADR #5).

### 6. policy_type widening / schema smuggling — NO FINDING
No new `policy_type`; locked enum confirmed closed and unknown values rejected; external
`$ref`s target only the locked Sentinel files (test-enforced), `$id`s unchanged; all
Orchestrator-defined schemas are `additionalProperties: false` and bounded
(`maxLength`/`maxItems`/`maximum`).

### 7. sign_on_behalf — NO FINDING
Reserved OFF and now **schema-enforced** via `enum: [false]` (secure-by-construction);
enabling Orchestrator-signing requires a new ADR + a deliberate schema widen (boundary b).

## Findings table

| # | Severity | Status |
|---|----------|--------|
| sign_on_behalf prose-gated (schema accepted `true`) | Med | RESOLVED → `enum: [false]` |
| Coarse query-authz disclosed only in ADR | Low | RESOLVED → boundary (d) in contract + per-op caveat |
| Inert mTLS-only global default; test lacked 2nd-factor guard | Low | RESOLVED → test requires HMAC/serviceToken per op |
| (code-review) agent_id absent from EventMetadata | High | RESOLVED → added as slug + FilterAgentId |
| (code-review) IngestTimestamp 20-digit; codegen false-green | Low | RESOLVED → tightened pattern; codegen asserts a spec model |

No High/Critical findings remained after the fix pass. No human escalation triggered.

## Oversight verdicts

- **Independent code review:** APPROVE, 0 findings (after fix pass). HIGH (agent_id) resolved;
  no scope creep, no policy_type widening, no locked-schema modification, no dishonest language.
- **Independent security audit:** **CLEAN**, 0 findings (design-level), all prior Med/Low
  resolved and verified empirically; suite run by the auditor (13 passed).

## Residual deferrals (honestly disclosed, by design)

mTLS provisioning → O-008; cross-product envelope/replay/dedup → O-002; ingest pipeline →
O-003; distribution engine → O-004; registry → O-005; per-tenant query authorization →
O-006. Each is stated verbatim in the contract and/or ADR, not implied away.

## Conclusion

The O-001 contract is **CLEAN at design level**. Honesty boundaries (a)–(d) are present
verbatim in the binding contract; the locked F-002 schemas are referenced, not copied or
widened; every example validates unmodified; mutualTLS is declared and applied to every
operation with a real second factor enforced by the test gate.
