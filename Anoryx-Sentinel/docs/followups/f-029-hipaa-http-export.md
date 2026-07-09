# Follow-up: HIPAA over the HTTP compliance-export surface

**Context:** F-029 (ADR-0035) ships the HIPAA framework as a first-class
control map usable via the CLI (`sentinel-cli compliance evidence --framework
HIPAA`, `sentinel-hipaa baa-summary`) and the whole F-011 engine (mapping / gap
analysis / evidence pack). What it does NOT do is expose HIPAA over the HTTP
compliance-export endpoints.

**Why deferred:** `src/gateway/routes/compliance.py` validates the `framework`
query/body param against a hardcoded `("SOC2", "ISO27001")` tuple, and
`contracts/openapi.yaml` pins the same `enum: [SOC2, ISO27001]` in two places
(the `/v1/compliance/evidence` and `/v1/compliance/export` parameter schemas).
`contracts/openapi.yaml` is api-architect-owned and hook-protected; extending
the enum is a contract change that path could not make this session (the
`ANORYX_ACTIVE_AGENT` propagation gap documented in ADR-0031/0032).

**What it takes once the contract gap closes** (small, well-scoped):

1. api-architect adds `HIPAA` to the `framework` enum in the two
   `contracts/openapi.yaml` parameter schemas (and updates the "v1 frameworks
   are SOC2 + ISO27001 ONLY" descriptive text).
2. In `routes/compliance.py`, change the two hardcoded `("SOC2", "ISO27001")`
   membership checks (the `ExportRequest._validate_framework` validator and the
   `GET /v1/compliance/evidence` handler) to accept HIPAA — ideally by
   referencing `compliance.constants.FRAMEWORKS` so the route and the engine
   never drift again.
3. No engine work: `load_framework("HIPAA")` / `generate_evidence` /
   `analyze_gaps` / the evidence-pack export already handle HIPAA today (proven
   by the CLI path). Only the route's allow-list and the contract enum gate it.

Note: the BAA-specific rendering (`hipaa/baa_export.py`) is a HIPAA-only
document shape; if it should also be HTTP-exposed, that is a NEW response schema
(a `sentinel-hipaa-baa-evidence/v1` body) and therefore a larger contract
addition than merely widening the framework enum — worth a separate decision.
