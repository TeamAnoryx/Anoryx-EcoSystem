# Follow-up: EU AI Act over the HTTP compliance-export surface

**Context:** F-030 (ADR-0036) ships the EU AI Act as a first-class framework
usable via the CLI (`sentinel-cli compliance evidence --framework EU_AI_ACT`,
`sentinel-euaiact`) and the whole F-011 engine. It does NOT expose EU_AI_ACT
over the HTTP compliance-export endpoints — the same deferral as HIPAA (F-029).

**Why deferred:** `src/gateway/routes/compliance.py` validates `framework`
against a hardcoded `("SOC2", "ISO27001")` tuple, and `contracts/openapi.yaml`
pins `enum: [SOC2, ISO27001]` in the `/v1/compliance/evidence` and
`/v1/compliance/export` parameter schemas. Extending the enum is an
api-architect `contracts/openapi.yaml` change unavailable this session (the
`ANORYX_ACTIVE_AGENT` propagation gap, ADR-0031/0032).

**What it takes** (identical to `f-029-hipaa-http-export.md`): api-architect
widens the two `framework` enums to include `HIPAA` and `EU_AI_ACT` (ideally the
route then references `compliance.constants.FRAMEWORKS` so route and engine
never drift), and the two hardcoded membership checks in `routes/compliance.py`
are updated. No engine work — `load_framework("EU_AI_ACT")` and the whole
evidence/gap/pack pipeline already handle it (proven by the CLI path).

**Note on the F-030-specific artifacts:** the classification helper and the
Article 13 disclosure template are NOT gap-report shapes — if they should be
HTTP-exposed, each is a NEW request/response schema (a
`sentinel-eu-ai-act-art13-disclosure/v1` body, a classification request/response)
and therefore a larger, separate contract addition than merely widening the
framework enum. Worth its own decision when the contract path is available.
