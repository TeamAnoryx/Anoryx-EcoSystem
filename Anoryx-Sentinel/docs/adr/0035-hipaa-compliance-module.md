# ADR-0035 — HIPAA Compliance Module (F-029)

- Status: Accepted (implemented)
- Date: 2026-07-09
- Builds on: ADR-0013 (F-011 compliance evidence engine — the framework-map/
  gap-analysis/evidence machinery this extends), ADR-0034 (F-028 custom-PII
  ReDoS-safe regex engine, reused for the built-in PHI pattern set), ADR-0003
  (F-003 hash-chained audit log — the technical mechanism behind the
  §164.312(b) audit-control attestation).
- Scope: `src/compliance/frameworks/hipaa.yaml` (new control map),
  `src/compliance/hipaa/` (new — PHI patterns, BAA export, CLI), plus three
  one-line registrations (`constants.FRAMEWORKS`, `frameworks/
  mapping.schema.json` enum, `compliance/cli.py` `_FRAMEWORKS`). **No
  `contracts/` change.**

## Context

Roadmap F-029: "HIPAA control mappings on F-011, PHI patterns, BAA-ready audit
format. Depends on F-011, F-028." Three sub-deliverables, all achievable
contract-free on top of the shipped F-011 engine and F-028 custom-PII engine.

Two constraints shaped the design:

1. **The HTTP export surface is contract-bound.** `routes/compliance.py` and
   `contracts/openapi.yaml` both pin the export `framework` param to
   `enum: [SOC2, ISO27001]`. Adding HIPAA to the HTTP route needs an
   api-architect `contracts/openapi.yaml` change — the same gap that scoped
   F-025/F-026/F-027. So HIPAA ships **CLI + engine only**; the HTTP route is
   untouched (it hardcodes its own tuple, decoupled from `FRAMEWORKS`).
2. **HIPAA has no certification.** The honest-language rule (CLAUDE.md) is
   sharper here than for SOC2/ISO: HIPAA compliance is not certifiable, so
   every artifact frames output as BAA due-diligence / audit preparation, never
   "HIPAA compliant."

## Decision

### 1. HIPAA control map (`frameworks/hipaa.yaml`)

A first-class framework map (13 controls) covering the §164.312 Technical
Safeguards Sentinel most directly evidences (Access Control, Audit Controls,
Integrity, Authentication) plus the §164.308 Administrative Safeguards it
technically evidences (activity review, access authorization, log-in
monitoring, incident procedures). Physical/workforce safeguards are explicitly
`not_applicable`; transmission security and the ePHI contingency plan are
honestly `not_covered` (no fabricated coverage — R8). **Every
`evidence_event_types` value is an EXISTING member of `VALID_EVENT_TYPES`**, so
no `contracts/events.schema.json` change is needed (verified by a test).
Registered by adding `"HIPAA"` to `FRAMEWORKS`, the mapping-schema enum, and
the CLI framework list — `load_all()`/`load_framework()` then handle it with
zero engine changes.

### 2. Built-in PHI patterns (`hipaa/phi_patterns.py`)

A curated, version-controlled set of common structured PHI identifiers (SSN,
Medicare MBI, DEA, NPI, MRN, ICD-10, health-plan IDs) matched by **reusing
F-028's ReDoS-safe engine** (`data_protection.custom_pii.engine`) — same
compile + per-match-timeout backstop — but sourced from this built-in set
rather than F-028's per-tenant DB. Context-labelled where a bare token would be
too ambiguous (MRN/NPI/plan-IDs require a nearby label, so an unlabelled
10-digit run is NOT flagged as an NPI). Each pattern is validated by F-028's
validator at import (fail-loud on a malformed addition). Honest scope: this is
HIGH-COVERAGE detection of structured identifiers, NOT "100% PHI detection";
free-text PHI is F-005's PERSON/LOCATION job, and de-identification under
§164.514 remains the covered entity's determination.

### 3. BAA-ready evidence summary (`hipaa/baa_export.py`)

Pure functions over a `GapReport` (no DB, no I/O) that render a
Business-Associate-Agreement-oriented document: readiness, a Technical-
Safeguards (§164.312) breakdown, an **audit-control attestation** grounded in
the F-003 hash-chain (the technical mechanism for §164.312(b)), a PHI-safeguard
statement grounded in the built-in pattern set, and mandatory honest framing
(HIPAA has no certification; a signed BAA + full safeguard program remain the
operator's responsibility). Markdown or JSON.

### 4. `sentinel-hipaa` CLI (`hipaa/cli.py`)

`phi-scan` (preview PHI detection; matched values never printed) and
`baa-summary` (render the BAA document over an audit-log window). The HIPAA
framework's per-control evidence is also available via the generic
`sentinel-cli compliance evidence --framework HIPAA`.

## Honest limitations

- **No HTTP export for HIPAA** — CLI/engine only, because the export route's
  `framework` enum is `contracts/openapi.yaml`-bound (api-architect-owned).
  Deferred to `docs/followups/f-029-hipaa-http-export.md`. Adding HIPAA to the
  route is a ~2-line change once the contract enum is extended.
- **PHI detection is high-coverage, not exhaustive** — structured identifiers
  only; free-text PHI relies on F-005, which is itself not exhaustive.
- **This is audit-preparation / BAA-due-diligence evidence, not a compliance
  attestation.** HIPAA has no certification; the administrative and physical
  safeguard program, risk analysis (§164.308(a)(1)(ii)(A)), and a signed BAA
  are the operator's responsibility and outside Sentinel's evidence boundary.
