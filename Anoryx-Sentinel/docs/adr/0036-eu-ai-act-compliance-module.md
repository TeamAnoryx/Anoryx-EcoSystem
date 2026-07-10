# ADR-0036 — EU AI Act Compliance Module (F-030)

- Status: Accepted (implemented)
- Date: 2026-07-09
- Builds on: ADR-0013 (F-011 compliance evidence engine — the framework-map /
  gap-analysis / evidence machinery this extends), ADR-0035 (F-029 HIPAA — the
  identical "new framework as a control-map YAML + registration + CLI, no
  contracts change" pattern this repeats), ADR-0003 (F-003 hash-chained audit
  log — the technical mechanism behind the Article 12 record-keeping evidence).
- Scope: `src/compliance/frameworks/eu_ai_act.yaml` (new control map),
  `src/compliance/eu_ai_act/` (new — classification, disclosure, CLI), plus
  three one-line registrations (`constants.FRAMEWORKS`, mapping-schema enum,
  compliance CLI `_FRAMEWORKS`). **No `contracts/` change.**

## Context

Roadmap F-030: "EU AI Act mappings, high-risk classification helpers, Article 13
disclosure templates. Depends on F-011." Three sub-deliverables, all
contract-free on top of the shipped F-011 engine.

The framing constraint is even sharper than HIPAA's: **most EU AI Act
obligations are process/governance duties of the provider or deployer**
(conformity assessment, quality-management system, risk-management system,
human-oversight staffing). Sentinel is an application-layer gateway; it supplies
technical evidence for the subset it can — most directly the **Article 12
record-keeping (logging)** obligation, plus Article 15 robustness/cybersecurity
— and must be scrupulously honest about the large remainder it does not.

## Decision

### 1. EU AI Act control map (`frameworks/eu_ai_act.yaml`)

An 11-control map over the Chapter III Section 2 high-risk obligations, keyed by
article (Art.12 record-keeping, Art.15 accuracy/robustness/cybersecurity, Art.10
data governance, Art.14 human oversight, Art.13 transparency, Art.26 deployer
obligations, Art.19 log retention), with honest `not_covered` for the
process-only obligations Sentinel merely feeds (Art.9 risk-management system,
Art.50 app-layer transparency) and `not_applicable` for pre-market provider
processes (Art.43 conformity assessment, Art.17 QMS). Article 12 is the control
Sentinel most directly evidences: the append-only hash-chained audit log IS the
"automatically generated logs" the article requires. **Every
`evidence_event_types` value is an EXISTING `VALID_EVENT_TYPES` member** — no
`contracts/events.schema.json` change (enforced by a test). Registered by adding
`"EU_AI_ACT"` to `FRAMEWORKS`, the mapping-schema enum, and the CLI framework
list; the engine handles it with zero code changes.

### 2. High-risk classification helper (`eu_ai_act/classification.py`)

`classify(use_case_tags)` screens a list of CONTROLLED tags (a curated
vocabulary drawn from Article 5 prohibited practices and Annex III high-risk
categories) into a likely tier: `prohibited` > `high_risk` > `limited_or_minimal`.
Returns the matched article references and an obligations hint pointing at the
Chapter III Section 2 duties (and at Sentinel's Art.12/Art.15 evidence). This is
**decision SUPPORT, not legal advice** and not a conformity assessment — the
definitive classification is the operator's legal determination; every result
carries that disclaimer. Unknown tags are ignored-and-noted, never guessed.

### 3. Article 13 disclosure template (`eu_ai_act/disclosure.py`)

`build_disclosure(...)` generates a structured "instructions for use" TEMPLATE:
the Sentinel-evidenced sections (record-keeping via Art.12, human-oversight
control point via F-008, input/output controls via F-005/F-007) are pre-filled;
every provider-supplied field (intended purpose, accuracy metrics, known
limitations) is an explicit `<<PROVIDER TO COMPLETE>>` placeholder. It is a
documentation AID that scaffolds the disclosure, NOT a completed Article 13
disclosure — stated in the framing and the disclaimer.

### 4. `sentinel-euaiact` CLI (`eu_ai_act/cli.py`)

`classify` / `list-tags` / `disclosure`. The framework's per-control evidence is
also available via `sentinel-cli compliance evidence --framework EU_AI_ACT`.

## Honest limitations

- **CLI/engine only — no HTTP export.** The compliance-export route's
  `framework` enum is `contracts/openapi.yaml`-bound (api-architect-owned), so
  EU_AI_ACT over HTTP is deferred (same as HIPAA F-029), see
  `docs/followups/f-030-eu-ai-act-http-export.md`.
- **Sentinel evidences a SMALL slice of the EU AI Act.** The large majority of
  obligations — conformity assessment, QMS, the risk-management system, technical
  documentation (Art.11), post-market monitoring (Art.72), fundamental-rights
  impact assessment (Art.27) — are provider/deployer processes outside a
  runtime gateway's boundary. The control map reports these honestly as
  `not_covered`/`not_applicable`; this module does not claim otherwise.
- **The classification helper is decision support, not a legal determination.**
  It screens a controlled tag vocabulary; it cannot read free-text use-case
  descriptions, does not cover every Annex III sub-case, and is explicitly not
  legal advice.
- **This is audit-preparation / due-diligence evidence, not conformity.** The EU
  AI Act has a conformity-assessment + CE-marking regime; nothing here produces
  or substitutes for that.
