# ADR-0034 — Custom Client-Defined PII Engine (F-028)

- Status: Accepted (implemented)
- Date: 2026-07-09
- Builds on: ADR-0007 (F-005 orchestration hooks — the `PreRequestHook`
  interface + `HookRegistry` chain this new hook plugs into; the built-in
  Presidio `PIIHook` this runs alongside), ADR-0005 (tenant isolation — the
  RLS pattern the new table follows), ADR-0009 (F-008 per-tenant config
  precedent), ADR-0032/0033 (the operator-CLI + per-tenant-config-table +
  hot-reload-cache shapes reused here).
- Scope: `src/data_protection/custom_pii/` (new),
  `src/persistence/models/tenant_custom_pii_pattern.py` +
  `repositories/tenant_custom_pii_pattern_repository.py` + migration 0034,
  one additive hook registration in `src/orchestration/registry.py`. **No
  `contracts/` change** — reuses the existing `pii_blocked` event type.

## Context

Roadmap F-028: "Per-tenant custom PII patterns (regex + ML hooks). Depends
on F-005, F-008." The built-in F-005 detector
(`src/orchestration/detectors/pii_detector.py`) covers a fixed set of
Presidio entities (EMAIL, PHONE, CREDIT_CARD, …) — but every enterprise has
its own identifiers (employee IDs, internal account numbers, case numbers)
that Presidio will never know about. F-028 lets a tenant register their own
regex patterns so those are masked/blocked alongside the built-ins.

Two facts shaped the design:

1. **Presidio's `AnalyzerEngine` requires the `en_core_web_lg` spaCy model**,
   which is a heavy optional dependency (the `[pii-spacy]` extra; the slim
   image omits it) and cannot be downloaded in every environment. Custom
   patterns, however, are **pure regex** — they need no NLP engine. Binding
   custom-PII to Presidio would mean it only works where spaCy is installed.
2. **Sentinel accepts these regexes from clients** — and a regex is code.
   A careless or malicious pattern like `(a+)+$` causes catastrophic
   backtracking (ReDoS), which for a gateway on the request path is a
   denial-of-service. This is the single most important risk in the feature.

## Decision

### Standalone regex engine, NOT Presidio (`custom_pii/engine.py`)

The matcher is a pure function `scan(text, patterns) -> (spans, timed_out)`
built on the **`regex` module** (a new core dependency) — chosen over stdlib
`re` specifically for its per-call `timeout=`, which is a hard ReDoS backstop
`re` cannot provide. No Presidio, no spaCy, no DB — so custom-PII runs on the
slim image and is trivially unit-testable offline. Each pattern matches under
its own timeout budget; a pattern that times out is **isolated** (skipped +
its name returned for logging) so one pathological pattern never takes the
request — or the co-registered good patterns — down.

### Defense-in-depth against client-supplied regex

Three layers, because no single ReDoS control is sufficient:

1. **Registration-time validation** (`custom_pii/validator.py`): a pattern
   must compile under the same `regex` engine, stay within a length cap, and
   pass a nested-quantifier heuristic lint (`(a+)+`, `(a*)*`, `(.*)+`, …
   rejected) — all BEFORE it ever reaches the DB (mirrors F-026's "SSRF guard
   before any write").
2. **Runtime match timeout** (`engine.py`): the hard backstop for whatever
   slips past the heuristic. Proven: a catastrophic pattern on a 4 000-char
   input raises `TimeoutError` at 0.1 s and is isolated while a co-registered
   normal pattern still matches.
3. **Bounded surface**: a per-tenant active-pattern cap (default 50 — an
   unbounded set is an unbounded per-request cost, so this is a security
   control, not just UX) and a per-request inspected-char cap (default 50 000,
   mirrors F-005's `max_pii_inspect_chars`).

### Per-tenant storage + hot-reload (`tenant_custom_pii_patterns`, `loader.py`)

New RLS-scoped table (migration 0034), same shape/discipline as
`tenant_mcp_servers` (0033): `pattern_id` PK, `tenant_id` FK RESTRICT,
optional team/project scope, `name` (entity label), `pattern` (regex text),
`score`, per-pattern `action` override, `version` (hot-reload staleness
signal), `is_active` (soft-disable, no DELETE). `CustomPiiPatternLoader`
loads a tenant's active patterns, compiles them, and caches per-tenant for a
short TTL (default 30 s) — a pattern change lands in a live gateway within one
window (bounded-lag hot-reload, same rationale as F-027's keyvault cache).

### The hook (`custom_pii/hook.py`) — additive to the F-005 chain

`CustomPiiHook` is a `PreRequestHook` registered AFTER the built-in `PIIHook`
(order: SecretInbound → Injection → PII → **CustomPII**). It emits the SAME
contract-conformant `pii_blocked` event the built-in detector uses — so **no
`contracts/events.schema.json` change** is needed. Gated on its OWN
`custom_pii_enabled` setting, not `pii_detection_enabled`, precisely because
it is spaCy-independent (a slim deploy can run custom patterns with Presidio
off). Action resolution is strict: if ANY matched pattern resolves to `block`,
the whole request blocks, regardless of other matches.

**Fail posture — fail-degraded, NOT fail-closed (deliberate).** CLAUDE.md #5's
fail-closed rule is satisfied by the MANDATORY F-005 layer (secret/injection/
PII), which runs BEFORE CustomPII in the chain and blocks on its own inspection
error. Custom PII is an OPTIONAL, additive, per-tenant augmentation. If its
pattern STORE is transiently unreachable, the hook DEGRADES to pass-through
(loud ERROR log + a `custom-pii-load` failure metric) rather than fail-closed-
blocking 100% of the tenant's traffic — a custom-table blip must not become a
self-inflicted gateway outage (availability is also a security property, and
the mandatory layer already inspected this content). A genuine pattern MATCH
still fails closed (mask/block). *(This corrects the initial fail-closed-block
design, which — discovered via CI — turned any custom-PII load hiccup into a
500 for the whole request; see the git history of this ADR.)*

### `sentinel-pii` CLI (`custom_pii/cli.py`)

`add` / `list` / `revoke` / `test`. `test` runs the SAME engine the request
path uses so an operator can preview masking; the matched **value** is never
printed (only the entity label + span offsets — no plaintext PII in operator
output, CLAUDE.md #6).

## Honest scope & limitations

- **"regex + ML hooks" — the regex half is delivered in full; "ML hooks" is
  interpreted narrowly and deferred.** This ADR ships the client-defined
  REGEX engine (the concrete, buildable, ReDoS-hardened core). Wiring
  per-tenant custom patterns into Presidio as ad-hoc `PatternRecognizer`s so
  they compose with the NLP-based entities in one pass — the "ML hooks"
  reading — is a separate, spaCy-dependent enhancement documented in
  `docs/followups/f-028-presidio-adhoc-recognizers.md`. The two engines run
  independently today (built-in PIIHook, then CustomPiiHook), which is
  sufficient for the roadmap's stated goal and avoids coupling custom-PII to
  the heavy optional dependency.
- **The ReDoS heuristic is not exhaustive.** No static linter catches every
  catastrophic pattern; that is exactly why the runtime timeout (layer 2) and
  bounded input (layer 3) exist as backstops. The heuristic rejects the
  common footguns cheaply; the timeout covers the rest.
- **No admin HTTP route** — CLI-managed only, same reasoning and same
  followup pattern as ADR-0031/0032 (an admin API for the pattern table is
  `contracts/`-gated).
- **Regex only, no reversible tokenization vault** — `tokenize` here produces
  an inline `[TOKEN:...]` marker, not a vault-backed reversible token. True
  reversible tokenization is F-033's scope (ADR to come), which this table
  can later feed.
