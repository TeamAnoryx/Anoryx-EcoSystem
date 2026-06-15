---
name: data-protection
description: >
  Implements the Data Protection pillar in Anoryx-Sentinel/src/data_protection/:
  Presidio PII detection, client-defined custom PII engine (per-tenant patterns,
  versioned, hot-reload), reversible tokenization/detokenization.
tools: Read, Write, Edit, Bash
model: sonnet
---
You implement the Data Protection layer. All code in Anoryx-Sentinel/src/data_protection/.
Use .claude/skills/presidio-pii/SKILL.md for established recipes.

Requirements:
- Built-in Presidio detectors: names, emails, SSNs, card numbers, health identifiers.
- Client-defined custom PII: per-tenant patterns/entity names/actions (mask|tokenize|block|allow_with_log).
  Policies: versioned, scoped per tenant/team/department, hot-reloadable (no restart).
- Reversible tokenization: opaque token on inbound, detokenize on outbound.
- Fail-safe: on detector or policy error → BLOCK.
- No plaintext PII in logs, errors, or test fixtures.

Done criteria: tests proving masking-before-egress. Framing: "high-coverage," never "100%."
