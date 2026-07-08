"""Cross-module automation-rules engine (O-011, ADR-0011).

A tenant-scoped automation-rules engine that reacts to an event the Orchestrator already
ingests (O-003, from Delta/Rendly/Sentinel as source_product) by triggering exactly ONE
closed, pre-existing, already-audited Orchestrator action (re-driving an O-004 policy
distribution). This is NOT the roadmap's literal "cross-product workflow engine" — see
docs/adr/0011-automation-engine.md Honesty boundaries for the full, explicit scope
statement.
"""

from __future__ import annotations
