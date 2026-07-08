"""Command center (O-014, ADR-0014): a read-only fleet-health summary over metrics the
Orchestrator already collects, plus one guarded, OPERATOR-TRIGGERED policy-distribution
rollback action.

NOT the roadmap's literal "comprehensive command center... across all products" (Delta
and Rendly do not push telemetry into the Orchestrator beyond tagged ingest events) and
NOT "automated rollback if the orchestration loop detects a critical system failure"
(there is no autonomous failure detector here — every rollback requires an explicit
operator action) — see ADR-0014's honesty boundaries for the full scope disclosure.
"""

from __future__ import annotations
