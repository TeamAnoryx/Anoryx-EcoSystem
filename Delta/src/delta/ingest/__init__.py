"""Delta event-ingest + posting layer (D-004).

Consume + posting ONLY. This package turns a Sentinel ``usage`` event (carried via
the Orchestrator) into an idempotent, balanced double-entry debit in the D-003
ledger. It makes no policy decision and blocks nothing: budget enforcement is D-005,
the kill-switch is D-006, dashboards are D-008. See docs/adr/0004.

Cost is Sentinel's CLIENT-SIDE COST ESTIMATE (``cost_estimate_cents``), never an
authoritative bill. Delta records it; it does not recompute pricing.
"""

from __future__ import annotations
