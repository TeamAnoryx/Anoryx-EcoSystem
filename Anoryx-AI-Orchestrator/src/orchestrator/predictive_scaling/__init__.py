"""Predictive scaling (O-015, ADR-0015): a read-only, current-rate ingest-traffic
forecast (`method: "current_rate_projection_v1"`, ecosystem-wide naming consistency with
Delta's D-011 forecast) plus a deterministic, threshold-based spike heuristic.

NOT the roadmap's literal "predictive scaling" — this endpoint takes NO autoscaling
action of any kind; it only reports a projection. NOT "telemetry analysis from the
registry" (sentinel_registry has no historical time-series to analyze — only the current
point-in-time health_status); this uses the O-003 ingest_events stream instead, the
Orchestrator's only genuinely timestamped, historically-queryable traffic signal. NOT a
trained statistical or ML model — see ADR-0015's honesty boundaries for the full scope
disclosure.
"""

from __future__ import annotations
