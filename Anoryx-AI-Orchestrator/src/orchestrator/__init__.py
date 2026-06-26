"""Anoryx-AI-Orchestrator runtime package (O-003).

The Orchestrator's first runtime: the event ingest pipeline that receives Sentinel
events over the O-002 HMAC webhook seam, validates them against the locked F-002
events schema, dedups on idempotency_key, persists with a hash-chained audit,
reject-to-DLQs failures per O-002's failure-envelope, and records forward-to-
subscriber INTENT (it does NOT route to subscribers — that is O-005).
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
