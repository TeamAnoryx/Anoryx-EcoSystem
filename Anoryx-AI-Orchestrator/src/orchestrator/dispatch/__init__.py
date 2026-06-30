"""Minimal D-004 push dispatcher for the Orchestrator->Delta consume seam.

HONESTY NOTE: this is NOT the full O-005 distribution engine (no subscriber registry,
no fan-out routing, no multi-subscriber delivery). It is a single-pass drain that forwards
pending forward_outbox 'usage' rows to Delta's inbound seam, signs each with the
Orchestrator->Delta shared-secret HMAC, and records the per-row delivery outcome. O-005
will own the general routing; this dispatcher is the narrow, honest D-004 producer half.
"""
