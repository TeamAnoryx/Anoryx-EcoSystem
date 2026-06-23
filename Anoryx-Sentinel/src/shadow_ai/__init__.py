"""F-018 — Shadow-AI detection: a detection + attribution layer on F-007's egress seam.

This package CONSUMES the egress sensor F-007 already ships
(`gateway/middleware/egress_monitor.py` → `shadow_ai_detected_outbound`). It does
NOT observe traffic itself and does NOT rebuild the httpx hook (ADR-0021 R2).

It reads a tenant's recent `shadow_ai_detected_outbound` audit rows, classifies
them into review CANDIDATES with an explainable confidence band, attributes each
to the offending team/project using the server-stamped (non-forgeable) IDs on
those rows, and emits a `shadow_ai_candidate_detected` audit event per new
candidate.

HONEST SCOPE (ADR-0021 §4): detection covers only traffic THROUGH Sentinel to a
known provider not on the tenant allow-list. It does not detect tools that bypass
Sentinel. Detections are candidates, not verdicts.
"""
