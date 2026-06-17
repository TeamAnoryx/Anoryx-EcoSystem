"""F-008 — Policy Intake & Enforcement layer (ADR-0009).

Verifies, persists, and enforces Delta/Orchestrator-signed policies inside
Sentinel. Internal Python only — no HTTP endpoints (F-009 owns the admin REST
API). Conforms exactly to contracts/policy.schema.json (sentinel:policy:v1).
"""

from __future__ import annotations
