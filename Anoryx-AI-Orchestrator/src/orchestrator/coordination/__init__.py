"""Multi-Sentinel coordination subsystem (O-005, ADR-0005).

Builds on O-004's distribution engine (consumed UNCHANGED) with a registry of Sentinel
instances, a health-check subsystem, and a coordinated push that fans the per-target
distribution across all healthy + capable registered targets. SSRF endpoint validation is the
load-bearing security property: every registered endpoint is validated/allowlisted at
registration and re-validated before every outbound use.
"""
