"""Third-party external gateway (O-013, ADR-0013): API-key issuance, rate limiting, scope
enforcement, and governance audit for a designated set of the Orchestrator's own
third-party-facing read seams.

NOT the roadmap's literal "global API gateway for all third-party interactions with the
ecosystem" — F-026 (the Sentinel-side MCP governance substrate) has since shipped, but
ships no live HTTP/MCP proxy endpoint (CLI-only allowlist + inspection tooling; its own
follow-up defers the proxy), so there is still no F-026 HTTP surface for this seam to
integrate with — see ADR-0013's honesty boundaries for the full scope disclosure.
"""

from __future__ import annotations
