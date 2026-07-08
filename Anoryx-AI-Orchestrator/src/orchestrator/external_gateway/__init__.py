"""Third-party external gateway (O-013, ADR-0013): API-key issuance, rate limiting, scope
enforcement, and governance audit for a designated set of the Orchestrator's own
third-party-facing read seams.

NOT the roadmap's literal "global API gateway for all third-party interactions with the
ecosystem" (that depends on F-026, which does not exist) — see ADR-0013's honesty
boundaries for the full scope disclosure.
"""

from __future__ import annotations
