"""F-025 — self-serve onboarding: operator-run sandbox-tenant provisioning
(ADR-0031).

Internal Python + CLI only (src/onboarding/cli.py, the `sentinel-onboarding`
console script) — deliberately NOT a new HTTP endpoint. contracts/openapi.yaml
is owned exclusively by the api-architect agent (CLAUDE.md non-negotiable #1)
and was unreachable in this session (see ADR-0031 §"Scoping decision" and
docs/followups/f-025-team-project-admin-api.md for the HTTP-API version of
this feature, fully specified and ready to apply once that access exists).
"""

from __future__ import annotations
