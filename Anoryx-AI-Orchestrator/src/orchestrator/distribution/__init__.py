"""Policy-distribution HTTP surface + engine (O-004, ADR-0004).

Inbound POST/GET /v1/policies/distributions (router.py) and the outbound best-effort
fan-out engine (engine.py) that forwards an already-signed policy record, unchanged, to
one or more Sentinel deployments. Reuses the O-003 persistence + RLS + hash-chain stack.
"""

from __future__ import annotations
