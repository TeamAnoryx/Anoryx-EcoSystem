"""F-026 — MCP & third-party integration layer: governance substrate (ADR-0032).

Internal Python + CLI only (src/mcp_gateway/cli.py, the `sentinel-mcp`
console script) — deliberately NOT a new HTTP endpoint or a live MCP-protocol
proxy. This package provides the two governance primitives the roadmap line
calls for that ARE buildable without touching contracts/ (api-architect-owned
— CLAUDE.md non-negotiable #1, unreachable in this session, see ADR-0032
"Scoping decision"):

  1. Per-tenant allow-listing of external MCP servers
     (persistence.repositories.tenant_mcp_server_repository, this package's
     url_guard.py for SSRF-safe validation at registration time).
  2. Uniform PII/injection/secret inspection of MCP-shaped payload content,
     reusing the EXACT same orchestration.registry hook chain
     /v1/chat/completions already uses (inspection.py).

What this package does NOT do: make a single network call to an external MCP
server. There is no live proxy here — see
docs/followups/f-026-mcp-proxy-endpoint.md for what that needs.
"""

from __future__ import annotations
