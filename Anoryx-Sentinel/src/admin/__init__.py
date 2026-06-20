"""Admin Console API (F-012a, ADR-0014).

The operator surface: cross-tenant tenant/key/audit/config management, gated by a
single deploy-injected env secret (SENTINEL_ADMIN_TOKEN). This package is a thin
control surface over the existing engines — it reuses persistence, the RLS
sessions, the audit writer, and the F-007/F-008/F-009/F-011 paths; it never
reimplements them. See docs/adr/0014-admin-console-api.md.
"""
