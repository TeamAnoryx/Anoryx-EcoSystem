"""Rendly identity persistence (R-004).

Makes the R-002 frozen identity domain (Tenant / User / Profile) and R-003's two
explicitly-left seams REAL on Postgres:

  * :class:`rendly.persistence.user_store.DbUserStore` implements the R-003
    ``UserStore`` ABC byte-for-byte (the credential/identity lookup seam).
  * :class:`rendly.persistence.refresh_store.DbRefreshTokenStore` implements the
    R-003 ``RefreshTokenStore`` ABC byte-for-byte (rotating refresh + reuse-detection),
    moving only the storage to Postgres — the in-memory semantics are unchanged.

Mirrors the Sentinel F-003b two-role RLS pattern as already replicated by Delta D-003
(ADR Fork A/B/D): an OWNED ``rendly`` schema, RLS on every tenant-scoped table, a
``rendly_app`` NOBYPASSRLS login role, and a transaction-local GUC carrying the tenant
context into the RLS predicates.

HONESTY BOUNDARY (R-003 → R-004): R-003's honesty note "only the user lookup is
fixture-backed" is RETIRED for the DB-backed path — the credential lookup, the
identity fetch, and the refresh-token state are all real Postgres now. The token
cryptography was already real in R-003. Channels + Memberships are DEFERRED to R-005
(Fork C); this layer persists identity + refresh-token families only.
"""

from __future__ import annotations

# The GUC that carries the tenant context into the RLS predicates. Identical name to
# the Sentinel F-003b / Delta D-003 pattern so the isolation boundary is the same shape
# across the whole ecosystem.
TENANT_GUC: str = "app.current_tenant_id"

# The non-privileged application login role (LOGIN, NOSUPERUSER, NOBYPASSRLS). Every
# session connecting as this role is governed by RLS and can never bypass it.
RENDLY_APP_ROLE: str = "rendly_app"

# The Postgres schema that houses every Rendly identity object (Fork A — OWNED schema).
# All DDL is schema-qualified into here, and the alembic_version table is pinned to it
# so Rendly's migration history never collides with another product's history when they
# share a Postgres instance.
RENDLY_SCHEMA: str = "rendly"
