"""Tenant-scoped, metadata-only read seams (O-006, ADR-0006).

The GET query/bus seams the O-001/O-002 contract specified but never implemented:
`GET /v1/events`, `GET /v1/bus/dlq`, `GET /v1/bus/schema-versions`. Each derives the caller's
per-tenant principal (require_tenant_principal), reads under that tenant's RLS session, and
returns only the contract's metadata projections (never event payloads or DLQ envelopes).
"""

from __future__ import annotations
