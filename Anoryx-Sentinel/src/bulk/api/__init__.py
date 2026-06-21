"""Bulk-pipeline data-plane API (F-015, ADR-0018 §1.2, Fork 5).

Tenant-facing /v1/batches* endpoints under the EXISTING virtual-API-key Bearer
auth (AuthMiddleware + resolve_tenant_context) — zero new auth. Each tenant sees
only its own batches (RLS).
"""

from __future__ import annotations

from bulk.api.routes import router

__all__ = ["router"]
