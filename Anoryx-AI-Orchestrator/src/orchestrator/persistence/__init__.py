"""Orchestrator persistence layer (O-003, ADR-0003).

Ported (NOT imported) from Sentinel's proven F-003 / F-003b patterns so the two
products stay decoupled, each owning its own database:

  - hash_chain      — tamper-evident SHA-256 chain (F-003 pattern).
  - database        — two-engine model: privileged (owner/BYPASSRLS) for chain ops
                      + migrations; orchestrator_app (NOBYPASSRLS) for tenant traffic.
                      get_tenant_session AUTOBEGINS (ADR-0026 double-begin discipline).
  - models          — the four ingest-baseline tables.
"""

from __future__ import annotations
