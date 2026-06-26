"""ORM models for the Orchestrator ingest baseline (O-003, ADR-0003).

The hand-written migration (0001_ingest_baseline) is the authoritative DDL — it carries
the RLS policies, append-only triggers, and role grants that ORM/autogenerate cannot
express. These models mirror its columns for repository use and for env.py's
target_metadata. Do NOT run alembic autogenerate against them.
"""

from __future__ import annotations

from orchestrator.persistence.models.base import Base
from orchestrator.persistence.models.dead_letter import DeadLetterEntry
from orchestrator.persistence.models.forward_outbox import ForwardOutbox
from orchestrator.persistence.models.ingest_audit_log import IngestAuditLog
from orchestrator.persistence.models.ingest_event import IngestEvent

__all__ = [
    "Base",
    "IngestEvent",
    "IngestAuditLog",
    "DeadLetterEntry",
    "ForwardOutbox",
]
