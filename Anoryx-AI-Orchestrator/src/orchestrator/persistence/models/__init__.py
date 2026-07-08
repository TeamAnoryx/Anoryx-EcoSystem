"""ORM models for the Orchestrator ingest baseline (O-003, ADR-0003).

The hand-written migration (0001_ingest_baseline) is the authoritative DDL — it carries
the RLS policies, append-only triggers, and role grants that ORM/autogenerate cannot
express. These models mirror its columns for repository use and for env.py's
target_metadata. Do NOT run alembic autogenerate against them.
"""

from __future__ import annotations

from orchestrator.persistence.models.base import Base
from orchestrator.persistence.models.dead_letter import DeadLetterEntry
from orchestrator.persistence.models.distribution_audit_log import DistributionAuditLog
from orchestrator.persistence.models.forward_outbox import ForwardOutbox
from orchestrator.persistence.models.identity_audit_log import IdentityAuditLog
from orchestrator.persistence.models.identity_event import IdentityEvent
from orchestrator.persistence.models.ingest_audit_log import IngestAuditLog
from orchestrator.persistence.models.ingest_event import IngestEvent
from orchestrator.persistence.models.policy_distribution import PolicyDistribution
from orchestrator.persistence.models.policy_distribution_target import PolicyDistributionTarget
from orchestrator.persistence.models.query_service_token import QueryServiceToken
from orchestrator.persistence.models.relay_audit_log import RelayAuditLog
from orchestrator.persistence.models.sentinel_registry import SentinelRegistry
from orchestrator.persistence.models.sentinel_registry_audit_log import SentinelRegistryAuditLog

__all__ = [
    "Base",
    "IngestEvent",
    "IngestAuditLog",
    "DeadLetterEntry",
    "ForwardOutbox",
    # O-004 policy distribution (ADR-0004).
    "PolicyDistribution",
    "PolicyDistributionTarget",
    "DistributionAuditLog",
    # O-005 multi-Sentinel coordination (ADR-0005).
    "SentinelRegistry",
    "SentinelRegistryAuditLog",
    # O-006 per-tenant query principal (ADR-0006).
    "QueryServiceToken",
    # O-009 governed relay (ADR-0009).
    "RelayAuditLog",
    # O-010 cross-product identity correlation (ADR-0010).
    "IdentityEvent",
    "IdentityAuditLog",
]
