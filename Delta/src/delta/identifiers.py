"""Constrained identifier types mirroring the Sentinel contracts.

These reproduce the EXACT formats from ``contracts/ids.md`` /
``contracts/events.schema.json`` so a Delta record's attribution is byte-shape
identical to the Sentinel event it joins to:

- tenant / team / project ids: UUID strings, ``maxLength`` 64
- agent_id: lowercase slug ``^[a-z0-9]+(-[a-z0-9]+)*$``, ``maxLength`` 64
- request_id: ``^[A-Za-z0-9._-]{1,64}$`` (log-injection-safe charset)

Using shared aliases keeps every tenant-scoped type tenant-first and identical in
shape, which is what lets D-003 apply the F-003b RLS predicate with no reshape.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints

_AGENT_ID_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
# Canonical dashed UUID (8-4-4-4-12 hex). Deliberately STRICT — uuid.UUID() would
# accept non-canonical forms (no-dashes, {braces}, urn:uuid:) that the wire
# `format:uuid` rejects, opening a parser differential and a different join string
# (M-1). This pattern accepts exactly the byte form the contracts accept.
_UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
_ID_MAX_LENGTH = 64


# UUID-shaped ids (semantic aliases share one underlying constraint set).
UuidStr = Annotated[str, StringConstraints(pattern=_UUID_PATTERN, max_length=_ID_MAX_LENGTH)]

TenantId = UuidStr
TeamId = UuidStr
ProjectId = UuidStr
AccountId = UuidStr
EntryId = UuidStr
TransactionId = UuidStr
AllocationId = UuidStr
EventId = UuidStr

# D-013 unified CRM identifiers — same UUID shape, tenant-scoped like every other id.
ClientId = UuidStr
DealId = UuidStr
InteractionId = UuidStr
StakeholderId = UuidStr

# D-014 ERP (asset register + vendor/purchase-order procurement) identifiers.
AssetId = UuidStr
VendorId = UuidStr
PurchaseOrderId = UuidStr

# D-015 project management (sprints, tasks, dependency mapping) identifiers.
SprintId = UuidStr
TaskId = UuidStr
TaskDependencyId = UuidStr

# D-016 team capacity management reuses the ecosystem-wide TeamId (above) as both a
# team's primary key and the tasks.team_id assignment column — no new identifier
# type needed.

# D-017 RBAC-gated dashboards (locally-issued, role-tagged bearer tokens).
AccessTokenId = UuidStr

# D-018 automated invoicing + vendor payment reconciliation.
InvoiceId = UuidStr
InvoicePaymentId = UuidStr

# D-019 corporate ERP/procurement/cloud-cost sync connectors.
ExternalSystemId = UuidStr
SyncRunId = UuidStr
SyncLineItemId = UuidStr

# D-021 personal budget tracking (B2C track). A B2C consumer IS one tenant_id here —
# no separate consumer-identity type (ADR-0021 Fork 1: reuse D-001's existing
# multi-tenant scoping boundary rather than building a new identity model).
PersonalAccountId = UuidStr
PersonalTransactionId = UuidStr
PersonalBudgetId = UuidStr

# Internal Sentinel component slug (NOT the end-user model name).
AgentId = Annotated[str, StringConstraints(pattern=_AGENT_ID_PATTERN, max_length=_ID_MAX_LENGTH)]

# Correlation id back to the originating gateway request.
RequestId = Annotated[
    str, StringConstraints(pattern=_REQUEST_ID_PATTERN, max_length=_ID_MAX_LENGTH)
]
