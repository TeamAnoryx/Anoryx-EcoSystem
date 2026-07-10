"""Constrained identifier types mirroring the LOCKED Rendly wire contract.

The pattern reproduces R-001's id format **byte-for-byte** — the dashed
8-4-4-4-12 hex shape from ``contracts/ids.md`` / the ``contracts/openapi.yaml``
path+schema parameters / ``messages.schema.json``, ``maxLength`` 64. Matching the
wire exactly is the requirement (the domain must never reject an id the LOCKED
wire accepts), so the constraint is deliberately the wire's: case-insensitive
``[0-9a-fA-F]`` with NO RFC-4122 version-nibble check and NO lowercase
normalization, exactly as the wire pattern specifies. Reproducing it here (rather
than ``uuid.UUID``) still closes the parser differential that matters: the
non-canonical forms ``uuid.UUID()`` would accept — no-dashes, ``{braces}``,
``urn:uuid:`` — are rejected, and the value is bounded to a UUID character shape
(no control chars / CRLF) as a log-injection defense.

Deliberately NOT done here, because the wire does not and it would diverge from
the LOCKED contract: case-folding a tenant id, or assigning the nil/all-zeros
UUID a wildcard meaning. ``ids.md`` reserves the Sentinel ``WILDCARD_UUID``
convention as NOT in use in Rendly (its adoption requires a future ADR), so a
nil/uppercase id is just an ordinary value with no special scope here, and
``tenant_id`` is ALWAYS server-resolved and never a client-shaped input that could
widen scope. Any cross-product canonicalization belongs at the O-010 join
(post-investment), not at this layer.

The R-002 persistence domain (Tenant / User / Profile / Channel / Membership) uses
three of the five locked ids; ``message_id`` and ``huddle_id`` identify
real-time/archival records owned by the R-005 runtime, not this domain, so they
are intentionally not defined here.

``EventId``/``SessionId`` (R-013) follow the same shape for the same reason as
``ChannelId``: they identify records of a pure-domain seam (``event.py``) that,
like R-002 before R-004, has no persistence yet — the id shape is fixed now so a
future persistence layer has nothing to reconcile.

``OpportunityId`` (R-021) follows the same shape for the same reason: it
identifies records of ``opportunity.py``, another pure-domain seam with no
persistence yet.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints

# Canonical dashed UUID (8-4-4-4-12 hex) — byte-identical to the wire `format: uuid`
# pattern in contracts/openapi.yaml and contracts/messages.schema.json.
_UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
_ID_MAX_LENGTH = 64

# All five Rendly ids share one underlying UUID constraint set; semantic aliases
# keep each tenant-scoped type self-documenting and identical in shape.
UuidStr = Annotated[str, StringConstraints(pattern=_UUID_PATTERN, max_length=_ID_MAX_LENGTH)]

TenantId = UuidStr
UserId = UuidStr
ChannelId = UuidStr
EventId = UuidStr
SessionId = UuidStr
OpportunityId = UuidStr
