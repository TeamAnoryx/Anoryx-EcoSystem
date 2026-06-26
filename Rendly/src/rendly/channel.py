"""Channel — a tenant-scoped, role-based secure communication channel.

Matches R-001's LOCKED ``components.schemas.Channel`` (``contracts/openapi.yaml``):
closed object, ``type ∈ {public, private, dm}``, and the Delta-team auto-mapping
seam expressed as a ``source`` discriminator + an opaque nullable ``external_ref``.

HONESTY BOUNDARY (FORK C, reconciled to R-001 — the contract is the law): the
Delta-team → channel auto-mapping is a SEAM ONLY. A normally-constructed channel
defaults to ``source="manual"`` with ``external_ref=None``; the ``delta_team``
value + ``external_ref`` pointer are RESERVED for R-006 / D-016 (with a manual
fallback) and are never auto-populated here. (The dispatch's tentative
``delta_team_id`` field name is superseded by R-001's committed
``source``/``external_ref`` shape.)

Seam-consistency invariant: ``external_ref`` is non-null IFF ``source ==
delta_team``. This keeps the reserved seam self-consistent — a ``manual`` channel
can never carry a mapping pointer, and a ``delta_team`` channel must name what it
maps to — so a future R-006 builds on a sound shape. ``external_ref`` is opaque but
charset-bounded (no control chars / CRLF) so the reserved pointer inherits the same
log-injection hardening every id field gets, before any R-006 consumer dereferences
it. NOTE: ``model_construct()`` skips this validator (a Pydantic escape hatch) and
is NOT a supported construction path for ``Channel``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator, model_validator

from .common import require_aware_utc
from .enums import ChannelSource, ChannelType
from .identifiers import ChannelId, TenantId, UserId

# Bounds mirror contracts/openapi.yaml. `name` takes ChannelCreate's minLength 1
# (a persisted channel always has a non-empty name). `external_ref` is opaque (R-001
# sets no pattern) but charset-bounded here to [A-Za-z0-9._:-] as a log-injection
# defense on the reserved seam — a strict subset of the wire's ≤64 string, so a value
# this domain emits always validates against the wire (the wire is always null in MVP).
ChannelName = Annotated[str, StringConstraints(min_length=1, max_length=128)]
ExternalRef = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,64}$", max_length=64)]


class Channel(BaseModel):
    """A role-based secure channel. Immutable; defaults to the ``manual`` seam state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_id: ChannelId
    tenant_id: TenantId
    name: ChannelName
    type: ChannelType
    source: ChannelSource = ChannelSource.MANUAL
    external_ref: ExternalRef | None = None
    created_by: UserId
    created_at: datetime
    archived: bool = False

    @field_validator("created_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "created_at")

    @model_validator(mode="after")
    def _source_external_ref_consistent(self) -> "Channel":
        # The reserved seam's shape: a manual channel carries no mapping pointer; a
        # delta_team channel must name the external resource it maps to.
        if self.source is ChannelSource.MANUAL and self.external_ref is not None:
            raise ValueError("manual channel must not carry an external_ref (reserved seam)")
        if self.source is ChannelSource.DELTA_TEAM and self.external_ref is None:
            raise ValueError("delta_team channel requires an external_ref (reserved seam)")
        return self
