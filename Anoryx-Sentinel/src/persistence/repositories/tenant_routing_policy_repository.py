"""TenantRoutingPolicyRepository — data access for tenant_routing_policy (F-006).

Reads run on get_tenant_session(tenant_id) (RLS-enforced). get_for_tenant adds a
defense-in-depth `WHERE tenant_id = caller_tenant_id` on top of RLS, mirroring
PolicyRepository.get_by_id (ADR-0008 §4.3 / threat #11).

When no row exists, returns the DOCUMENTED default (ADR-0008 §4.2): all three
providers allowed, fallback_order [openai, anthropic, bedrock], NO cost ceiling.
The router intersects this with the providers that actually have credentials
(fail-closed on a missing key, §3).

Provider-token membership and fallback_order ⊆ allowed_providers are validated
here (the DB CHECK only backstops non-emptiness — a CSV-subset relationship is
not easily expressible in SQL).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.tenant_routing_policy import TenantRoutingPolicy

if TYPE_CHECKING:  # pragma: no cover - typing only (avoids persistence→orchestration at runtime)
    from gateway.context import TenantContext
    from orchestration.judge.config import ClassifierConfig

_KNOWN_PROVIDERS = ("openai", "anthropic", "bedrock")
# ADR-0008 §4.2 default fallback order.
_DEFAULT_FALLBACK_ORDER = ["openai", "anthropic", "bedrock"]


class RoutingPolicyValidationError(ValueError):
    """Raised when a routing policy row has an invalid provider set / order."""


@dataclass(frozen=True)
class EffectiveRoutingPolicy:
    """The resolved routing policy for a tenant (row-backed or default).

    allowed_providers / fallback_order are parsed, validated lists.
    cost_ceiling_cents is a client-side cost-ESTIMATE ceiling (None = no ceiling).
    is_default flags the §4.2 generous default (no row present).
    """

    tenant_id: str
    allowed_providers: list[str]
    fallback_order: list[str]
    cost_ceiling_cents: float | None = None
    is_default: bool = False
    _: dict = field(default_factory=dict, repr=False, compare=False)


def _parse_csv(value: str) -> list[str]:
    return [tok.strip() for tok in value.split(",") if tok.strip()]


def _validate(allowed: list[str], order: list[str], tenant_id: str) -> None:
    if not allowed:
        raise RoutingPolicyValidationError(f"allowed_providers empty for tenant {tenant_id!r}")
    unknown = set(allowed) - set(_KNOWN_PROVIDERS)
    if unknown:
        raise RoutingPolicyValidationError(
            f"allowed_providers has unknown providers {sorted(unknown)} for tenant {tenant_id!r}"
        )
    if not set(order).issubset(set(allowed)):
        raise RoutingPolicyValidationError(
            f"fallback_order {order} is not a subset of allowed_providers {allowed} "
            f"for tenant {tenant_id!r}"
        )


def default_policy(tenant_id: str) -> EffectiveRoutingPolicy:
    """Return the ADR §4.2 default (no row): all providers, no ceiling."""
    return EffectiveRoutingPolicy(
        tenant_id=tenant_id,
        allowed_providers=list(_KNOWN_PROVIDERS),
        fallback_order=list(_DEFAULT_FALLBACK_ORDER),
        cost_ceiling_cents=None,
        is_default=True,
    )


class TenantRoutingPolicyRepository:
    """Data access for tenant_routing_policy (one row per tenant)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for_tenant(
        self,
        tenant_id: str,
        caller_tenant_id: str,
    ) -> EffectiveRoutingPolicy:
        """Return the effective routing policy for a tenant.

        Defense-in-depth: the WHERE clause always includes
        AND tenant_id = caller_tenant_id (on top of RLS). Returns the §4.2
        default when no row exists. Raises RoutingPolicyValidationError if a
        stored row is malformed (fail-closed — a bad row is not silently used).
        """
        stmt = (
            select(TenantRoutingPolicy)
            .where(TenantRoutingPolicy.tenant_id == tenant_id)
            .where(TenantRoutingPolicy.tenant_id == caller_tenant_id)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return default_policy(tenant_id)

        allowed = _parse_csv(row.allowed_providers)
        order = _parse_csv(row.fallback_order)
        _validate(allowed, order, tenant_id)

        ceiling: float | None = None
        if row.cost_ceiling_cents is not None:
            ceiling = (
                float(row.cost_ceiling_cents)
                if isinstance(row.cost_ceiling_cents, Decimal)
                else float(row.cost_ceiling_cents)
            )

        return EffectiveRoutingPolicy(
            tenant_id=tenant_id,
            allowed_providers=allowed,
            fallback_order=order,
            cost_ceiling_cents=ceiling,
            is_default=False,
        )

    async def resolve_classifier_config(
        self,
        tenant_id: str,
        caller_tenant_id: str,
    ) -> "ClassifierConfig":
        """Resolve the F-007 classifier config via the B2C inheritance walk (ADR-0010 §6).

        Reads the tenant_routing_policy row (defense-in-depth tenant predicate on top
        of RLS) and feeds it as a candidate to the pure inheritance resolver. The
        table is one row per tenant, so the candidate list is tenant-scoped today;
        the resolver is future-proof for per-scope rows. No row → UNCONFIGURED.
        """
        from orchestration.judge.config import ScopeConfig, resolve_inherited_config

        stmt = (
            select(TenantRoutingPolicy)
            .where(TenantRoutingPolicy.tenant_id == tenant_id)
            .where(TenantRoutingPolicy.tenant_id == caller_tenant_id)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return resolve_inherited_config([])
        candidates = [
            ScopeConfig(
                specificity=0,
                model_id=row.classifier_model_id,
                audit_mode=row.audit_mode,
            )
        ]
        return resolve_inherited_config(candidates)

    async def get_config_row(
        self, tenant_id: str, caller_tenant_id: str
    ) -> TenantRoutingPolicy | None:
        """Return the raw routing-policy row for a tenant, or None (F-012 config view).

        Defense-in-depth tenant predicate on top of RLS. Exposes the F-007/F-009
        adjustable fields (classifier_model_id, audit_mode, team_rpm_limit) for the
        admin operator surface.
        """
        stmt = (
            select(TenantRoutingPolicy)
            .where(TenantRoutingPolicy.tenant_id == tenant_id)
            .where(TenantRoutingPolicy.tenant_id == caller_tenant_id)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def update_config(
        self, tenant_id: str, caller_tenant_id: str, updates: dict[str, object]
    ) -> TenantRoutingPolicy | None:
        """Bounded update of F-007/F-009 config on an existing row (F-012, ADR-0014 D6).

        Only classifier_model_id / audit_mode / team_rpm_limit may be set. The
        table's existing CHECK constraints (ck_trp_classifier_model_id allow-list,
        ck_trp_audit_mode, ck_trp_team_rpm_limit > 0) are the source of truth and
        backstop at flush. Returns the updated row, or None if no row exists (the
        caller maps that to 404 — creating the base routing policy is out of scope,
        owned by F-008/defaults). This changes config DATA only, not engine logic.
        """
        allowed = {"classifier_model_id", "audit_mode", "team_rpm_limit"}
        unknown = set(updates) - allowed
        if unknown:
            raise ValueError(f"unsupported config fields: {sorted(unknown)}")
        row = await self.get_config_row(tenant_id, caller_tenant_id)
        if row is None:
            return None
        for key, value in updates.items():
            setattr(row, key, value)
        await self._session.flush()
        await self._session.refresh(row)
        return row


async def get_classifier_config(tenant_context: "TenantContext") -> "ClassifierConfig":
    """Resolve a tenant's classifier config on a tenant session (RLS, R13).

    Module-level entry used by the injection detector. Opens a tenant session and
    delegates to TenantRoutingPolicyRepository.resolve_classifier_config.
    """
    from persistence.database import get_tenant_session

    async with get_tenant_session(tenant_context.tenant_id) as session:
        async with session.begin():
            repo = TenantRoutingPolicyRepository(session)
            return await repo.resolve_classifier_config(
                tenant_context.tenant_id, caller_tenant_id=tenant_context.tenant_id
            )
