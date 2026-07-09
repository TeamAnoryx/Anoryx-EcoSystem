"""Register / list / revoke a tenant's custom PII patterns (F-028, ADR-0034).

Validates name + regex (compile, length, ReDoS heuristic) and enforces the
per-tenant pattern cap BEFORE any write — mirrors mcp_gateway/allowlist.py's
"guard before persistence" discipline exactly.
"""

from __future__ import annotations

from data_protection.custom_pii.config import get_custom_pii_settings
from data_protection.custom_pii.exceptions import InvalidPattern, PatternLimitExceeded
from data_protection.custom_pii.validator import normalize_name, validate_pattern
from persistence.database import get_tenant_session
from persistence.models.tenant_custom_pii_pattern import TenantCustomPiiPattern
from persistence.repositories.tenant_custom_pii_pattern_repository import (
    TenantCustomPiiPatternRepository,
)

_VALID_ACTIONS = ("mask", "tokenize", "block")


async def register_pattern(
    tenant_id: str,
    name: str,
    pattern: str,
    *,
    score: float = 0.85,
    action: str | None = None,
    team_id: str | None = None,
    project_id: str | None = None,
) -> TenantCustomPiiPattern:
    """Validate + persist a new custom PII pattern for a tenant.

    Raises InvalidPatternName / InvalidPattern / PatternLimitExceeded before
    touching the DB.
    """
    settings = get_custom_pii_settings()

    normalized_name = normalize_name(name)
    validate_pattern(pattern, max_length=settings.custom_pii_max_pattern_length)

    if action is not None and action not in _VALID_ACTIONS:
        raise InvalidPattern(f"action must be one of {_VALID_ACTIONS}, got {action!r}")
    if not (0.0 <= score <= 1.0):
        raise InvalidPattern(f"score must be in [0, 1], got {score}")

    async with get_tenant_session(tenant_id) as ts:
        repo = TenantCustomPiiPatternRepository(ts)
        active_count = await repo.count_active_for_tenant(tenant_id)
        if active_count >= settings.custom_pii_max_patterns_per_tenant:
            raise PatternLimitExceeded(
                f"tenant already has {active_count} active patterns "
                f"(max {settings.custom_pii_max_patterns_per_tenant})"
            )
        row = await repo.create(
            tenant_id=tenant_id,
            name=normalized_name,
            pattern=pattern,
            score=score,
            action=action,
            team_id=team_id,
            project_id=project_id,
        )
        await ts.commit()
        return row


async def list_patterns(
    tenant_id: str, *, active_only: bool = True
) -> list[TenantCustomPiiPattern]:
    async with get_tenant_session(tenant_id) as ts:
        return await TenantCustomPiiPatternRepository(ts).list_for_tenant(
            tenant_id, active_only=active_only
        )


async def revoke_pattern(tenant_id: str, pattern_id: str) -> TenantCustomPiiPattern:
    """Soft-deactivate a custom PII pattern (no hard delete)."""
    async with get_tenant_session(tenant_id) as ts:
        row = await TenantCustomPiiPatternRepository(ts).deactivate(
            pattern_id, caller_tenant_id=tenant_id
        )
        await ts.commit()
        return row
