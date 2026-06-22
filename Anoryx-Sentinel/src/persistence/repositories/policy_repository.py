"""PolicyRepository — data access for policies and policy_versions tables (F-003b).

MONOTONICITY ENFORCEMENT: Any attempt to upsert a policy version where the
incoming policy_version is <= the current max version for the same policy_id
is rejected with PolicyMonotonicityError. This prevents replay/rollback attacks
(an attacker re-submitting a signed older version to roll enforcement back).

Enforcement is dual-layer:
1. Application layer: this repository checks before insert.
2. Database layer: a BEFORE INSERT trigger on policy_versions raises an exception
   if the new version is not strictly greater than the current max (migration 0004).

F-003b (ADR-0005): get_by_id now accepts caller_tenant_id as a defense-in-depth
guard. RLS on the tenant session is the primary boundary; the app-layer check is
the second lock and makes the security intent explicit in code review.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.policy import Policy, PolicyVersion

# Compact-JWS pattern: three dot-separated base64url segments.
_JWS_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_VALID_POLICY_TYPES = frozenset({"budget_limit", "model_allowlist", "model_denylist", "code_scan"})


class PolicyNotFoundError(Exception):
    """Raised when a policy lookup finds no matching row."""


class PolicyMonotonicityError(Exception):
    """Raised when an incoming policy_version is not strictly greater than current."""


def _validate_signature(signature: str) -> None:
    """Raise ValueError if the signature does not match compact-JWS format."""
    if not (16 <= len(signature) <= 4096):
        raise ValueError(f"signature length {len(signature)} out of range [16, 4096]")
    if not _JWS_PATTERN.match(signature):
        raise ValueError("signature must be compact-JWS (three base64url segments)")


class PolicyRepository:
    """Data-access for policies (current state) and policy_versions (full history)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_policy(
        self,
        policy_id: str,
        policy_type: str,
        policy_version: int,
        tenant_id: str,
        team_id: str,
        project_id: str,
        agent_id: str,
        effective_from: datetime,
        signature: str,
        policy_payload: dict[str, Any],
    ) -> tuple[Policy, PolicyVersion]:
        """Insert or update a policy, appending a new version record.

        Raises PolicyMonotonicityError if policy_version <= current stored version.
        Raises ValueError for invalid inputs (signature format, policy_type, etc.).
        Returns (updated Policy, new PolicyVersion).
        """
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(f"Invalid policy_type: {policy_type!r}")
        if policy_version < 1:
            raise ValueError(f"policy_version must be >= 1, got {policy_version}")
        _validate_signature(signature)

        payload_json = json.dumps(policy_payload, sort_keys=True, separators=(",", ":"))

        # Check monotonicity: fetch current max version for this policy_id.
        stmt_max = select(func.max(PolicyVersion.policy_version)).where(
            PolicyVersion.policy_id == policy_id
        )
        result_max = await self._session.execute(stmt_max)
        current_max: int | None = result_max.scalar_one_or_none()

        if current_max is not None and policy_version <= current_max:
            raise PolicyMonotonicityError(
                f"Incoming policy_version={policy_version} is not strictly greater "
                f"than current max={current_max} for policy_id={policy_id!r}. "
                "Replay/rollback rejected."
            )

        # Append the new version record.
        version_row = PolicyVersion(
            id=str(uuid.uuid4()),
            policy_id=policy_id,
            policy_version=policy_version,
            policy_type=policy_type,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            effective_from=effective_from,
            signature=signature,
            policy_payload=payload_json,
            recorded_at=datetime.now(timezone.utc),
        )
        self._session.add(version_row)

        # Upsert the current-state policy row.
        stmt_policy = select(Policy).where(Policy.policy_id == policy_id)
        result_policy = await self._session.execute(stmt_policy)
        policy_row = result_policy.scalar_one_or_none()

        if policy_row is None:
            policy_row = Policy(
                policy_id=policy_id,
                policy_type=policy_type,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                current_version=policy_version,
                effective_from=effective_from,
                signature=signature,
                policy_payload=payload_json,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            self._session.add(policy_row)
        else:
            policy_row.current_version = policy_version
            policy_row.policy_type = policy_type
            policy_row.effective_from = effective_from
            policy_row.signature = signature
            policy_row.policy_payload = payload_json
            policy_row.updated_at = datetime.now(timezone.utc)

        await self._session.flush()
        return policy_row, version_row

    async def save_new_version(
        self,
        *,
        policy_id: str,
        policy_type: str,
        policy_version: int,
        tenant_id: str,
        team_id: str,
        project_id: str,
        agent_id: str,
        effective_from: datetime,
        signature: str,
        policy_payload: dict[str, Any],
    ) -> tuple[Policy, PolicyVersion]:
        """F-008 (ADR-0009 §3) alias for persisting a new verified, signed version.

        Named per the F-008 charter; delegates to upsert_policy so the monotonicity
        check + append-only version history (shared with F-003 callers) stay in one
        place. The scope arguments MUST be the signature-resolved scope, not body IDs.
        """
        return await self.upsert_policy(
            policy_id=policy_id,
            policy_type=policy_type,
            policy_version=policy_version,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            effective_from=effective_from,
            signature=signature,
            policy_payload=policy_payload,
        )

    async def get_max_version(self, policy_id: str) -> int | None:
        """Return the current max policy_version for a policy_id, or None if unseen.

        F-008 (ADR-0009 §5): the intake-time replay/rollback check. Runs on the
        privileged session during intake (BYPASSRLS) so it sees the true global
        max regardless of tenant context, before any write. The 0004 monotonic
        trigger remains the last line of defense.
        """
        stmt = select(func.max(PolicyVersion.policy_version)).where(
            PolicyVersion.policy_id == policy_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_policies_for_scope(
        self,
        tenant_id: str,
        policy_type: str,
        *,
        now: datetime | None = None,
    ) -> list[Policy]:
        """Return active (effective_from <= now) current policies of a type for a tenant.

        F-008 (ADR-0009 §6): a coarse tenant + type + active fetch. Precise
        per-variant matching — the Sentinel-ID wildcard convention for model
        policies (which needs Python-side specificity ranking, Decision A) and the
        scope-field match for budget policies — is performed in the enforcement
        layer, not in SQL, so the persistence layer stays free of policy semantics.
        Runs on the caller's session: a tenant session at request time, where RLS
        plus the explicit tenant_id predicate both scope the rows.
        """
        effective_now = now or datetime.now(timezone.utc)
        stmt = (
            select(Policy)
            .where(Policy.tenant_id == tenant_id)
            .where(Policy.policy_type == policy_type)
            .where(Policy.effective_from <= effective_now)
            .order_by(Policy.policy_id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_id(self, policy_id: str, caller_tenant_id: str) -> Policy:
        """Return the current policy row for policy_id, or raise PolicyNotFoundError.

        caller_tenant_id is REQUIRED (LOW-1, ADR-0005 round-2).  The WHERE
        clause always includes AND tenant_id = caller_tenant_id.  RLS on the
        tenant session is the primary boundary; this check is the second lock.
        """
        stmt = select(Policy).where(Policy.policy_id == policy_id)
        stmt = stmt.where(Policy.tenant_id == caller_tenant_id)
        result = await self._session.execute(stmt)
        policy = result.scalar_one_or_none()
        if policy is None:
            raise PolicyNotFoundError(f"Policy not found: {policy_id!r}")
        return policy

    async def get_versions(self, policy_id: str) -> list[PolicyVersion]:
        """Return all version records for a policy, ordered by version ascending."""
        stmt = (
            select(PolicyVersion)
            .where(PolicyVersion.policy_id == policy_id)
            .order_by(PolicyVersion.policy_version)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_for_tenant(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Policy]:
        """Return current policies for a tenant, ordered by policy_type.

        Default limit: 100.  Hard max: 1000.  Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, 1000)
        stmt = (
            select(Policy)
            .where(Policy.tenant_id == tenant_id)
            .order_by(Policy.policy_type, Policy.policy_id)
            .limit(effective_limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
