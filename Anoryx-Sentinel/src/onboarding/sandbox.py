"""Sandbox-tenant provisioning (F-025, ADR-0031).

provision_sandbox() creates a tenant + team + project + virtual API key in one
guided step, reusing the EXACT repository calls and audit-event types the
existing admin HTTP routes use (src/admin/tenants.py::create_tenant,
src/admin/keys.py::mint_key) — this is the same privileged/tenant-session
split, the same VirtualApiKeyRepository.create() call, the same
admin_tenant_created / admin_key_minted event types. No new event type is
introduced: team/project creation is not yet audited anywhere in this
codebase (there is no admin HTTP route for it either — see
docs/followups/f-025-team-project-admin-api.md), so this CLI path does not
audit it either, rather than inventing an unreviewed event type.

actor_id is always None here (mirrors the break-glass / operator-CLI
attribution the admin console itself uses when there is no SSO operator
session — CLAUDE.md #4/#6 apply: never log the plaintext key or any secret).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from admin.audit import emit_admin_event
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.project_repository import ProjectRepository
from persistence.repositories.team_repository import TeamRepository
from persistence.repositories.tenant_repository import TenantRepository
from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository

# Matches admin/schemas.py's _TENANT_NAME_RE — the same name convention applies
# to tenant/team/project names throughout this admin surface.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_KEY_PREFIX = "sk-sentinel-"
_SANDBOX_AGENT_ID = "sandbox-trial"


class InvalidSandboxName(ValueError):
    """A supplied tenant/team/project name failed the shared naming convention."""


def _validate_name(label: str, value: str) -> None:
    if not _NAME_RE.match(value):
        raise InvalidSandboxName(
            f"{label} must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$, got {value!r}"
        )


def _new_plaintext_key() -> str:
    import secrets

    return _KEY_PREFIX + secrets.token_urlsafe(32)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    tenant_id: str
    tenant_name: str
    team_id: str
    project_id: str
    key_id: str
    agent_id: str
    plaintext_key: str  # returned exactly once — caller must not log/persist this


async def provision_sandbox(
    name: str,
    *,
    display_name: str | None = None,
    team_name: str = "sandbox-team",
    project_name: str = "sandbox-project",
) -> SandboxResult:
    """Create a tenant + team + project + virtual API key for a guided trial.

    Raises InvalidSandboxName if any name fails the shared naming convention.
    Raises whatever the repositories raise on a genuine DB error — this
    function does not swallow errors.

    tenants.name has NO uniqueness constraint (tenant_id is the real
    identity, matching admin/tenants.py's own create_tenant) — re-running
    with the same name creates a SECOND, distinct tenant rather than erroring.

    NOT atomic across the tenant-create step and the team/project/key step
    (two separate sessions, matching admin/tenants.py + admin/keys.py exactly
    — the SAME two-step shape the existing admin routes already use, not a
    new failure mode introduced here). A failure between steps leaves a
    tenant with no team/project/key, inspectable via the existing
    `GET /admin/tenants`; because names aren't unique, cleanup/retry is an
    operator decision (delete/deactivate the orphaned tenant, or just
    provision a fresh one) rather than something this function can detect.
    """
    _validate_name("tenant name", name)
    _validate_name("team name", team_name)
    _validate_name("project name", project_name)

    request_id = "onb-" + uuid.uuid4().hex

    async with get_privileged_session() as ps, ps.begin():
        tenant = await TenantRepository(ps).create(name=name, display_name=display_name)
        tenant_id = tenant.tenant_id
        await emit_admin_event(
            ps,
            event_type="admin_tenant_created",
            target_tenant_id=tenant_id,
            request_id=request_id,
        )

    plaintext = _new_plaintext_key()
    async with get_tenant_session(tenant_id) as ts:
        team = await TeamRepository(ts).create(tenant_id=tenant_id, name=team_name)
        project = await ProjectRepository(ts).create(
            tenant_id=tenant_id, team_id=team.team_id, name=project_name
        )
        key_row = await VirtualApiKeyRepository(ts).create(
            plaintext,
            tenant_id=tenant_id,
            team_id=team.team_id,
            project_id=project.project_id,
            agent_id=_SANDBOX_AGENT_ID,
            label="sandbox onboarding wizard",
        )
        key_id = key_row.key_id
        await ts.commit()

    async with get_privileged_session() as ps, ps.begin():
        await emit_admin_event(
            ps,
            event_type="admin_key_minted",
            target_tenant_id=tenant_id,
            request_id=request_id,
            team_id=team.team_id,
            project_id=project.project_id,
        )

    return SandboxResult(
        tenant_id=tenant_id,
        tenant_name=name,
        team_id=team.team_id,
        project_id=project.project_id,
        key_id=key_id,
        agent_id=_SANDBOX_AGENT_ID,
        plaintext_key=plaintext,
    )
