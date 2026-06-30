"""Row <-> frozen-domain mapping + the minimal identity write primitives (R-004).

The R-003 seams are READ-only (look up a credential, fetch a user). Onboarding still
needs WRITE primitives to put identity rows in place; this module is that narrow write
surface plus the single row->domain reconstruction point so the store and the tests
share one mapping (DRY) and never drift.

Reconstruction rebuilds the FROZEN R-002 types via their constructors (never mutating):
ids are returned verbatim (NO canonicalization — mixed-case in, mixed-case out),
``created_at`` stays tz-aware UTC, and the ``presence`` / ``org_role`` text columns are
turned back into their ``StrEnum`` members. Tenant provisioning is a privileged/admin op
(the global ``tenants`` registry); user/profile/credential inserts run under the row's
own tenant session so RLS WITH CHECK binds them to that tenant.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..enums import OrgRole, PresenceStatus
from ..profile import Profile
from ..tenant import Tenant
from ..user import User
from .models import CredentialRow, ProfileRow, TenantRow, UserRow

# --- row -> frozen domain --------------------------------------------------------------


def tenant_from_row(row: TenantRow) -> Tenant:
    return Tenant(tenant_id=row.tenant_id, created_at=row.created_at)


def user_from_row(row: UserRow) -> User:
    return User(
        user_id=row.user_id,
        tenant_id=row.tenant_id,
        display_name=row.display_name,
        status_text=row.status_text,
        presence=PresenceStatus(row.presence),
        created_at=row.created_at,
    )


def profile_from_row(row: ProfileRow) -> Profile:
    return Profile(
        user_id=row.user_id,
        tenant_id=row.tenant_id,
        org_role=OrgRole(row.org_role),
        team=row.team,
    )


# --- write primitives (onboarding + test seeding) -------------------------------------


def insert_tenant(session: Session, tenant: Tenant) -> None:
    """Insert a tenant row. The ``tenants`` registry is global (no RLS) — use a PRIVILEGED
    session; ``rendly_app`` has no INSERT grant on it (tenant provisioning is admin)."""
    session.add(TenantRow(tenant_id=tenant.tenant_id, created_at=tenant.created_at))


def insert_user(session: Session, user: User) -> None:
    """Insert a user row under a TENANT session (RLS WITH CHECK binds it to the GUC tenant)."""
    session.add(
        UserRow(
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            display_name=user.display_name,
            status_text=user.status_text,
            presence=user.presence.value,
            created_at=user.created_at,
        )
    )


def insert_profile(session: Session, profile: Profile) -> None:
    """Insert a profile row under a TENANT session (one profile per user, RLS-scoped)."""
    session.add(
        ProfileRow(
            tenant_id=profile.tenant_id,
            user_id=profile.user_id,
            org_role=profile.org_role.value,
            team=profile.team,
        )
    )


def insert_credential(
    session: Session,
    *,
    username: str,
    user_id: str,
    tenant_id: str,
    password_hash: str,
    created_at,
) -> None:
    """Insert a credential row under a TENANT session. ``password_hash`` is an Argon2id PHC."""
    session.add(
        CredentialRow(
            username=username,
            user_id=user_id,
            tenant_id=tenant_id,
            password_hash=password_hash,
            created_at=created_at,
        )
    )


# --- read helpers (used by the store; kept here so mapping lives in one place) ---------


def load_user(session: Session, *, user_id: str, tenant_id: str) -> User | None:
    """Load a user within the session's tenant scope (RLS applies on a tenant session)."""
    row = session.execute(
        select(UserRow).where(UserRow.tenant_id == tenant_id, UserRow.user_id == user_id)
    ).scalar_one_or_none()
    return user_from_row(row) if row is not None else None
