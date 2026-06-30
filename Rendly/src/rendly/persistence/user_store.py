"""DbUserStore — the DB-backed implementation of R-003's ``UserStore`` seam (R-004).

Implements the R-003 ``UserStore`` ABC byte-for-byte (no contract change):

    def get_credentials(self, username: str) -> StoredCredential | None
    def get_user(self, user_id: str, tenant_id: str) -> User | None

CROSS-TENANT LOGIN LOOKUP (documented, deliberate): ``get_credentials`` runs under the
PRIVILEGED (BYPASSRLS) session because the username is a GLOBAL key and the tenant is
unknown until the row is read — ``tenant_id`` is NEVER an input to credential lookup. The
tenant claim is taken FROM the stored row and becomes the token's authoritative tenant,
exactly as R-003's in-memory store and ``TokenService`` already assume. ``get_user`` runs
under the TENANT session, so a foreign-tenant id yields zero rows (RLS) and returns
``None`` — a foreign-tenant id is indistinguishable from a missing one.

``granted_scopes`` is derived from the profile's org role using the SAME
``_SCOPES_BY_ROLE`` table R-003 defines — imported, not re-listed, so the scope bundles
can never drift from the auth layer's single source of truth.
"""

from __future__ import annotations

from sqlalchemy import select

from ..auth.store import _SCOPES_BY_ROLE, StoredCredential, UserStore
from ..user import User
from .database import get_privileged_session, get_tenant_session
from .identity_repo import load_user, profile_from_row, user_from_row
from .models import CredentialRow, ProfileRow, UserRow


class DbUserStore(UserStore):
    """A Postgres-backed ``UserStore``. Real rows, real Argon2id hashes, RLS-scoped reads."""

    def get_credentials(self, username: str) -> StoredCredential | None:
        """Resolve a credential by global username (privileged, cross-tenant).

        Reads the credential row, then its user + profile rows (all under the privileged
        BYPASSRLS session — the tenant is discovered from the row, never supplied). Returns
        ``None`` if no such username. ``granted_scopes`` = ``_SCOPES_BY_ROLE[org_role]``.
        """
        with get_privileged_session() as session:
            cred = session.execute(
                select(CredentialRow).where(CredentialRow.username == username)
            ).scalar_one_or_none()
            if cred is None:
                return None
            user_row = session.execute(
                select(UserRow).where(
                    UserRow.tenant_id == cred.tenant_id, UserRow.user_id == cred.user_id
                )
            ).scalar_one_or_none()
            profile_row = session.execute(
                select(ProfileRow).where(
                    ProfileRow.tenant_id == cred.tenant_id, ProfileRow.user_id == cred.user_id
                )
            ).scalar_one_or_none()
            if user_row is None or profile_row is None:
                # A credential with no backing user/profile is a corrupt onboarding; treat
                # as "no such credential" rather than leak a partial record.
                return None
            profile = profile_from_row(profile_row)
            return StoredCredential(
                user=user_from_row(user_row),
                profile=profile,
                password_hash=cred.password_hash,
                granted_scopes=_SCOPES_BY_ROLE[profile.org_role],
            )

    def get_user(self, user_id: str, tenant_id: str) -> User | None:
        """Fetch a user by id WITHIN ``tenant_id`` (RLS-scoped); ``None`` if absent/foreign-tenant."""
        with get_tenant_session(tenant_id) as session:
            return load_user(session, user_id=user_id, tenant_id=tenant_id)
