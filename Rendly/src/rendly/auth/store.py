"""UserStore — the credential/identity lookup seam (R-003 scope decision A).

HONESTY BOUNDARY (verbatim, non-removable): R-003's end-to-end test proves the REAL
issue/verify/refresh path against a FIXTURE user store; it is NOT proven against a database. The
token cryptography and the verify/refresh logic are real and fully tested — only the user lookup
is fixture-backed. This is a stated seam, not a stubbed enforcement path. R-004 implements
:class:`UserStore` against the real database with NO contract change.

The seam is deliberately narrow — exactly what token issuance and the identity-proof route need:
look up a credential by username (password grant), and fetch a user by id within a tenant (refresh
grant re-issue + ``GET /users/me``). ``tenant_id`` is NEVER an input to credential lookup; it is
read from the stored ``User`` and becomes the token's authoritative tenant claim. ``get_user`` is
tenant-scoped: a user id resolved under the wrong tenant returns ``None`` (the same structural
cross-tenant isolation R-001/R-002 mandate — a foreign-tenant id is indistinguishable from a
missing one).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..enums import OrgRole, PresenceStatus
from ..profile import Profile, bind_profile
from ..user import User
from .passwords import hash_password

# Scope bundles granted per org role. Subsets of the 8 LOCKED contract scopes; never a new scope.
_MEMBER_SCOPES = frozenset(
    {"profile:read", "profile:write", "channels:read", "chat:read", "chat:write", "huddle:initiate"}
)
_GUEST_SCOPES = frozenset({"profile:read", "channels:read", "chat:read"})
_ADMIN_SCOPES = _MEMBER_SCOPES | {"channels:write", "channels:admin"}

_SCOPES_BY_ROLE: dict[OrgRole, frozenset[str]] = {
    OrgRole.ADMIN: _ADMIN_SCOPES,
    OrgRole.MEMBER: _MEMBER_SCOPES,
    OrgRole.GUEST: _GUEST_SCOPES,
}


@dataclass(frozen=True)
class StoredCredential:
    """Everything token issuance needs for one user. ``password_hash`` is an Argon2id PHC string."""

    user: User
    profile: Profile
    password_hash: str
    granted_scopes: frozenset[str]


class UserStore(abc.ABC):
    """The credential/identity lookup seam. R-004 implements this against the database."""

    @abc.abstractmethod
    def get_credentials(self, username: str) -> StoredCredential | None:
        """Look up a credential by username, or ``None`` if no such user (no tenant input)."""

    @abc.abstractmethod
    def get_user(self, user_id: str, tenant_id: str) -> User | None:
        """Fetch a user by id WITHIN ``tenant_id``; ``None`` if absent or in another tenant."""


class InMemoryUserStore(UserStore):
    """A fixture, in-memory ``UserStore``. Real Argon2id hashes; no DB. R-004 replaces it."""

    def __init__(self) -> None:
        self._by_username: dict[str, StoredCredential] = {}
        self._by_id: dict[tuple[str, str], User] = {}

    def add(
        self,
        *,
        username: str,
        password: str,
        user: User,
        org_role: OrgRole,
        team: str | None = None,
    ) -> StoredCredential:
        """Register a fixture user (password hashed with real Argon2id) and index it."""
        profile = bind_profile(user, org_role=org_role, team=team)
        cred = StoredCredential(
            user=user,
            profile=profile,
            password_hash=hash_password(password),
            granted_scopes=_SCOPES_BY_ROLE[org_role],
        )
        self._by_username[username] = cred
        self._by_id[(user.tenant_id, user.user_id)] = user
        return cred

    def get_credentials(self, username: str) -> StoredCredential | None:
        return self._by_username.get(username)

    def get_user(self, user_id: str, tenant_id: str) -> User | None:
        return self._by_id.get((tenant_id, user_id))


def build_fixture_store() -> InMemoryUserStore:
    """Two tenants, three users — enough for the e2e + cross-tenant adversarial tests.

    Fixture identifiers are fixed UUIDs and the passwords are obvious non-secrets; nothing here is
    a real credential. R-004 replaces this with a DB-backed store.
    """
    from datetime import datetime, timezone

    created = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    tenant_a = "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6"
    tenant_b = "9f8e7d6c-1122-4a3b-8c9d-e0f1a2b3c4d5"

    store = InMemoryUserStore()
    store.add(
        username="alex@tenant-a.example",
        password="alex-fixture-pw",
        user=User(
            user_id="7d9e2f3a-1234-5c6b-8def-0123456789ab",
            tenant_id=tenant_a,
            display_name="Alex Rivera",
            presence=PresenceStatus.ONLINE,
            created_at=created,
        ),
        org_role=OrgRole.MEMBER,
        team="platform",
    )
    store.add(
        username="dana@tenant-a.example",
        password="dana-fixture-pw",
        user=User(
            user_id="1c2b3a49-aaaa-4bbb-8ccc-ddddeeeeffff",
            tenant_id=tenant_a,
            display_name="Dana Admin",
            presence=PresenceStatus.ONLINE,
            created_at=created,
        ),
        org_role=OrgRole.ADMIN,
    )
    store.add(
        username="kim@tenant-b.example",
        password="kim-fixture-pw",
        user=User(
            user_id="3e4f5a6b-7777-4888-9999-aaaabbbbcccc",
            tenant_id=tenant_b,
            display_name="Kim Guest",
            presence=PresenceStatus.AWAY,
            created_at=created,
        ),
        org_role=OrgRole.GUEST,
    )
    return store
