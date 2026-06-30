"""R-004 round-trip: persist the frozen identity types + a refresh family, load them back.

Proves the DB-backed stores reconstruct the EXACT R-002 frozen values: ids are NOT
canonicalized (mixed-case in, mixed-case out), timestamps stay tz-aware UTC, and the
presence / org_role enums round-trip. ``granted_scopes`` is derived from the org role via
the SAME ``_SCOPES_BY_ROLE`` table the auth layer uses (no drift).
"""

from __future__ import annotations

from datetime import datetime, timezone

from rendly.auth.store import _SCOPES_BY_ROLE
from rendly.enums import OrgRole, PresenceStatus
from rendly.persistence.database import get_tenant_session, reset_engines
from rendly.persistence.refresh_store import DbRefreshTokenStore
from rendly.persistence.user_store import DbUserStore

# Mixed-case, valid (case-insensitive hex) ids — must survive the round-trip verbatim.
T_MIXED = "2A4f8C1e-0012-4B3d-9aBc-d1E2f3A4B5c6"
U_MIXED = "7D9e2F3a-1234-5c6B-8dEf-0123456789Ab"


def test_user_round_trips_uncanonicalized(seed_identity) -> None:
    created = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    _, user, _ = seed_identity(
        tenant_id=T_MIXED,
        user_id=U_MIXED,
        username="round-trip@tenant.example",
        password="round-trip-pw",
        org_role=OrgRole.ADMIN,
        team="platform",
        display_name="Round Tripper",
        presence=PresenceStatus.BUSY,
        status_text="heads down",
        created_at=created,
    )

    loaded = DbUserStore().get_user(U_MIXED, T_MIXED)
    assert loaded is not None
    # Frozen equality + verbatim ids (NO lower-casing on read or write).
    assert loaded == user
    assert loaded.user_id == U_MIXED
    assert loaded.tenant_id == T_MIXED
    assert loaded.presence is PresenceStatus.BUSY
    assert loaded.status_text == "heads down"
    # Timestamp stays tz-aware UTC (require_aware_utc would reject a naive value).
    assert loaded.created_at.tzinfo is not None
    assert loaded.created_at.utcoffset() == timezone.utc.utcoffset(None)
    assert loaded.created_at == created


def test_credentials_round_trip_with_derived_scopes(seed_identity) -> None:
    _, user, profile = seed_identity(
        tenant_id=T_MIXED,
        user_id=U_MIXED,
        username="cred@tenant.example",
        password="cred-pw",
        org_role=OrgRole.ADMIN,
        team="platform",
    )

    cred = DbUserStore().get_credentials("cred@tenant.example")
    assert cred is not None
    assert cred.user == user
    assert cred.profile == profile
    assert cred.profile.org_role is OrgRole.ADMIN
    # granted_scopes derived from the org role — identical to the auth layer's source of truth.
    assert cred.granted_scopes == _SCOPES_BY_ROLE[OrgRole.ADMIN]
    # password_hash is an Argon2id PHC string (verifiable by the real verifier).
    from rendly.auth.passwords import verify_password

    assert verify_password(cred.password_hash, "cred-pw") is True


def test_unknown_username_returns_none(seed_identity) -> None:
    seed_identity(tenant_id=T_MIXED, user_id=U_MIXED, username="known@x.example", password="pw")
    assert DbUserStore().get_credentials("nobody@x.example") is None


def test_credential_without_backing_user_returns_none(tenant_id) -> None:
    """Corrupt onboarding: a credential whose users row is missing -> get_credentials None.

    The credentials->users FK normally makes this state impossible, so we forge it by
    disabling referential-integrity triggers for the single INSERT (SET LOCAL
    ``session_replication_role='replica'`` — superuser-only, auto-cleared at COMMIT so the
    pooled connection is never polluted). The privileged owner bypasses RLS, so no tenant
    GUC is needed. This exercises the defensive ``user_row is None`` branch in
    DbUserStore.get_credentials (the "no backing user/profile -> treat as no credential").
    """
    from datetime import datetime, timezone

    from sqlalchemy import text

    from rendly.persistence.database import get_privileged_session
    from rendly.persistence.models import CredentialRow

    username = "orphan-cred@x.example"
    created = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    with get_privileged_session() as session:
        # Autobegins this transaction; SET LOCAL skips RI triggers for the INSERT below and
        # is cleared at COMMIT. autoflush is off, so the INSERT flushes at commit() inside
        # this same RI-disabled transaction.
        session.execute(text("SET LOCAL session_replication_role = 'replica'"))
        session.add(
            CredentialRow(
                username=username,
                tenant_id=tenant_id,
                user_id="no-such-user-0000",
                password_hash="not-a-real-hash",
                created_at=created,
            )
        )
        session.commit()

    # Credential exists, but its backing user does not -> defensive branch returns None.
    assert DbUserStore().get_credentials(username) is None


def test_get_user_foreign_tenant_returns_none(seed_identity, other_tenant_id) -> None:
    seed_identity(tenant_id=T_MIXED, user_id=U_MIXED, username="u@x.example", password="pw")
    # Right user id, wrong tenant -> RLS yields zero rows -> None (not an error/leak).
    assert DbUserStore().get_user(U_MIXED, other_tenant_id) is None


def test_refresh_family_round_trips_across_fresh_engine(tenant_id, seed_identity) -> None:
    # A refresh family now FK-references its user (fk_rtf_user, DEFERRABLE INITIALLY
    # DEFERRED) — seed the backing user so issue()'s commit satisfies the constraint.
    seed_identity(
        tenant_id=tenant_id, user_id=U_MIXED, username="refresh-rt@x.example", password="pw"
    )
    store = DbRefreshTokenStore()
    scopes = frozenset({"profile:read", "chat:read"})
    roles = ("member",)
    raw = store.issue(
        user_id=U_MIXED, tenant_id=tenant_id, scopes=scopes, roles=roles, ttl_seconds=3600
    )
    assert raw.startswith("rt_")

    # Force a brand-new connection/pool to prove the state is persisted, not in-process.
    reset_engines()

    rotation = store.rotate(raw, ttl_seconds=3600)
    assert rotation.new_token.startswith("rt_")
    assert rotation.new_token != raw
    assert rotation.user_id == U_MIXED
    assert rotation.tenant_id == tenant_id
    assert rotation.scopes == scopes
    assert rotation.roles == roles

    # The successor is itself rotatable (generation+1 in the same family).
    rotation2 = store.rotate(rotation.new_token, ttl_seconds=3600)
    assert rotation2.tenant_id == tenant_id
    assert rotation2.scopes == scopes


def test_tokens_are_hashed_at_rest(tenant_id, seed_identity) -> None:
    """A store dump must never contain a usable token — only its SHA-256 hex."""
    import hashlib

    from sqlalchemy import select

    from rendly.persistence.models import RefreshTokenRow

    # Seed the backing user (fk_rtf_user is satisfied at issue()'s commit).
    seed_identity(
        tenant_id=tenant_id, user_id=U_MIXED, username="hashed-rt@x.example", password="pw"
    )
    store = DbRefreshTokenStore()
    raw = store.issue(
        user_id=U_MIXED,
        tenant_id=tenant_id,
        scopes=frozenset({"profile:read"}),
        roles=("member",),
        ttl_seconds=3600,
    )
    with get_tenant_session(tenant_id) as session:
        hashes = session.execute(select(RefreshTokenRow.token_hash)).scalars().all()
    assert hashes == [hashlib.sha256(raw.encode()).hexdigest()]
    assert raw not in hashes  # the raw token is never stored


def test_concurrent_rotation_of_same_token_serialises(tenant_id, seed_identity) -> None:
    """Two callers presenting the SAME raw token: the FOR UPDATE row-lock serialises them so
    EXACTLY ONE rotation succeeds; the loser blocks until the winner commits, then observes
    ``used==True`` and is rejected (reuse). Without the lock both could read ``used==False``
    and both mint a successor (the bug this guards). Deterministic with the lock present.
    """
    import threading

    from rendly.auth.refresh import RefreshInvalid, RefreshReuse

    seed_identity(tenant_id=tenant_id, user_id=U_MIXED, username="race-rt@x.example", password="pw")
    store = DbRefreshTokenStore()
    raw = store.issue(
        user_id=U_MIXED,
        tenant_id=tenant_id,
        scopes=frozenset({"profile:read"}),
        roles=("member",),
        ttl_seconds=3600,
    )

    results: list[str] = []
    errors: list[Exception] = []
    guard = threading.Lock()
    barrier = threading.Barrier(2)

    def _rotate() -> None:
        barrier.wait()  # release both threads simultaneously to force real lock contention
        try:
            res = store.rotate(raw, ttl_seconds=3600)
            with guard:
                results.append(res.new_token)
        except Exception as exc:  # noqa: BLE001 — recorded for the assertion below
            with guard:
                errors.append(exc)

    threads = [threading.Thread(target=_rotate) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    # Exactly one rotation won; the other was rejected (reuse — the consumed-row path).
    assert len(results) == 1, (results, errors)
    assert len(errors) == 1, (results, errors)
    assert isinstance(errors[0], (RefreshReuse, RefreshInvalid)), errors[0]
