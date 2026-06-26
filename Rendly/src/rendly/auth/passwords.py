"""Argon2id password hashing + constant-time verify (R-003 FORK C).

Uses ``argon2-cffi`` (Argon2id), the ecosystem standard — Sentinel stores Argon2id PHC strings
(``Anoryx-Sentinel/src/persistence/models/user.py``) per the OWASP password-storage guidance. The
``UserStore`` seam returns a stored PHC string; R-003 verifies a presented password against it
here. This sets the exact credential pattern R-004 inherits for the real DB-backed store —
R-003's only fixture-backed part is the *lookup*, not the hashing.

A plaintext password is NEVER stored, logged, or compared by equality. ``verify`` swallows a
mismatch into ``False`` (constant-time within Argon2) so the caller cannot distinguish "no such
user" from "wrong password" by exception *type* — both surface as the same generic 401.

The error *shape* is not enough on its own: an unknown user that skipped hashing would return far
faster than a known user with a wrong password (a *timing* enumeration oracle). :func:`dummy_verify`
closes that — the credential path runs exactly one Argon2 verification whether or not the user
exists, so the two cases are indistinguishable by time as well as by error.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError, VerifyMismatchError

# Library defaults are Argon2id with OWASP-aligned parameters.
_HASHER = PasswordHasher()

# A fixed decoy hash, computed once at import, for timing-equalization on the unknown-user path.
# Its plaintext is a throwaway random value that is never a real credential and is never stored.
_DECOY_HASH = _HASHER.hash(secrets.token_urlsafe(16))


def hash_password(plaintext: str) -> str:
    """Return an Argon2id PHC hash string for ``plaintext`` (for fixtures / R-004)."""
    return _HASHER.hash(plaintext)


def dummy_verify(plaintext: str) -> bool:
    """Run one Argon2 verify against a decoy hash; always ``False`` (timing equalization).

    Called on the unknown-user branch so an absent account costs the same Argon2 work as a
    present account with a wrong password — defeating a username-enumeration timing oracle.
    """
    try:
        _HASHER.verify(_DECOY_HASH, plaintext)
    except (VerifyMismatchError, InvalidHashError, Argon2Error):
        pass
    return False


def verify_password(phc_hash: str, plaintext: str) -> bool:
    """Constant-time verify ``plaintext`` against a stored Argon2id PHC hash.

    Returns ``False`` on any mismatch or malformed hash rather than raising, so credential
    checking has a single uniform negative outcome (no user-enumeration via error shape).
    """
    try:
        return _HASHER.verify(phc_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError, Argon2Error):
        # Wrong password OR a malformed/garbage stored hash -> a single uniform False.
        return False
