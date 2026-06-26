"""Fixtures for the R-003 auth suite.

Builds a REAL ES256 key pair (through the production loader), the fixture user store, and a
FastAPI TestClient over the real app. ``sign_raw`` mints arbitrary signed payloads so the
adversarial tests can craft expired / wrong-issuer / wrong-token_use / alg-confusion tokens
against the same key the server verifies with — the user lookup is the only fixture-backed part.
"""

from __future__ import annotations

from collections.abc import Callable

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from rendly.app import create_app
from rendly.auth.keys import KeyMaterial, load_key_material
from rendly.auth.refresh import InMemoryRefreshTokenStore
from rendly.auth.store import build_fixture_store


@pytest.fixture(scope="session")
def _raw_keypair() -> tuple[str, str]:
    """A freshly generated ES256 (P-256) key pair as (private_pem, public_pem) strings."""
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )
    return private_pem, public_pem


@pytest.fixture
def private_pem(_raw_keypair: tuple[str, str]) -> str:
    return _raw_keypair[0]


@pytest.fixture
def public_pem(_raw_keypair: tuple[str, str]) -> str:
    return _raw_keypair[1]


@pytest.fixture
def key(private_pem: str) -> KeyMaterial:
    """KeyMaterial loaded through the real fail-closed loader (not a hand-built object)."""
    return load_key_material(private_pem)


@pytest.fixture
def client(key: KeyMaterial) -> TestClient:
    """TestClient over the real app: fixture user store + in-memory refresh store + the ES256 key."""
    app = create_app(
        user_store=build_fixture_store(),
        refresh_store=InMemoryRefreshTokenStore(),
        key=key,
    )
    return TestClient(app)


@pytest.fixture
def sign_raw(key: KeyMaterial) -> Callable[..., str]:
    """Mint a signed token from an arbitrary claims dict (default valid ES256 over our key)."""

    def _sign(payload: dict, *, algorithm: str = "ES256", signing_key: object | None = None) -> str:
        return jwt.encode(payload, signing_key or key.private_key, algorithm=algorithm)

    return _sign
