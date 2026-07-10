"""Offline license validation (F-036, ADR-0041)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from airgap.exceptions import LicenseError, LicenseKeyError
from airgap.license import load_license_public_key, sign_license, verify_license
from policy.crypto import generate_keypair, public_key_to_pem


def _claims(**over) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "license_id": "LIC-001",
        "customer": "Acme Corp",
        "edition": "enterprise",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=365)).isoformat(),
        "features": ["hipaa", "eu_ai_act"],
        "max_tenants": 50,
    }
    base.update(over)
    return base


@pytest.fixture
def keypair():
    return generate_keypair()


def test_valid_license_verifies(keypair):
    priv, pub = keypair
    token = sign_license(_claims(), priv)
    lic = verify_license(token, pub)
    assert lic.license_id == "LIC-001"
    assert lic.customer == "Acme Corp"
    assert lic.has_feature("hipaa")
    assert lic.max_tenants == 50


def test_expired_license_rejected(keypair):
    priv, pub = keypair
    now = datetime.now(timezone.utc)
    token = sign_license(
        _claims(
            not_before=(now - timedelta(days=400)).isoformat(),
            expires_at=(now - timedelta(days=1)).isoformat(),
        ),
        priv,
    )
    with pytest.raises(LicenseError):
        verify_license(token, pub)


def test_not_yet_valid_license_rejected(keypair):
    priv, pub = keypair
    now = datetime.now(timezone.utc)
    token = sign_license(
        _claims(
            not_before=(now + timedelta(days=1)).isoformat(),
            expires_at=(now + timedelta(days=30)).isoformat(),
        ),
        priv,
    )
    with pytest.raises(LicenseError):
        verify_license(token, pub)


def test_wrong_key_rejected(keypair):
    priv, _ = keypair
    _, other_pub = generate_keypair()
    token = sign_license(_claims(), priv)
    with pytest.raises(LicenseError):
        verify_license(token, other_pub)


def test_tampered_token_rejected(keypair):
    priv, pub = keypair
    token = sign_license(_claims(), priv)
    header, payload, sig = token.split(".")
    # Flip a character in the payload segment.
    tampered_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    with pytest.raises(LicenseError):
        verify_license(f"{header}.{tampered_payload}.{sig}", pub)


def test_missing_required_claim_rejected_at_sign(keypair):
    priv, _ = keypair
    claims = _claims()
    del claims["customer"]
    with pytest.raises(LicenseError):
        sign_license(claims, priv)


def test_bad_feature_type_rejected(keypair):
    priv, pub = keypair
    token = sign_license(_claims(features="hipaa"), priv)  # str, not list
    with pytest.raises(LicenseError):
        verify_license(token, pub)


def test_load_public_key_from_env_fail_closed(monkeypatch, tmp_path, keypair):
    _, pub = keypair
    # Unset -> fail closed.
    monkeypatch.delenv("SENTINEL_LICENSE_PUBKEY_PATH", raising=False)
    with pytest.raises(LicenseKeyError):
        load_license_public_key()
    # Set to a real key -> loads.
    key_path = tmp_path / "license.pub"
    key_path.write_bytes(public_key_to_pem(pub))
    monkeypatch.setenv("SENTINEL_LICENSE_PUBKEY_PATH", str(key_path))
    loaded = load_license_public_key()
    assert loaded.public_numbers() == pub.public_numbers()
