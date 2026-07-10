"""Leaf rotation classification (F-034, ADR-0040)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography import x509

from service_mesh.ca import MeshCa
from service_mesh.identity import ComponentIdentity
from service_mesh.rotation import RotationState, evaluate

DOMAIN = "sentinel.mesh"


def _leaf(ttl_hours: int) -> x509.Certificate:
    ca = MeshCa.generate(DOMAIN)
    cred = ca.issue(
        ComponentIdentity(trust_domain=DOMAIN, component="gateway"), ttl_hours=ttl_hours
    )
    return x509.load_pem_x509_certificate(cred.cert_pem)


def test_fresh_leaf_is_fresh():
    leaf = _leaf(24)
    status = evaluate(leaf)
    assert status.state is RotationState.FRESH
    assert not status.needs_renewal


def test_leaf_past_two_thirds_is_due():
    leaf = _leaf(24)
    # Jump to just past 2/3 of a 24h TTL (~16h) from not_valid_before.
    now = leaf.not_valid_before_utc + timedelta(hours=17)
    status = evaluate(leaf, now=now)
    assert status.state is RotationState.DUE
    assert status.needs_renewal


def test_expired_leaf_is_expired():
    leaf = _leaf(1)
    now = leaf.not_valid_after_utc + timedelta(hours=1)
    status = evaluate(leaf, now=now)
    assert status.state is RotationState.EXPIRED
    assert status.needs_renewal
    assert status.seconds_until_expiry < 0


def test_invalid_fraction_rejected():
    leaf = _leaf(24)
    with pytest.raises(ValueError):
        evaluate(leaf, renew_at_fraction=1.5)
