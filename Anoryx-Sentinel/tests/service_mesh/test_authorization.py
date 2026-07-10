"""MeshAuthorizationPolicy — default-deny allow-list (F-034, ADR-0040)."""

from __future__ import annotations

import pytest

from service_mesh.exceptions import MeshAuthorizationError
from service_mesh.identity import ComponentIdentity
from service_mesh.verify import MeshAuthorizationPolicy

DOMAIN = "sentinel.mesh"


def _id(component: str, domain: str = DOMAIN) -> ComponentIdentity:
    return ComponentIdentity(trust_domain=domain, component=component)


@pytest.fixture
def policy() -> MeshAuthorizationPolicy:
    return MeshAuthorizationPolicy.from_pairs(
        {
            "gateway": ["orchestration-emitter", "admin-api"],
            "bulk-worker": ["orchestration-emitter"],
        }
    )


def test_allowed_pair_passes(policy: MeshAuthorizationPolicy):
    assert policy.is_allowed(_id("gateway"), _id("orchestration-emitter"))
    policy.enforce(_id("gateway"), _id("admin-api"))  # no raise


def test_default_deny_for_unlisted_caller(policy: MeshAuthorizationPolicy):
    assert not policy.is_allowed(_id("admin-api"), _id("gateway"))
    with pytest.raises(MeshAuthorizationError):
        policy.enforce(_id("admin-api"), _id("gateway"))


def test_deny_unlisted_callee(policy: MeshAuthorizationPolicy):
    with pytest.raises(MeshAuthorizationError):
        policy.enforce(_id("bulk-worker"), _id("admin-api"))


def test_cross_trust_domain_always_denied(policy: MeshAuthorizationPolicy):
    # Even a listed pair is denied across trust domains.
    assert not policy.is_allowed(_id("gateway"), _id("orchestration-emitter", domain="other.mesh"))
    with pytest.raises(MeshAuthorizationError):
        policy.enforce(_id("gateway"), _id("orchestration-emitter", domain="other.mesh"))
