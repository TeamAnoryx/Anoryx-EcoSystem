"""ComponentIdentity parse/format + validation (F-034, ADR-0040)."""

from __future__ import annotations

import pytest

from service_mesh.exceptions import InvalidIdentityError
from service_mesh.identity import ComponentIdentity


def test_uri_roundtrip():
    ident = ComponentIdentity(trust_domain="sentinel.mesh", component="gateway")
    assert ident.uri == "spiffe://sentinel.mesh/component/gateway"
    assert ComponentIdentity.parse(ident.uri) == ident


def test_str_is_uri():
    ident = ComponentIdentity(trust_domain="sentinel.mesh", component="bulk-worker")
    assert str(ident) == "spiffe://sentinel.mesh/component/bulk-worker"


@pytest.mark.parametrize(
    "domain,component",
    [
        ("Sentinel.Mesh", "gateway"),  # uppercase domain
        ("sentinel.mesh", "Gateway"),  # uppercase component
        ("sentinel..mesh", "gateway"),  # empty label
        ("sentinel.mesh", "with space"),
        ("-bad.mesh", "gateway"),
        ("sentinel.mesh", "gateway_underscore"),
    ],
)
def test_invalid_identities_rejected(domain, component):
    with pytest.raises(InvalidIdentityError):
        ComponentIdentity(trust_domain=domain, component=component)


@pytest.mark.parametrize(
    "uri",
    [
        "https://sentinel.mesh/component/gateway",  # wrong scheme
        "spiffe://sentinel.mesh/gateway",  # missing /component/
        "spiffe://sentinel.mesh/component/",  # empty component
        "spiffe://sentinel.mesh/service/gateway",  # wrong path segment
        "spiffe://sentinel.mesh/component/gateway/extra",  # too many segments
    ],
)
def test_parse_rejects_malformed_uris(uri):
    with pytest.raises(InvalidIdentityError):
        ComponentIdentity.parse(uri)
