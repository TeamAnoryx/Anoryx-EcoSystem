"""Mesh component identity — a SPIFFE-style URI (F-034, ADR-0040).

Every component in the mesh has a stable identity of the form

    spiffe://<trust-domain>/component/<component-name>

carried as the URI SAN of that component's leaf certificate. The trust domain
names the mesh (e.g. `sentinel.mesh`); the component name is the workload
(`gateway`, `orchestration-emitter`, `bulk-worker`, `admin-api`, ...).

We use the SPIFFE URI shape deliberately: it is the de-facto standard identity
format for mTLS meshes, so a later migration onto SPIFFE/SPIRE or Istio does not
require re-minting identities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from service_mesh.exceptions import InvalidIdentityError

_SCHEME = "spiffe"
# Trust-domain: DNS-like label set. Component: a single path segment.
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_COMPONENT_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


@dataclass(frozen=True)
class ComponentIdentity:
    """An immutable mesh identity: a trust domain + a component name."""

    trust_domain: str
    component: str

    def __post_init__(self) -> None:
        if not _TRUST_DOMAIN_RE.match(self.trust_domain):
            raise InvalidIdentityError(f"invalid mesh trust domain: {self.trust_domain!r}")
        if not _COMPONENT_RE.match(self.component):
            raise InvalidIdentityError(f"invalid mesh component name: {self.component!r}")

    @property
    def uri(self) -> str:
        """The SPIFFE URI form used as the leaf certificate's URI SAN."""
        return f"{_SCHEME}://{self.trust_domain}/component/{self.component}"

    @classmethod
    def parse(cls, uri: str) -> ComponentIdentity:
        """Parse a `spiffe://<domain>/component/<name>` URI, fail-closed on drift."""
        prefix = f"{_SCHEME}://"
        if not uri.startswith(prefix):
            raise InvalidIdentityError(f"identity URI must start with {prefix!r}: {uri!r}")
        rest = uri[len(prefix) :]
        parts = rest.split("/")
        if len(parts) != 3 or parts[1] != "component" or not parts[2]:
            raise InvalidIdentityError(
                f"identity URI must be {prefix}<trust-domain>/component/<name>: {uri!r}"
            )
        return cls(trust_domain=parts[0], component=parts[2])

    def __str__(self) -> str:
        return self.uri
