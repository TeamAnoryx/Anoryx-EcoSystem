"""ProviderKeySource protocol + credential value object (F-027)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ProviderCredentials:
    """Fetched credential material for one provider.

    `values` holds provider-shaped fields (e.g. {"api_key": "..."} for
    Anthropic, {"region": .., "access_key_id": .., "secret_access_key": ..}
    for Bedrock) — never logged or repr'd with real values (see __repr__).
    """

    provider: str
    values: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:  # pragma: no cover — defense in depth only
        return f"ProviderCredentials(provider={self.provider!r}, values=<redacted>)"


class ProviderKeySource(Protocol):
    """Fetches live credentials for a provider. Fail-closed on any error."""

    async def fetch_credentials(self, provider: str) -> ProviderCredentials:
        """Return credentials for `provider`.

        Raises KeyNotConfigured if the provider has no credentials on this
        backend, or KeyFetchError on any backend failure (network, auth,
        malformed secret). Never returns a partial/stale result silently.
        """
        ...
