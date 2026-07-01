"""O-004 distribution client — publish a signed policy (ADR-0005 §3.4, vectors 7-9).

POSTs an already-signed ``budget_limit`` to the real O-004 receive-policy seam
``POST /v1/policies/distributions`` with a Bearer service token, ``sign_on_behalf=false``
(O-004 never signs — ADR-0004 Fork A). Response classification mirrors O-004's own
upstream policy and the D-004 transient/permanent split:

  * 202            -> Distributed(distribution_id)
  * 429 / 5xx      -> TransientPublishError (retry; O-004/network is momentarily unavailable)
  * other 4xx      -> PermanentPublishError (the policy/token is rejected; do not retry)
  * network/timeout-> TransientPublishError (connection refused / read timeout is retryable)

No token or signature byte is ever logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .config import EngineSettings


class TransientPublishError(Exception):
    """A retryable distribution failure (429/5xx/connection) — the decision stays pending."""


class PermanentPublishError(Exception):
    """A non-retryable distribution rejection (4xx other than 429) — dead-letter it."""


@dataclass(frozen=True)
class Distributed:
    distribution_id: str


async def publish_signed_policy(
    signed_policy: dict[str, Any], settings: EngineSettings
) -> Distributed:
    """POST a signed policy to the O-004 seam. Raises Transient/PermanentPublishError."""
    url = settings.distribution_endpoint()
    headers = {"Authorization": f"Bearer {settings.service_token}"}
    body = {"policy": signed_policy, "sign_on_behalf": False}

    try:
        async with httpx.AsyncClient(timeout=settings.publish_timeout_seconds) as client:
            resp = await client.post(url, json=body, headers=headers)
    except (httpx.TransportError, httpx.TimeoutException) as exc:
        # Connection refused / DNS / read timeout — O-004 momentarily unreachable.
        raise TransientPublishError(f"distribution transport error: {exc!r}") from exc

    if resp.status_code == 202:
        try:
            distribution_id = resp.json().get("distribution_id")
        except ValueError as exc:
            raise TransientPublishError("202 with unparseable body") from exc
        if not distribution_id:
            raise TransientPublishError("202 without a distribution_id")
        return Distributed(distribution_id=str(distribution_id))

    if resp.status_code == 429 or resp.status_code >= 500:
        raise TransientPublishError(f"distribution transient status {resp.status_code}")

    # Any other 4xx (400/401/403/422 — rejected token / schema / sign_on_behalf): permanent.
    raise PermanentPublishError(f"distribution rejected with status {resp.status_code}")
