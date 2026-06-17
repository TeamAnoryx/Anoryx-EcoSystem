"""ProviderRegistry — per-provider client lifecycle (F-006, ADR-0008 §3).

Built in main.py::_lifespan after init_http_client and torn down on shutdown.
Holds the initialized adapters keyed by provider name. A provider with no
configured credential is NOT initialised and is therefore unavailable for every
tenant (fail-closed, §3 / §10).

Transport model (§3):
  - OpenAI:   reuses the existing module-global httpx client (init_http_client).
  - Anthropic: a dedicated httpx.AsyncClient with base_url config-pinned and
               follow_redirects=False (SSRF defense, threat #9).
  - Bedrock:  no httpx client; the BedrockAdapter lazily creates an aioboto3
               session/client per call with config-pinned region/creds.

No provider base_url is ever derived from the request body or any client header.
"""

from __future__ import annotations

import httpx
import structlog

from gateway.config import GatewaySettings
from gateway.middleware.egress_monitor import egress_request_hook
from gateway.router.providers.anthropic_provider import AnthropicAdapter
from gateway.router.providers.bedrock_provider import BedrockAdapter
from gateway.router.providers.openai_provider import OpenAiAdapter

log = structlog.get_logger(__name__)


class ProviderRegistry:
    """Holds initialized provider adapters and owns their client lifecycle."""

    def __init__(self) -> None:
        self._adapters: dict[str, object] = {}
        self._anthropic_client: httpx.AsyncClient | None = None
        self._initialized = False

    def init(self, settings: GatewaySettings) -> None:
        """Initialise adapters for every CONFIGURED provider (fail-closed).

        Idempotent: a second call is a no-op. Provider base URLs are pinned from
        config; redirects are disabled. NEVER logs keys (threat #1).
        """
        if self._initialized:
            return

        configured = settings.configured_providers()

        # OpenAI — always configured; reuses the global client via the proxy.
        self._adapters["openai"] = OpenAiAdapter(
            stream_timeout=settings.stream_timeout_seconds,
        )

        if "anthropic" in configured:
            timeout = httpx.Timeout(
                connect=min(10.0, settings.request_timeout_seconds),
                read=settings.stream_timeout_seconds,
                write=settings.request_timeout_seconds,
                pool=settings.request_timeout_seconds,
            )
            self._anthropic_client = httpx.AsyncClient(
                base_url=settings.anthropic_base_url,  # config-pinned (threat #9)
                timeout=timeout,
                follow_redirects=False,
                # F-007 (ADR-0010 §5): shadow-AI egress hook (never blocks/raises).
                event_hooks={"request": [egress_request_hook]},
            )
            self._adapters["anthropic"] = AnthropicAdapter(
                client=self._anthropic_client,
                api_key=settings.anthropic_api_key or "",
                default_max_tokens=settings.router_anthropic_default_max_tokens,
            )

        if "bedrock" in configured:
            self._adapters["bedrock"] = BedrockAdapter(
                region=settings.aws_region or "",
                access_key_id=settings.aws_access_key_id or "",
                secret_access_key=settings.aws_secret_access_key or "",
            )

        self._initialized = True
        # Log only the provider NAMES that are available — never any credential.
        log.info("provider_registry_initialized", providers=sorted(self._adapters.keys()))

    async def teardown(self) -> None:
        """Close per-provider clients. Idempotent."""
        if self._anthropic_client is not None:
            await self._anthropic_client.aclose()
            self._anthropic_client = None
        self._adapters.clear()
        self._initialized = False
        log.info("provider_registry_torn_down")

    def get(self, name: str) -> object | None:
        """Return the adapter for a provider name, or None if unavailable."""
        return self._adapters.get(name)

    def available_providers(self) -> set[str]:
        """Return the set of provider names with an initialised adapter."""
        return set(self._adapters.keys())
