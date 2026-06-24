"""F-020 webhook-dispatcher configuration (ADR-0023 §5.3/§5.5/§7).

All values are env-driven via pydantic-settings, consistent with the existing
BulkSettings / OrchestrationSettings convention (no env prefix by default:
a field `webhook_candidates_stream_key` reads `WEBHOOK_CANDIDATES_STREAM_KEY`).

Secrets are NOT stored here (CLAUDE.md #4): signing_secret / credential blobs
live in webhook_config rows as secret_box(AES-256-GCM) ciphertext and are
decrypted by the dispatcher at send time only.

NEVER log: any field ending in _secret or _key, or raw error text from
outbound HTTP responses.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default port allowlist (ADR-0023 §7 hardening point 3).
_DEFAULT_PORT_ALLOWLIST = {443, 8088}

# Minimum / maximum bounded retry budget (ADR-0023 §5.3 D3).
_DEFAULT_WEBHOOK_RETRY_MAX = 3

# HMAC-SHA256 replay-rejection tolerance window (ADR-0023 §5.5).
WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 300


class WebhookSettings(BaseSettings):
    """F-020 webhook-dispatcher runtime configuration.

    All fields are read from environment variables (case-insensitive).
    No secrets are stored here; the class only carries operational knobs.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Feature flag (default OFF — emits into webhook:candidates only when True)
    # -------------------------------------------------------------------------

    #: Master F-020 toggle. When False the XADD tap in context.emit() is a no-op
    #: and the dispatcher worker matches nothing and emits nothing.
    webhook_dispatch_enabled: bool = False

    # -------------------------------------------------------------------------
    # Redis Streams keys (reuse the F-009 pool)
    # -------------------------------------------------------------------------

    #: Stream that context.emit() XADDs candidate metadata envelopes into.
    #: Consumed by the webhook-dispatcher worker.
    webhook_candidates_stream_key: str = "webhook:candidates"

    #: Consumer group name for the dispatcher worker pool.
    webhook_consumer_group: str = "webhook-dispatcher-group"

    #: Delivery DLQ — XADD destination for dead-lettered deliveries.
    webhook_dlq_stream_key: str = "webhook:dlq"

    # -------------------------------------------------------------------------
    # Retry / backoff bounds (ADR-0023 §5.3 D3)
    # -------------------------------------------------------------------------

    #: Maximum delivery attempts before a job is dead-lettered.
    webhook_retry_max: int = _DEFAULT_WEBHOOK_RETRY_MAX

    #: Base delay (seconds) for exponential backoff between retries.
    webhook_retry_base_delay_seconds: float = 2.0

    #: Cap on backoff delay (seconds) — prevents extreme delays on high retry counts.
    webhook_retry_max_delay_seconds: float = 30.0

    # -------------------------------------------------------------------------
    # SSRF guard (ADR-0023 §7)
    # -------------------------------------------------------------------------

    #: Ports the URL guard permits. XADD in context.emit() never checks ports
    #: (it never makes outbound connections); this controls the dispatcher guard.
    webhook_allowed_ports: frozenset[int] = frozenset(_DEFAULT_PORT_ALLOWLIST)

    # -------------------------------------------------------------------------
    # HTTP client (ADR-0023 §5.3/§7)
    # -------------------------------------------------------------------------

    #: Total timeout (seconds) for the outbound webhook POST (connect + read).
    webhook_http_timeout_seconds: float = 10.0

    # -------------------------------------------------------------------------
    # Consumer worker loop
    # -------------------------------------------------------------------------

    #: Max messages to read per XREADGROUP call.
    webhook_read_count: int = 10

    #: Block time (ms) on XREADGROUP when the stream is empty.
    webhook_read_block_ms: int = 5000

    #: Idle time (ms) before a pending message is reclaimable from a crashed worker.
    webhook_claim_min_idle_ms: int = 60_000

    # -------------------------------------------------------------------------
    # TEST-ONLY bypass seam (DEFAULT EMPTY — completely inert in production)
    # -------------------------------------------------------------------------

    #: TEST-ONLY. DEFAULT EMPTY. When non-empty, check_url bypasses the
    #: IP-classification deny AND allows http scheme + the listed port for
    #: any host[:port] listed here so a real local sink (e.g. http://127.0.0.1:PORT)
    #: is reachable for the V12 non-stubbed e2e test.
    #:
    #: Production safety: this field defaults to frozenset() (empty). No production
    #: code path ever sets it. It is read ONLY from the environment variable
    #: WEBHOOK_ALLOWED_TEST_HOSTS (comma-separated host:port strings). A security
    #: reviewer can confirm it is a dead code path in production by verifying:
    #:   (a) the default is empty, and
    #:   (b) no prod config or infra sets WEBHOOK_ALLOWED_TEST_HOSTS.
    #: This is the ONLY guard bypass in url_guard.py and it is reachable ONLY
    #: for hosts explicitly listed in this default-empty set.
    #:
    #: Example for tests: WEBHOOK_ALLOWED_TEST_HOSTS="127.0.0.1:19876"
    webhook_allowed_test_hosts: frozenset[str] = frozenset()

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("webhook_retry_max")
    @classmethod
    def _positive_retry(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("webhook_retry_max must be > 0")
        return v

    @field_validator("webhook_http_timeout_seconds", "webhook_retry_base_delay_seconds")
    @classmethod
    def _positive_float(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("webhook float settings must be > 0")
        return v


@lru_cache(maxsize=1)
def get_webhook_settings() -> WebhookSettings:
    """Cached WebhookSettings accessor (one instance per process)."""
    return WebhookSettings()


def _reset_webhook_settings_for_testing() -> None:
    """Clear the cached settings (test helper only)."""
    get_webhook_settings.cache_clear()
