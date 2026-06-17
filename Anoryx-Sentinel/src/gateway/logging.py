"""Structlog secret-redaction processor (F-006, ADR-0008 threat #1).

The router introduces three provider integrations (OpenAI, Anthropic, Bedrock)
whose credentials are secrets. Vector #1 requires that provider API keys and AWS
credentials never reach the logs — not via an explicit log field, not via an
accidental bind, and not via an exception arg.

This module installs a structlog processor that DROPS any event-dict key whose
NAME matches a secret pattern (case-insensitive):

    *_API_KEY     e.g. anthropic_api_key, openai_api_key
    *SECRET*      e.g. aws_secret_access_key, sentinel_key_secret, client_secret
    AWS_*         e.g. aws_access_key_id, aws_region (region is not secret but the
                  prefix is dropped wholesale — region is carried elsewhere as a
                  non-AWS-prefixed field when it must be logged)

This is a NAME-based backstop, not a value scanner: it is cheap, deterministic,
and cannot itself leak the value it is protecting. Application code MUST still
avoid binding secrets to log events in the first place; this processor is the
defense-in-depth net (ADR-0008 §8 vector #1).

The redaction is wired in configure_logging(), called once from main.py before
any request is served.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

# Compiled, case-insensitive. A key is dropped if ANY pattern matches.
_SECRET_KEY_PATTERNS = (
    re.compile(r".*_API_KEY$", re.IGNORECASE),
    re.compile(r".*SECRET.*", re.IGNORECASE),
    re.compile(r"^AWS_.*", re.IGNORECASE),
)

# The placeholder substituted for a dropped key. We do NOT emit the original
# value; the key itself is replaced with a marker so operators can see that a
# secret-shaped field was scrubbed without learning its contents.
_REDACTED = "[REDACTED]"


def _is_secret_key(key: str) -> bool:
    return any(pat.match(key) for pat in _SECRET_KEY_PATTERNS)


def redact_secrets_processor(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor: replace secret-shaped keys' VALUES with a marker.

    We replace the value rather than delete the key so the presence of a
    secret-shaped field is still visible in the log (useful for catching a
    code path that is binding a secret it should not), but the value never
    appears. Matching is on the key NAME only — pure and value-independent.
    """
    for key in list(event_dict.keys()):
        if isinstance(key, str) and _is_secret_key(key):
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging() -> None:
    """Configure structlog with the secret-redaction processor installed.

    Idempotent-ish: structlog.configure replaces the active configuration.
    Called once from main.py at startup. The redaction processor runs BEFORE
    the renderer so the secret value is scrubbed before serialization.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_secrets_processor,  # threat #1: drop secret-shaped keys.
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        cache_logger_on_first_use=True,
    )
