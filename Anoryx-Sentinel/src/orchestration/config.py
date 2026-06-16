"""Orchestration layer configuration (F-005, ADR-0007 §19).

All values are env-driven via pydantic-settings, consistent with the existing
GatewaySettings pattern in src/gateway/config.py.  Defaults match the
ADR-0007 approved configuration table exactly.

Entropy threshold is set at 4.5 bits/character (Shannon).  This value was
chosen empirically: English prose averages ~3.5 bits/char; random hex/base64
keys average 5.0–6.0 bits/char.  4.5 separates typical text from secrets
while staying above common structured data (JSON, base64-padded tokens).
It is documented here per the ADR requirement to "document value".

Spacy / Presidio model download step:
  python -m spacy download en_core_web_lg
  # or: pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl
The package remains importable without the model installed (detectors lazy-load).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class OrchestrationSettings(BaseSettings):
    """Runtime configuration for the F-005 inspection layer.

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
    # PII detection (ADR-0007 §19)
    # -------------------------------------------------------------------------

    #: Master toggle for the PII hook.
    pii_detection_enabled: bool = True

    #: Mitigation action when PII is detected.
    #: One of "mask" | "tokenize" | "block" → action_taken "masked"|"tokenized"|"blocked".
    pii_action: str = "mask"

    #: Minimum Presidio confidence score to act and emit (default 0.85).
    pii_confidence_threshold: float = 0.85

    #: Upper bound on characters inspected by the PII detector (latency/memory cap).
    max_pii_inspect_chars: int = 50_000

    # -------------------------------------------------------------------------
    # Injection detection (ADR-0007 §19)
    # -------------------------------------------------------------------------

    #: Master toggle for the injection hook.
    injection_detection_enabled: bool = True

    #: classifier_score >= this threshold → action_taken "blocked", else "logged".
    injection_score_threshold: float = 0.75

    # -------------------------------------------------------------------------
    # Secret detection (ADR-0007 §19)
    # -------------------------------------------------------------------------

    #: Master toggle for both inbound and outbound secret hooks.
    secret_detection_enabled: bool = True

    #: Character used when masking a detected secret in outbound traffic.
    secret_redact_character: str = "*"  # noqa: S105 — masking char, not a credential

    #: Shannon-entropy threshold for generic high-entropy credential detection.
    #: Tuned at 4.5 bits/char — above prose (~3.5), below random keys (~5.0–6.0).
    #: See module docstring for rationale.
    entropy_threshold: float = 4.5

    #: Minimum token length before entropy is evaluated (threat #6 UUID FP mitigation).
    min_token_length_for_entropy: int = 20

    # -------------------------------------------------------------------------
    # Shadow-AI emission (ADR-0007 §13, §19)
    # -------------------------------------------------------------------------

    #: Gates the shadow-AI event-emission primitive.  Default false: F-005 ships
    #: only the emission seam.  Real detection is deferred to F-007.
    shadow_ai_emission_enabled: bool = False

    # -------------------------------------------------------------------------
    # Event / stream limits (ADR-0007 §19, D4, D2)
    # -------------------------------------------------------------------------

    #: Maximum events per detector per request (D4 — event-flood DoS mitigation).
    events_per_detector_cap: int = 10

    #: Sliding-window buffer size for outbound stream secret inspection (D2).
    #: Must be large enough to span the longest secret pattern plus margin (8 KiB).
    stream_inspect_buffer_bytes: int = 8_192


_settings: OrchestrationSettings | None = None


def get_orchestration_settings() -> OrchestrationSettings:
    """Return the module-level singleton OrchestrationSettings.

    Lazy-initialised so import does not trigger env reads at module load.
    """
    global _settings
    if _settings is None:
        _settings = OrchestrationSettings()
    return _settings


def _reset_orchestration_settings() -> None:
    """Reset the singleton for test isolation.  Not for production use."""
    global _settings
    _settings = None
