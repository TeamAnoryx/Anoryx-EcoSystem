"""PII detector — Microsoft Presidio Analyzer backend (F-005, ADR-0007 §3, D1).

Detects the following entity types (English only — multi-language deferred to F-005b):
  EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE, IP_ADDRESS,
  US_PASSPORT, US_DRIVER_LICENSE, MEDICAL_LICENSE, LOCATION, PERSON

  Honest scope (FIX-3):
  - US_SSN: Presidio's default AnalyzerEngine with the en_core_web_lg spacy
    model returns NO results for US SSN patterns (e.g. "123-45-6789") at any
    confidence threshold.  This is a model limitation, not a threshold issue.
    US_SSN detection is DEFERRED to F-005b, which will add a dedicated regex-
    based Presidio recognizer.  The entity is NOT listed as "covered" here.
    (Empirical evidence: analyzer.analyze(text="My SSN is 123-45-6789",
    entities=["US_SSN"], language="en") returns [] in this environment.)
  - PHONE_NUMBER: Presidio scores phone numbers at 0.40–0.75 depending on
    context.  A per-entity threshold of 0.40 is used so common US phone
    formats are detected and masked (FIX-3, Option α).
    (Empirical evidence: analyzer.analyze(text="call 415-555-2671 now",
    entities=["PHONE_NUMBER"], language="en") returns score=0.40.)

Design decisions
----------------
- Presidio Analyzer is LAZY-LOADED (imported on first detect() call) so the
  package is importable without the heavy spacy model being installed (CI / unit
  tests do not require it).
- If the Presidio import or model-load fails, the detector FAIL-SAFE BLOCKS
  every request (ADR-0007 D3): it raises an exception that the registry wraps as
  HookFailSafeError → 500 internal_error.  This is safer than passing through
  content that cannot be inspected.
- Inspection is bounded to MAX_PII_INSPECT_CHARS (default 50 000) to stay within
  the latency budget (ADR-0007 §15 target: PII ≤ ~30 ms).
- action is driven by PII_ACTION env var: "mask" | "tokenize" | "block".
- sample_excerpt_redacted is ALWAYS omitted: constructing it from surrounding
  context risks leaking adjacent raw PII characters alongside the marker (D7
  invariant — if cannot guarantee, omit the field).

Per-entity confidence thresholds (FIX-3)
-----------------------------------------
  PHONE_NUMBER: 0.40 (Presidio scores US phone numbers 0.40–0.75; global
    threshold of 0.85 would suppress all phone detection).
  All other entities: PII_CONFIDENCE_THRESHOLD (default 0.85).

Confidence → severity mapping
------------------------------
  score >= 0.90  → critical
  score >= 0.80  → high
  score >= 0.70  → medium
  else           → low
  (threshold gate: only scores >= per-entity threshold are acted on / emitted)

Multi-language deferral
-----------------------
  F-005 inspects English-language content only.  Presidio's default analyzer
  engine uses the en_core_web_lg spacy model.  Multi-language PII detection is
  deferred to F-005b (ADR-0007 §16).  Callers MUST NOT rely on this detector for
  non-English input — it may miss PII in other languages.
"""

from __future__ import annotations

import re
import structlog
from typing import Any

from orchestration.hooks.base import DetectorResult, PreRequestHook

log = structlog.get_logger(__name__)

# PII entity types to detect (ADR-0007 D1 scope / FIX-3 honest scope).
# US_SSN is EXCLUDED: Presidio's default model returns no results for SSN
# patterns regardless of threshold.  Deferred to F-005b (dedicated recognizer).
_PII_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "MEDICAL_LICENSE",
    "LOCATION",
    "PERSON",
]

# Per-entity confidence thresholds (FIX-3, Option α).
# Presidio scores PHONE_NUMBER at 0.40–0.75, which is below the global
# PII_CONFIDENCE_THRESHOLD of 0.85.  A per-entity override allows phone
# detection without lowering the global threshold for higher-precision entities.
_PER_ENTITY_THRESHOLDS: dict[str, float] = {
    "PHONE_NUMBER": 0.40,
}

# Mask token used as a replacement placeholder in content forwarded upstream.
# Uses a format that cannot be mistaken for raw PII.
_MASK_TEMPLATE = "[REDACTED:{entity_type}]"


def _confidence_to_severity(score: float) -> str:
    """Map Presidio confidence score to events.schema.json severity enum."""
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"


def _action_taken_for(pii_action: str) -> str:
    """Map PII_ACTION config value to events.schema.json action_taken enum."""
    mapping = {"mask": "masked", "tokenize": "tokenized", "block": "blocked"}
    return mapping.get(pii_action, "masked")


# Module-level lazy singletons — initialised on first call to _get_analyzer().
_analyzer: Any = None
_analyzer_failed: bool = False
_analyzer_error: Exception | None = None


def _get_analyzer() -> Any:
    """Return the Presidio AnalyzerEngine, lazy-loading on first call.

    Raises RuntimeError if the import or model load fails.
    ADR-0007 D3: callers must treat this as a fail-safe block trigger.
    """
    global _analyzer, _analyzer_failed, _analyzer_error

    if _analyzer_failed:
        raise RuntimeError(
            f"Presidio AnalyzerEngine failed to load (fail-safe block active): "
            f"{_analyzer_error!r}"
        ) from _analyzer_error

    if _analyzer is not None:
        return _analyzer

    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import-untyped]

        _analyzer = AnalyzerEngine()
        log.info("orchestration.pii_detector.analyzer_loaded")
    except Exception as exc:
        _analyzer_failed = True
        _analyzer_error = exc
        log.error(
            "orchestration.pii_detector.analyzer_load_failed",
            exc_type=type(exc).__name__,
            # Never log exc message — may contain path info.
        )
        raise RuntimeError(
            f"Presidio AnalyzerEngine failed to load: {type(exc).__name__}"
        ) from exc

    return _analyzer


def _reset_analyzer_for_testing() -> None:
    """Reset the lazy analyzer singleton — for test isolation only."""
    global _analyzer, _analyzer_failed, _analyzer_error
    _analyzer = None
    _analyzer_failed = False
    _analyzer_error = None


def _apply_pii_masks(text: str, results: list[Any], action: str) -> str:
    """Apply masking/tokenization to a text by replacing detected spans.

    Replacements are applied in reverse order of start position to preserve
    offsets for earlier spans.
    """
    if action == "block":
        # Block: no mutation needed (content not forwarded).
        return text

    # Sort by start descending to apply replacements without offset drift.
    sorted_results = sorted(results, key=lambda r: r.start, reverse=True)
    text_list = list(text)
    for result in sorted_results:
        entity = result.entity_type
        if action == "tokenize":
            replacement = f"[TOKEN:{entity}:{result.start}:{result.end}]"
        else:
            replacement = _MASK_TEMPLATE.format(entity_type=entity)
        text_list[result.start : result.end] = list(replacement)
    return "".join(text_list)


class PIIHook(PreRequestHook):
    """Pre-request PII detection hook using Microsoft Presidio Analyzer.

    Inspect content against _PII_ENTITIES with per-finding confidence threshold.
    Action (mask / tokenize / block) is driven by OrchestrationSettings.pii_action.

    On the FIRST finding that meets the threshold:
      - block:    return DetectorResult(action="block", event=...).
      - mask/tokenize: apply ALL findings as masks/tokens, return DetectorResult(
                  action="mask", event=..., modified_payload=...) for the first
                  finding's event.  Remaining findings are emitted separately via
                  context.emit() by the registry.

    Multi-finding behaviour: the hook returns the FIRST finding's result and
    bundles the masked content.  The registry receives "mask" and emits the event
    for the first finding.  Additional findings are not independently emitted by
    this hook — the registry does not call inspect() multiple times.  Each call
    to inspect() therefore emits at most one event (plus the registry-level emit
    for that result).  For a document with N PII items, each hook call yields
    one event (for the highest-confidence or first finding); the event cap (D4)
    limits total events to EVENTS_PER_DETECTOR_CAP per request.
    """

    detector_slug = "data-protection"

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Inspect content for PII.  Bounded to MAX_PII_INSPECT_CHARS."""
        if not content:
            return DetectorResult(action="pass")

        # Bound inspection (latency / memory cap).
        inspected = content[: self._settings.max_pii_inspect_chars]

        try:
            analyzer = _get_analyzer()
        except RuntimeError:
            # Fail-safe block per D3: if the analyzer cannot load, block the request.
            raise

        results = analyzer.analyze(
            text=inspected,
            entities=_PII_ENTITIES,
            language="en",
        )

        # Filter by per-entity threshold (FIX-3, Option α).
        # Each entity type uses either its per-entity override or the global
        # PII_CONFIDENCE_THRESHOLD.  This allows entities like PHONE_NUMBER
        # (which Presidio scores at 0.40–0.75) to be detected without lowering
        # the global threshold for higher-precision entities.
        global_threshold = self._settings.pii_confidence_threshold
        above_threshold = [
            r for r in results
            if r.score >= _PER_ENTITY_THRESHOLDS.get(r.entity_type, global_threshold)
        ]

        if not above_threshold:
            return DetectorResult(action="pass")

        # Sort by score descending, take first as the "primary" finding.
        above_threshold.sort(key=lambda r: r.score, reverse=True)
        primary = above_threshold[0]

        severity = _confidence_to_severity(primary.score)
        action_taken = _action_taken_for(self._settings.pii_action)

        # Build event dict (envelope fields are stamped by HookContext.emit()).
        # sample_excerpt_redacted is ALWAYS omitted per D7 invariant.
        event = {
            "event_type": "pii_blocked",
            "pattern_name": _pattern_name_safe(primary.entity_type),
            "severity": severity,
            "action_taken": action_taken,
        }

        pii_action = self._settings.pii_action

        if pii_action == "block":
            return DetectorResult(action="block", event=event, modified_payload=None)

        # mask or tokenize: apply all findings.
        masked = _apply_pii_masks(inspected, above_threshold, pii_action)
        # If we truncated the content for inspection, append the unscanned tail.
        if len(content) > self._settings.max_pii_inspect_chars:
            masked = masked + content[self._settings.max_pii_inspect_chars :]

        return DetectorResult(action="mask", event=event, modified_payload=masked)


def _pattern_name_safe(entity_type: str) -> str:
    """Return a schema-safe pattern_name (≤128, never the matched value)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", entity_type).lower()[:128]
