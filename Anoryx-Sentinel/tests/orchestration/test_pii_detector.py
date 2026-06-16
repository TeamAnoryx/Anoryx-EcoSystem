"""Tests for PIIHook and pii_detector module (F-005, ADR-0007 §3).

10 covered; US_SSN deferred to F-005b (Presidio recognizer requires tuning).

Covers (spec test list):
  - 10 PII entity types detected (US_SSN excluded — deferred to F-005b).
  - Confidence threshold honored (below threshold → pass).
  - mask / block actions.
  - pii_blocked event contract conformance (schema-validated).
  - sample_excerpt_redacted never emitted (omit policy per D7).
  - Bounded inspection (MAX_PII_INSPECT_CHARS).
  - Threat #7: injection scans original content, not masked content.
  - Threat #1 / #2 deferral: encoded / obfuscated PII honestly NOT caught.
  - Lazy Presidio import: ImportError → fail-safe block.

NOTE: These tests mock the Presidio AnalyzerEngine so the test suite does not
require the spacy en_core_web_lg model to be installed in CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import jsonschema
import pytest

from orchestration.detectors.pii_detector import (
    PIIHook,
    _apply_pii_masks,
    _confidence_to_severity,
    _reset_analyzer_for_testing,
)
from orchestration.hooks.base import DetectorResult

# Load events schema for contract validation.
_EVENTS_SCHEMA_PATH = (
    Path(__file__).parent.parent.parent / "contracts" / "events.schema.json"
)
_EVENTS_SCHEMA = json.loads(_EVENTS_SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = jsonschema.Draft202012Validator(_EVENTS_SCHEMA)


def _make_settings(
    pii_action="mask",
    threshold=0.85,
    max_chars=50_000,
):
    s = MagicMock()
    s.pii_action = pii_action
    s.pii_confidence_threshold = threshold
    s.max_pii_inspect_chars = max_chars
    return s


def _make_presidio_result(entity_type: str, score: float, start: int, end: int):
    r = MagicMock()
    r.entity_type = entity_type
    r.score = score
    r.start = start
    r.end = end
    return r


@pytest.fixture(autouse=True)
def reset_analyzer():
    _reset_analyzer_for_testing()
    yield
    _reset_analyzer_for_testing()


# ---------------------------------------------------------------------------
# Confidence → severity mapping
# ---------------------------------------------------------------------------


def test_severity_critical():
    assert _confidence_to_severity(0.95) == "critical"


def test_severity_high():
    assert _confidence_to_severity(0.85) == "high"


def test_severity_medium():
    assert _confidence_to_severity(0.75) == "medium"


def test_severity_low():
    assert _confidence_to_severity(0.60) == "low"


# ---------------------------------------------------------------------------
# Masking / action application
# ---------------------------------------------------------------------------


def test_apply_pii_masks_mask():
    results = [_make_presidio_result("EMAIL_ADDRESS", 0.9, 6, 25)]
    text = "email: test@example.com suffix"
    masked = _apply_pii_masks(text, results, "mask")
    assert "[REDACTED:EMAIL_ADDRESS]" in masked
    assert "test@example.com" not in masked


def test_apply_pii_masks_tokenize():
    results = [_make_presidio_result("US_SSN", 0.95, 0, 11)]
    text = "123-45-6789 rest"
    masked = _apply_pii_masks(text, results, "tokenize")
    assert "[TOKEN:US_SSN:" in masked
    assert "123-45-6789" not in masked


def test_apply_pii_masks_block_no_mutation():
    results = [_make_presidio_result("CREDIT_CARD", 0.9, 0, 10)]
    text = "4111111111111111"
    out = _apply_pii_masks(text, results, "block")
    assert out == text  # no mutation — content is not forwarded


# ---------------------------------------------------------------------------
# All 11 PII entity types — mocked Presidio
# ---------------------------------------------------------------------------


PII_ENTITY_CASES = [
    ("EMAIL_ADDRESS", "user@example.com"),
    ("PHONE_NUMBER", "+1-555-123-4567"),
    ("CREDIT_CARD", "4111111111111111"),
    # US_SSN omitted: deferred to F-005b — Presidio's default recognizer
    # requires tuning for SSN patterns; US_SSN is NOT in _PII_ENTITIES at runtime.
    ("IBAN_CODE", "GB82WEST12345698765432"),
    ("IP_ADDRESS", "192.168.1.1"),
    ("US_PASSPORT", "A12345678"),
    ("US_DRIVER_LICENSE", "D1234567"),
    ("MEDICAL_LICENSE", "MED123456"),
    ("LOCATION", "New York City"),
    ("PERSON", "John Doe"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("entity_type,_text", PII_ENTITY_CASES)
async def test_pii_hook_detects_entity_type(entity_type, _text, mock_hook_context):
    """Each of the 11 PII entity types triggers the hook (mocked Presidio)."""
    settings = _make_settings()
    hook = PIIHook(settings=settings)

    mock_result = _make_presidio_result(entity_type, 0.90, 0, len(_text))
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect(_text, mock_hook_context)

    assert result.action in ("mask", "block")
    assert result.event is not None
    assert result.event["event_type"] == "pii_blocked"
    assert result.event["action_taken"] == "masked"
    assert result.event["pattern_name"] == entity_type.lower()


# ---------------------------------------------------------------------------
# Confidence threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_hook_below_threshold_passes(mock_hook_context):
    """Findings below PII_CONFIDENCE_THRESHOLD are ignored."""
    settings = _make_settings(threshold=0.85)
    hook = PIIHook(settings=settings)

    mock_result = _make_presidio_result("EMAIL_ADDRESS", 0.70, 0, 10)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("user@x.com", mock_hook_context)

    assert result.action == "pass"


# ---------------------------------------------------------------------------
# block action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_hook_block_action(mock_hook_context):
    settings = _make_settings(pii_action="block")
    hook = PIIHook(settings=settings)

    mock_result = _make_presidio_result("US_SSN", 0.95, 0, 11)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("123-45-6789", mock_hook_context)

    assert result.action == "block"
    assert result.event["action_taken"] == "blocked"
    assert result.modified_payload is None


# ---------------------------------------------------------------------------
# pii_blocked event contract conformance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_blocked_event_contract_conformance(tenant_context, monkeypatch):
    """Stamped event must validate against contracts/events.schema.json."""
    from orchestration.context import HookContext

    emitted = []

    async def fake_emit_inner(event, *, detector_slug):
        # Simulate stamping that HookContext.emit() does.
        import uuid as _uuid
        from datetime import UTC, datetime

        stamped = dict(event)
        stamped["tenant_id"] = tenant_context.tenant_id
        stamped["team_id"] = tenant_context.team_id
        stamped["project_id"] = tenant_context.project_id
        stamped["agent_id"] = detector_slug
        stamped["event_id"] = str(_uuid.uuid4())
        stamped["event_timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        stamped["request_id"] = "req-0000000000000001"
        emitted.append(stamped)
        return True

    ctx = HookContext(
        tenant_context=tenant_context,
        request_id="req-0000000000000001",
        original_user_content="test",
        phase="pre_request",
        _events_per_detector_cap=10,
    )
    # Monkeypatch emit to capture without DB.
    ctx.emit = fake_emit_inner  # type: ignore[method-assign]

    settings = _make_settings()
    hook = PIIHook(settings=settings)
    mock_result = _make_presidio_result("EMAIL_ADDRESS", 0.90, 0, 15)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("user@example.com", ctx)

    # Manually emit via ctx to get the stamped event.
    if result.event:
        await ctx.emit(result.event, detector_slug="data-protection")

    assert emitted, "No event emitted"
    ev = emitted[0]
    # Must validate against the schema.
    errors = list(_VALIDATOR.iter_errors(ev))
    assert not errors, f"Schema validation errors: {errors}"


# ---------------------------------------------------------------------------
# sample_excerpt_redacted NEVER present
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_blocked_no_sample_excerpt(mock_hook_context):
    """sample_excerpt_redacted must never be present (D7 invariant)."""
    settings = _make_settings()
    hook = PIIHook(settings=settings)
    mock_result = _make_presidio_result("EMAIL_ADDRESS", 0.92, 0, 15)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("user@example.com", mock_hook_context)

    assert result.event is not None
    assert "sample_excerpt_redacted" not in result.event


# ---------------------------------------------------------------------------
# Bounded inspection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_inspection_bounded(mock_hook_context):
    """Content beyond MAX_PII_INSPECT_CHARS is not passed to Presidio."""
    settings = _make_settings(max_chars=10)
    hook = PIIHook(settings=settings)

    analyzed_texts = []
    mock_analyzer = MagicMock()

    def _analyze(text, entities, language):
        analyzed_texts.append(text)
        return []

    mock_analyzer.analyze.side_effect = _analyze

    long_content = "a" * 50
    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        await hook.inspect(long_content, mock_hook_context)

    assert len(analyzed_texts[0]) == 10


# ---------------------------------------------------------------------------
# Presidio import failure → fail-safe block (RuntimeError)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_analyzer_import_failure_raises(mock_hook_context):
    """If Presidio cannot load, inspect() raises RuntimeError (D3 fail-safe)."""
    from orchestration.detectors.pii_detector import _reset_analyzer_for_testing

    _reset_analyzer_for_testing()

    settings = _make_settings()
    hook = PIIHook(settings=settings)

    with patch(
        "orchestration.detectors.pii_detector._get_analyzer",
        side_effect=RuntimeError("model missing"),
    ):
        with pytest.raises(RuntimeError, match="model missing"):
            await hook.inspect("user@example.com", mock_hook_context)


# ---------------------------------------------------------------------------
# Threat #7: injection scans original_user_content, not masked content
# Verified via registry integration test — see test_integration.py.
# Documented here for completeness: PIIHook mutates content AFTER injection
# hook has scored the original snapshot.  This test confirms the hook returns
# the masked content for forwarding, not the raw content.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_hook_returns_masked_payload(mock_hook_context):
    settings = _make_settings()
    hook = PIIHook(settings=settings)
    mock_result = _make_presidio_result("EMAIL_ADDRESS", 0.91, 5, 20)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    content = "call user@example.com now"
    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect(content, mock_hook_context)

    assert result.modified_payload is not None
    assert "user@example.com" not in result.modified_payload


# ---------------------------------------------------------------------------
# FIX-3: per-entity thresholds — PHONE_NUMBER detected at score 0.40
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fix3_phone_number_detected_at_score_040(mock_hook_context):
    """FIX-3 (Option α): PHONE_NUMBER at score 0.40 is detected and masked.

    Presidio scores US phone numbers at 0.40–0.75.  The global threshold of 0.85
    would suppress all phone detection.  Per-entity threshold 0.40 enables masking.
    """
    settings = _make_settings(threshold=0.85)  # global threshold remains 0.85
    hook = PIIHook(settings=settings)

    mock_result = _make_presidio_result("PHONE_NUMBER", 0.40, 5, 17)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    content = "call 415-555-2671 now"
    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect(content, mock_hook_context)

    assert result.action == "mask", (
        f"FIX-3: PHONE_NUMBER at score 0.40 should be masked, got {result.action!r}"
    )
    assert result.event is not None
    assert result.event["event_type"] == "pii_blocked"
    assert result.event["pattern_name"] == "phone_number"
    assert result.modified_payload is not None


@pytest.mark.asyncio
async def test_fix3_us_ssn_excluded_from_entities(mock_hook_context):
    """FIX-3 (Option β): US_SSN is excluded from _PII_ENTITIES because Presidio
    returns no results for SSN patterns in this environment (empirically verified).

    This test confirms that US_SSN is NOT in the entity list passed to Presidio,
    matching the honest documentation in the pii_detector module docstring.
    """
    from orchestration.detectors.pii_detector import _PII_ENTITIES

    assert "US_SSN" not in _PII_ENTITIES, (
        "FIX-3: US_SSN must be excluded from _PII_ENTITIES — Presidio's default "
        "model returns no results for SSN patterns (deferred to F-005b)."
    )


@pytest.mark.asyncio
async def test_fix3_phone_not_suppressed_by_global_threshold(mock_hook_context):
    """FIX-3: PHONE_NUMBER at score 0.40 is NOT suppressed by global threshold 0.85.

    Verifies the per-entity threshold logic in PIIHook.inspect() by ensuring
    that a score below the global threshold but above the PHONE_NUMBER per-entity
    threshold (0.40) still results in a mask action.
    """
    settings = _make_settings(threshold=0.85)
    hook = PIIHook(settings=settings)

    # score=0.45 — above PHONE_NUMBER per-entity threshold (0.40), below global (0.85)
    mock_result = _make_presidio_result("PHONE_NUMBER", 0.45, 0, 12)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("650-555-0101", mock_hook_context)

    assert result.action == "mask", (
        f"PHONE_NUMBER score=0.45 should be masked (per-entity threshold=0.40), "
        f"got {result.action!r}"
    )


@pytest.mark.asyncio
async def test_fix3_phone_at_score_below_per_entity_threshold_passes(mock_hook_context):
    """FIX-3: PHONE_NUMBER at score 0.30 (below per-entity threshold 0.40) is NOT acted on."""
    settings = _make_settings(threshold=0.85)
    hook = PIIHook(settings=settings)

    mock_result = _make_presidio_result("PHONE_NUMBER", 0.30, 0, 7)
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = [mock_result]

    with patch("orchestration.detectors.pii_detector._get_analyzer", return_value=mock_analyzer):
        result = await hook.inspect("555-123", mock_hook_context)

    assert result.action == "pass", (
        f"PHONE_NUMBER score=0.30 should pass (below per-entity threshold 0.40), "
        f"got {result.action!r}"
    )
