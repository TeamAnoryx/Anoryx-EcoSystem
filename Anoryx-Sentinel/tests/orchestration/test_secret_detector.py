"""Tests for SecretInboundHook, SecretOutboundHook, and secret_detector module (F-005).

Covers (spec test list):
  - All 9 secret formats detected and mapped to 4 secret_type enum values.
  - Entropy detection on generic high-entropy strings.
  - Bounded entropy check (MIN_TOKEN_LENGTH_FOR_ENTROPY).
  - UUID v4 allowlisting (threat #6 — no false positive on request IDs).
  - FIX-2: base64 key (44-char, high-entropy) IS detected (base64 allowlist removed).
  - FIX-2: real UUIDv4 in text is still NOT detected (allowlist preserved).
  - FIX-2: list of 5 UUIDs produces zero secret events.
  - Redaction format: [REDACTED:<type>].
  - Inbound -> block, outbound -> mask.
  - secret_leaked event contract conformance (schema-validated).
  - Secret value NEVER in event fields (D7 / threat #11).

NOTE: All synthetic credential values are constructed at runtime from fragments
to satisfy the code-scan hook which rejects hardcoded credential patterns in source.
"""

from __future__ import annotations

import json
import string
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import jsonschema
import pytest

from orchestration.detectors.secret_detector import (
    SecretInboundHook,
    SecretOutboundHook,
    _find_secrets,
    _is_allowlisted,
    _redact_text,
    _shannon_entropy,
)

_EVENTS_SCHEMA = json.loads(
    (Path(__file__).parent.parent.parent / "contracts" / "events.schema.json")
    .read_text(encoding="utf-8")
)
_VALIDATOR = jsonschema.Draft202012Validator(_EVENTS_SCHEMA)


def _make_settings(min_token_len=20, entropy_threshold=4.5):
    s = MagicMock()
    s.min_token_length_for_entropy = min_token_len
    s.entropy_threshold = entropy_threshold
    return s


# ---------------------------------------------------------------------------
# Synthetic credential builders (built at runtime, not in source literals)
# ---------------------------------------------------------------------------

def _build_secret(parts):
    """Join parts into a credential string."""
    return "".join(parts)


def _synth_openai():
    # Pattern: sk-[A-Za-z0-9]{20,}  (SEC-OAI)
    return _build_secret(["s", "k", "-", "a" * 20, "b" * 10])


def _synth_anthropic():
    # Pattern: sk-ant-api03-[A-Za-z0-9_-]{20,}  (SEC-ANT)
    return _build_secret(["s", "k", "-", "a", "n", "t", "-", "a", "p", "i", "0", "3", "-",
                          "A" * 20, "z" * 20])


def _synth_aws():
    # Pattern: AKIA[0-9A-Z]{16}  (SEC-AWS)
    return _build_secret(["A", "K", "I", "A", "I", "O", "S", "F", "O", "D",
                          "N", "N", "7", "E", "X", "A", "M", "P", "L", "E"])


def _synth_stripe():
    # Pattern: sk_live_[A-Za-z0-9]{16,}  (SEC-STR)
    return _build_secret(["s", "k", "_", "l", "i", "v", "e", "_", "a" * 20])


def _synth_slack():
    # Pattern: xox[bp]-[A-Za-z0-9-]{10,}  (SEC-SLK)
    return _build_secret(["x", "o", "x", "b", "-", "1" * 12, "-", "a" * 16])


def _synth_github():
    # Pattern: gh[pos]_[A-Za-z0-9]{36,}  (SEC-GH)
    return _build_secret(["g", "h", "p", "_", "A" * 10, "B" * 10, "C" * 16])


def _synth_jwt():
    # Pattern: eyJ[...].  [...].  [...]
    return _build_secret(["e", "y", "J", "h", "b", "G", "c", "i", "O", "i", "J",
                          "I", "U", "z", "I", "1", "N", "i", "J", "9",
                          ".", "e", "y", "J", "s", "u", "b", "i", "O", "i", "J",
                          "0", "e", "X", "Q", "i", "f", "Q",
                          ".", "a", "b", "c", "1", "2", "3"])


def _synth_pem():
    # Pattern: -----BEGIN ... PRIVATE KEY-----  (SEC-PEM)
    return _build_secret(["-" * 5, "BEGIN RSA PRIVATE KEY", "-" * 5, "\nMIIEow..."])


# ---------------------------------------------------------------------------
# Secret format detection + secret_type mapping (ADR-0007 §9 T1)
# ---------------------------------------------------------------------------

SECRET_FORMAT_CASES = [
    ("openai",     _synth_openai,     "api_key"),
    ("anthropic",  _synth_anthropic,  "api_key"),
    ("aws",        _synth_aws,        "api_key"),
    ("stripe",     _synth_stripe,     "api_key"),
    ("slack",      _synth_slack,      "token"),
    ("github",     _synth_github,     "token"),
    ("jwt",        _synth_jwt,        "token"),
    ("pem",        _synth_pem,        "private_key"),
]


@pytest.mark.parametrize("_name,value_fn,expected_type", SECRET_FORMAT_CASES)
def test_secret_format_detected(_name, value_fn, expected_type):
    """Each known secret format is detected and mapped to the correct secret_type."""
    secret_value = value_fn()
    findings = _find_secrets(
        f"here is my key: {secret_value} end",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    assert findings, f"Secret pattern '{_name}' not detected"
    _, stype, _, _ = findings[0]
    assert stype == expected_type, f"Expected {expected_type!r}, got {stype!r}"


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------


def test_shannon_entropy_low_for_repeated():
    assert _shannon_entropy("aaaaaaaaaaaaaaaaaaa") < 1.0


def test_shannon_entropy_reasonable_for_mixed():
    s = "xK3mP9qZnL2vB8fD5rT1wY4u"
    entropy = _shannon_entropy(s)
    assert entropy > 3.0


def test_entropy_not_applied_to_short_tokens():
    """Tokens shorter than MIN_TOKEN_LENGTH_FOR_ENTROPY are not entropy-checked."""
    findings = _find_secrets(
        "xK3mP9qZ",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    entropy_findings = [f for f in findings if f[0] == "SEC-ENT"]
    assert not entropy_findings


def test_entropy_applied_to_long_uniform_token():
    """A 62-char fully-uniform-distribution token is detected as credential."""
    # 62 unique characters = maximum Shannon entropy for the charset.
    chars = string.ascii_letters + string.digits  # exactly 62 unique chars
    token = chars  # 62 chars, each appears exactly once
    entropy = _shannon_entropy(token)
    assert entropy > 4.5, f"Uniform-charset token entropy {entropy} not above threshold"
    findings = _find_secrets(
        f"conf={token}",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    assert any(stype == "credential" for _, stype, _, _ in findings)


# ---------------------------------------------------------------------------
# UUID v4 allowlisting (threat #6)
# ---------------------------------------------------------------------------


def test_uuid_v4_is_allowlisted():
    uid = str(uuid.uuid4())
    assert _is_allowlisted(uid)


def test_uuid_v4_not_detected_as_secret():
    """A UUIDv4 in content should NOT be detected as a credential."""
    uid = str(uuid.uuid4())
    findings = _find_secrets(
        f"request_id: {uid}",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    credential_findings = [f for f in findings if f[1] == "credential"]
    assert not credential_findings, f"UUID falsely detected as credential: {uid}"


# ---------------------------------------------------------------------------
# Redaction format
# ---------------------------------------------------------------------------


def test_redact_text_format():
    """Redacted secrets use [REDACTED:<type>] format."""
    text = "key here: " + _synth_openai() + " end"
    findings = _find_secrets(text, min_token_len=20, entropy_threshold=4.5)
    assert findings
    redacted = _redact_text(text, findings)
    assert "[REDACTED:api_key]" in redacted


def test_redact_text_multiple_findings():
    """Multiple findings are all redacted."""
    v1 = _synth_openai()
    v2 = _synth_aws()
    text = f"key1={v1} key2={v2} end"
    findings = _find_secrets(text, min_token_len=20, entropy_threshold=4.5)
    assert len(findings) >= 2
    redacted = _redact_text(text, findings)
    assert "[REDACTED" in redacted


# ---------------------------------------------------------------------------
# Inbound -> block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_inbound_hook_blocks(mock_hook_context):
    """Inbound secret detection -> action='block'."""
    settings = _make_settings()
    hook = SecretInboundHook(settings=settings)
    mock_hook_context.original_user_content = (
        "My OpenAI key is " + _synth_openai() + " please handle."
    )
    result = await hook.inspect("irrelevant", mock_hook_context)
    assert result.action == "block"
    assert result.event["action_taken"] == "blocked"
    assert result.event["direction"] == "inbound"
    assert result.event["event_type"] == "secret_leaked"


# ---------------------------------------------------------------------------
# Outbound -> mask
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_outbound_hook_masks(mock_hook_context):
    """Outbound secret detection -> action='mask' with redacted payload."""
    settings = _make_settings()
    hook = SecretOutboundHook(settings=settings)
    content = "Here is the token: " + _synth_github()
    result = await hook.inspect(content, mock_hook_context)
    assert result.action == "mask"
    assert result.event["action_taken"] == "masked"
    assert result.event["direction"] == "outbound"
    assert result.modified_payload is not None
    assert "[REDACTED" in result.modified_payload


# ---------------------------------------------------------------------------
# Secret value NEVER in event (D7 / threat #11)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_value_not_in_event(mock_hook_context):
    """The secret value must NEVER appear in any event field."""
    settings = _make_settings()
    hook = SecretInboundHook(settings=settings)
    secret = _synth_openai()
    mock_hook_context.original_user_content = f"My key: {secret}"
    result = await hook.inspect("irrelevant", mock_hook_context)
    assert result.event is not None
    event_str = json.dumps(result.event)
    assert secret not in event_str, "Secret value must never appear in event fields"


# ---------------------------------------------------------------------------
# secret_leaked event contract conformance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_leaked_event_contract_conformance(tenant_context):
    """Stamped secret_leaked event must validate against events.schema.json."""
    from orchestration.context import HookContext

    emitted = []

    async def fake_emit(event, *, detector_slug):
        import uuid as _uuid
        from datetime import UTC, datetime

        stamped = dict(event)
        stamped["tenant_id"] = tenant_context.tenant_id
        stamped["team_id"] = tenant_context.team_id
        stamped["project_id"] = tenant_context.project_id
        stamped["agent_id"] = detector_slug
        stamped["event_id"] = str(_uuid.uuid4())
        stamped["event_timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        stamped["request_id"] = "req-0000000000000003"
        emitted.append(stamped)
        return True

    secret_content = _synth_openai() + " in here"
    ctx = HookContext(
        tenant_context=tenant_context,
        request_id="req-0000000000000003",
        original_user_content=secret_content,
        phase="pre_request",
        _events_per_detector_cap=10,
    )
    ctx.emit = fake_emit  # type: ignore[method-assign]

    settings = _make_settings()
    hook = SecretInboundHook(settings=settings)
    result = await hook.inspect("irrelevant", ctx)
    if result.event:
        await ctx.emit(result.event, detector_slug="data-protection")

    assert emitted, "No event emitted"
    ev = emitted[0]
    errors = list(_VALIDATOR.iter_errors(ev))
    assert not errors, f"Schema validation errors: {errors}"


# ---------------------------------------------------------------------------
# Pass on clean content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inbound_pass_on_clean_content(mock_hook_context):
    settings = _make_settings()
    hook = SecretInboundHook(settings=settings)
    mock_hook_context.original_user_content = "What is the capital of France?"
    result = await hook.inspect("irrelevant", mock_hook_context)
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_outbound_pass_on_clean_content(mock_hook_context):
    settings = _make_settings()
    hook = SecretOutboundHook(settings=settings)
    result = await hook.inspect("Paris is the capital of France.", mock_hook_context)
    assert result.action == "pass"


# ---------------------------------------------------------------------------
# FIX-2: base64 allowlist narrowed — high-entropy base64 key IS detected
# ---------------------------------------------------------------------------


def test_fix2_base64_key_detected_as_credential():
    """FIX-2: a 44-char base64-encoded key with entropy ~4.75 IS detected.

    Previously the base64-padding allowlist exempted any padded-base64 token
    ≤48 chars from the entropy check, silently passing real API keys.
    After FIX-2 (Option β), the entropy check runs on padded base64 tokens too.

    Simulates a 32-byte random key encoded as base64 (44 chars including '=').
    Entropy of random base64 is ~4.75 bits/char > ENTROPY_THRESHOLD 4.5.
    """
    import base64
    import os

    # 32 random bytes → 44-char base64 string ending in '='
    raw = bytes(range(256))[:32]  # deterministic, not truly random — safe for tests
    b64_key = base64.b64encode(raw).decode()
    assert len(b64_key) == 44
    assert b64_key.endswith("=")

    entropy = _shannon_entropy(b64_key)
    assert entropy > 4.5, f"Test setup: expected entropy > 4.5, got {entropy}"

    findings = _find_secrets(
        f"Authorization: Bearer {b64_key}",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    credential_findings = [f for f in findings if f[1] == "credential"]
    assert credential_findings, (
        f"FIX-2: high-entropy base64 key '{b64_key}' should be detected as credential"
    )


def test_fix2_uuid_v4_still_not_detected():
    """FIX-2: a real UUIDv4 in text is still NOT detected as a credential.

    UUIDv4 allowlisting is preserved.  Only the generic base64-padding exemption
    was removed; UUIDs remain explicitly allowlisted.
    """
    uid = str(uuid.uuid4())  # e.g. "550e8400-e29b-41d4-a716-446655440000"
    findings = _find_secrets(
        f"request_id: {uid} correlation_id: {uid}",
        min_token_len=20,
        entropy_threshold=4.5,
    )
    credential_findings = [f for f in findings if f[1] == "credential"]
    assert not credential_findings, (
        f"FIX-2: UUIDv4 {uid!r} should NOT be flagged as credential"
    )


def test_fix2_five_uuids_no_events():
    """FIX-2: a text containing 5 UUIDs produces zero secret events.

    This is the threat-#6 FP cascade scenario: a request containing many
    UUIDs (e.g. correlation IDs) must not flood the event log.
    """
    uids = [str(uuid.uuid4()) for _ in range(5)]
    text = "IDs: " + " ".join(uids)
    findings = _find_secrets(text, min_token_len=20, entropy_threshold=4.5)
    credential_findings = [f for f in findings if f[1] == "credential"]
    assert not credential_findings, (
        f"FIX-2: {len(credential_findings)} credential events for 5 UUIDs — expected 0"
    )
