"""Unit tests for the HMAC-SHA256 signer (F-020, ADR-0023 §5.5).

Security-critical: covers vectors 10 (timestamp inside signed payload) and
11 (replay outside tolerance window detectable) from ADR-0023 §6.

Tests are purely in-memory — no network, no DB, no Redis.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from orchestration.webhooks.signer import (
    WEBHOOK_SIGNATURE_TOLERANCE_SECONDS,
    SignedHeaders,
    should_sign,
    sign_body,
    verify_within_tolerance,
)

_TEST_SECRET = b"test-signing-secret-32-bytes-long!"


# ---------------------------------------------------------------------------
# should_sign — provider dispatch
# ---------------------------------------------------------------------------


class TestShouldSign:
    """Only generic/Splunk deliveries are HMAC-signed; Slack/Jira use native auth."""

    def test_slack_not_signed(self):
        assert should_sign("slack") is False

    def test_jira_not_signed(self):
        assert should_sign("jira") is False

    def test_splunk_signed(self):
        assert should_sign("splunk") is True

    def test_case_insensitive(self):
        assert should_sign("SLACK") is False
        assert should_sign("SPLUNK") is True


# ---------------------------------------------------------------------------
# sign_body — vector 10: timestamp INSIDE the signed payload
# ---------------------------------------------------------------------------


class TestSignBody:
    """Vector 10: HMAC signs f'{ts}.{body}'; timestamp is the first signed element."""

    def test_sign_returns_signed_headers(self):
        headers = sign_body(_TEST_SECRET, '{"event_type":"pii_blocked"}')
        assert isinstance(headers, SignedHeaders)
        assert headers.x_sentinel_timestamp
        assert headers.x_sentinel_signature.startswith("sha256=")

    def test_timestamp_in_body_makes_signature(self):
        """Recompute the HMAC from scratch and verify it matches."""
        body = '{"event_type":"pii_blocked","severity":"high"}'
        headers = sign_body(_TEST_SECRET, body)
        ts = headers.x_sentinel_timestamp

        # Recompute exactly as the signer does.
        signed_payload = f"{ts}.{body}".encode("utf-8")
        expected_digest = hmac.new(_TEST_SECRET, signed_payload, hashlib.sha256).hexdigest()
        expected_sig = f"sha256={expected_digest}"

        assert headers.x_sentinel_signature == expected_sig

    def test_different_body_different_signature(self):
        body1 = '{"event_type":"pii_blocked"}'
        body2 = '{"event_type":"injection_detected"}'
        h1 = sign_body(_TEST_SECRET, body1)
        h2 = sign_body(_TEST_SECRET, body2)
        # Signatures MUST differ (different body → different MAC).
        assert h1.x_sentinel_signature != h2.x_sentinel_signature

    def test_different_secret_different_signature(self):
        body = '{"event_type":"pii_blocked"}'
        h1 = sign_body(b"secret-key-a", body)
        h2 = sign_body(b"secret-key-b", body)
        assert h1.x_sentinel_signature != h2.x_sentinel_signature

    def test_signature_format_sha256_prefix(self):
        headers = sign_body(_TEST_SECRET, '{"test":"body"}')
        # Must begin with "sha256=" (Slack-style format).
        assert headers.x_sentinel_signature.startswith("sha256=")
        # After the prefix: 64 hex chars (SHA-256 digest).
        hex_part = headers.x_sentinel_signature[len("sha256=") :]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_timestamp_is_unix_integer_string(self):
        before = int(time.time()) - 2
        headers = sign_body(_TEST_SECRET, '{"test":"body"}')
        after = int(time.time()) + 2
        ts = int(headers.x_sentinel_timestamp)
        assert before <= ts <= after

    def test_strip_timestamp_header_breaks_replay(self):
        """If a receiver ignores X-Sentinel-Timestamp, replay is detectable via body."""
        body = '{"event_type":"pii_blocked"}'
        headers = sign_body(_TEST_SECRET, body)
        # An attacker strips the timestamp HEADER and tries to replay just the body.
        # The signature covers f"{ts}.{body}" not just body, so verifying
        # HMAC(secret, body) against headers.x_sentinel_signature MUST fail.
        attacker_payload = body.encode("utf-8")
        expected_without_ts = hmac.new(_TEST_SECRET, attacker_payload, hashlib.sha256).hexdigest()
        actual_sig_hex = headers.x_sentinel_signature[len("sha256=") :]
        # They MUST differ — proof that timestamp is inside the signed payload.
        assert actual_sig_hex != expected_without_ts


# ---------------------------------------------------------------------------
# verify_within_tolerance — vector 11: replay outside window rejected
# ---------------------------------------------------------------------------


class TestVerifyWithinTolerance:
    """Vector 11: timestamp outside tolerance window is detectable."""

    def test_current_timestamp_accepted(self):
        ts = str(int(time.time()))
        assert verify_within_tolerance(ts) is True

    def test_timestamp_at_boundary_accepted(self):
        # One second inside tolerance — should be accepted (abs <= tolerance).
        # We use TOLERANCE-1 to avoid a sub-second race where int(time.time())
        # advances between the ts calculation and the verify call.
        ts = str(int(time.time()) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS + 1)
        assert verify_within_tolerance(ts) is True

    def test_timestamp_just_outside_boundary_rejected(self):
        ts = str(int(time.time()) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS - 1)
        assert verify_within_tolerance(ts) is False

    def test_future_timestamp_far_rejected(self):
        ts = str(int(time.time()) + WEBHOOK_SIGNATURE_TOLERANCE_SECONDS + 60)
        assert verify_within_tolerance(ts) is False

    def test_old_replay_rejected(self):
        # 10 minutes in the past — well outside the 5-minute window.
        ts = str(int(time.time()) - 600)
        assert verify_within_tolerance(ts) is False

    def test_injected_now_controls_window(self):
        """Test-injection seam: _now lets tests freeze time."""
        frozen_now = 1_700_000_000.0
        ts_fresh = str(int(frozen_now))
        assert verify_within_tolerance(ts_fresh, _now=frozen_now) is True

        ts_stale = str(int(frozen_now) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS - 1)
        assert verify_within_tolerance(ts_stale, _now=frozen_now) is False

    def test_non_integer_timestamp_rejected(self):
        assert verify_within_tolerance("not_a_timestamp") is False

    def test_empty_timestamp_rejected(self):
        assert verify_within_tolerance("") is False

    def test_tolerance_constant_is_300(self):
        assert WEBHOOK_SIGNATURE_TOLERANCE_SECONDS == 300


# ---------------------------------------------------------------------------
# Stream payload contains no request/response/PII content
# (ADR-0023 D1 / Affu Hard Requirement 1 — structural test on adapters)
# ---------------------------------------------------------------------------


class TestForAOneNoPayloadEgress:
    """Structural assertion: the metadata projection used in XADD / adapters
    contains zero request/response/payload content.

    This test mirrors ADR-0023 §6 vector 13 (test_no_payload_egress) and is
    placed here because the adapters enforce this by construction via
    _ALLOWED_ENVELOPE_KEYS.
    """

    def test_adapter_slack_strips_non_metadata(self):
        from orchestration.webhooks.adapters import build_slack_body

        envelope_with_payload = {
            "event_type": "pii_blocked",
            "severity": "high",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "team_id": "00000000-0000-0000-0000-000000000002",
            "project_id": "00000000-0000-0000-0000-000000000003",
            "agent_id": "data-protection",
            "event_id": "00000000-0000-0000-0000-000000000004",
            "event_timestamp": "2026-06-24T00:00:00Z",
            "request_id": "req-abc123",
            "action_taken": "masked",
            "violation_type": "",
            "webhook_provider": "",
            # Payload/PII fields that MUST NOT appear in the body:
            "original_user_content": "My SSN is 123-45-6789",
            "response_body": '{"choices":[{"message":{"content":"secret data"}}]}',
            "sample_excerpt_redacted": "[REDACTED]",
        }
        body_str = build_slack_body(envelope_with_payload)
        # No payload content must appear in the serialized body.
        assert "123-45-6789" not in body_str
        assert "secret data" not in body_str
        assert "original_user_content" not in body_str
        assert "response_body" not in body_str

    def test_adapter_splunk_strips_non_metadata(self):
        from orchestration.webhooks.adapters import build_splunk_body

        envelope_with_payload = {
            "event_type": "injection_detected",
            "severity": "critical",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "team_id": "00000000-0000-0000-0000-000000000002",
            "project_id": "00000000-0000-0000-0000-000000000003",
            "agent_id": "defense",
            "event_id": "00000000-0000-0000-0000-000000000004",
            "event_timestamp": "2026-06-24T00:00:00Z",
            "request_id": "req-def456",
            "action_taken": "blocked",
            "violation_type": "",
            "webhook_provider": "",
            # Payload fields:
            "prompt_text": "IGNORE PREVIOUS INSTRUCTIONS",
            "raw_response": "leaked data",
        }
        body_str = build_splunk_body(envelope_with_payload)
        assert "IGNORE PREVIOUS INSTRUCTIONS" not in body_str
        assert "leaked data" not in body_str
        assert "prompt_text" not in body_str
        assert "raw_response" not in body_str
