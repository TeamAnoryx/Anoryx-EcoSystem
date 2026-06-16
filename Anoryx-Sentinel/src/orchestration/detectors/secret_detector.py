"""Secret detector — regex + Shannon-entropy backend (F-005, ADR-0007 §9, D2, T1, T2).

Detected formats and secret_type mapping (ADR-0007 §9 / Decision T1):
  1. OpenAI sk-...                        → api_key
  2. Anthropic sk-ant-api03-...           → api_key
  3. AWS AKIA...                          → api_key
  4. Stripe sk_live_... / pk_live_...     → api_key
  5. Slack xoxb-... / xoxp-...            → token
  6. GitHub ghp_ / gho_ / ghs_            → token
  7. JWT eyJ... (3 dot-separated b64 seg) → token
  8. SSH/PEM BEGIN ... PRIVATE KEY        → private_key
  9. Generic high-entropy string          → credential

Inbound (request) direction: SECRET → BLOCK (raises HookBlockedError via registry).
Outbound (response) direction: SECRET → MASK ([REDACTED:<type>] substitution).

Shannon-entropy filtering (threat #6 — UUID FP mitigation)
----------------------------------------------------------
Before the entropy check we allowlist:
  - UUIDv4 (canonical xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
  (FIX-2: base64-padding exemption REMOVED — see _is_allowlisted docstring.)
Only tokens > MIN_TOKEN_LENGTH_FOR_ENTROPY are evaluated.
Entropy threshold: ENTROPY_THRESHOLD (default 4.5 bits/char).

Threat #5 (secret line-split / comment bypass)
----------------------------------------------
Inbound: scans the JOINED user content (context.original_user_content from
HookContext), so a secret split across messages or lines in a single block is
scanned as a continuous string.
Outbound: the bounded sliding-window in the gateway integration carries
up to STREAM_INSPECT_BUFFER_BYTES of the previous chunk's tail, so secrets
straddling chunk boundaries are detected.  Deeply interleaved multi-line
splits (e.g. alternate characters across lines) may evade — noted limitation.

Secret value is NEVER logged or emitted (ADR-0007 D7 / threat #11).
The event only carries secret_type (4-value enum), direction, and action_taken.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

import structlog

from orchestration.hooks.base import DetectorResult, PostResponseHook, PreRequestHook

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# UUID v4 pattern for allowlisting (threat #6)
# ---------------------------------------------------------------------------
_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# FIX-2 (Option β): The base64-padding allowlist is REMOVED.
# Rationale: any token ending in '=' that is ≤48 chars was previously exempted
# from the entropy check, which silently passed real base64-encoded API keys
# (e.g. 44-char base64url keys with entropy ~4.75 > ENTROPY_THRESHOLD 4.5).
# Only UUIDv4 canonical form remains allowlisted — it has a well-defined,
# low-entropy structure (hex digits + dashes) and is the primary FP source.
# Generic base64 tokens are now entropy-checked regardless of padding shape.
# See ADR-0007 §14 FIX-2 note.


@dataclass(frozen=True)
class SecretPattern:
    """A single secret detection pattern.

    pattern_id: stable ID used in log messages (never the secret value).
    pattern:    compiled regex.
    secret_type: one of the 4 ADR-0007 T1 enum values.
    """

    pattern_id: str
    pattern: re.Pattern[str]
    secret_type: str  # api_key | token | private_key | credential


def _pat(pid: str, regex: str, stype: str) -> SecretPattern:
    return SecretPattern(
        pattern_id=pid,
        pattern=re.compile(regex),
        secret_type=stype,
    )


# ---------------------------------------------------------------------------
# Pattern catalog — ordered: more-specific patterns first to avoid overlap.
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[SecretPattern] = [
    # 2. Anthropic (before generic sk- so it matches the longer prefix)
    _pat(
        "SEC-ANT",
        r"sk-ant-api03-[A-Za-z0-9_\-]{20,}",
        "api_key",
    ),
    # 1. OpenAI
    _pat(
        "SEC-OAI",
        r"sk-[A-Za-z0-9]{20,}",
        "api_key",
    ),
    # 3. AWS access key
    _pat(
        "SEC-AWS",
        r"AKIA[0-9A-Z]{16}",
        "api_key",
    ),
    # 4. Stripe live keys
    _pat(
        "SEC-STR",
        r"(?:sk|pk)_live_[A-Za-z0-9]{16,}",
        "api_key",
    ),
    # 5. Slack tokens
    _pat(
        "SEC-SLK",
        r"xox[bp]-[A-Za-z0-9\-]{10,}",
        "token",
    ),
    # 6. GitHub tokens
    _pat(
        "SEC-GH",
        r"gh[pos]_[A-Za-z0-9]{36,}",
        "token",
    ),
    # 7. JWT (three base64url segments separated by dots)
    _pat(
        "SEC-JWT",
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "token",
    ),
    # 8. SSH / PEM private key block
    _pat(
        "SEC-PEM",
        r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----",
        "private_key",
    ),
]

# Redact template for outbound masking (Decision T2: redact → action_taken "masked").
_REDACT_TEMPLATE = "[REDACTED:{secret_type}]"


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_allowlisted(token: str) -> bool:
    """Return True if the token is a known low-entropy false-positive class.

    Allowlist (threat #6 / FIX-2):
      - UUIDv4 canonical form (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx) only.

    The base64-padding exemption was removed (FIX-2, Option β): padded base64
    tokens are now entropy-checked regardless of shape so that real base64-
    encoded API keys (≥4.5 bits/char) are not silently passed.
    """
    if _UUID_V4_RE.match(token):
        return True
    return False


def _find_secrets(
    text: str,
    *,
    min_token_len: int,
    entropy_threshold: float,
) -> list[tuple[str, str, int, int]]:
    """Return list of (pattern_id, secret_type, start, end) tuples for each match.

    Checks named patterns first, then performs entropy scan on whitespace-
    delimited tokens that are long enough and not allowlisted.

    The secret VALUE is never included in the returned data.
    """
    findings: list[tuple[str, str, int, int]] = []
    matched_spans: list[tuple[int, int]] = []

    for pat in SECRET_PATTERNS:
        for m in pat.pattern.finditer(text):
            findings.append((pat.pattern_id, pat.secret_type, m.start(), m.end()))
            matched_spans.append((m.start(), m.end()))

    # Entropy scan on whitespace-delimited tokens not already matched.
    # Defense-in-depth: strip leading/trailing JSON structural characters from
    # each candidate token so the replacement never consumes structural chars
    # like `"`, `}`, `]`, `,`, `\`, or newlines that appear adjacent to a
    # secret in a compact JSON string.  We adjust the matched span start/end
    # accordingly so _redact_text only replaces the secret characters.
    _STRUCTURAL = '"}],' + "\\\n\r"
    for m in re.finditer(r"\S+", text):
        raw_token = m.group()
        raw_start = m.start()

        # Strip leading structural chars and advance start offset.
        lstripped = raw_token.lstrip(_STRUCTURAL)
        leading_stripped = len(raw_token) - len(lstripped)
        tstart = raw_start + leading_stripped

        # Strip trailing structural chars and retreat end offset.
        rstripped = lstripped.rstrip(_STRUCTURAL)
        token = rstripped
        tend = tstart + len(token)

        if len(token) < min_token_len:
            continue
        # Skip if overlapping with any named pattern match (overlap = not disjoint).
        # Containment-only check allowed a named match sitting inside a larger
        # whitespace token to leave the outer token un-suppressed, causing
        # SEC-ENT to over-redact/mis-label the wider span.  The overlap check
        # (not disjoint) correctly defers to named patterns in all such cases.
        if any(not (tend <= s or tstart >= e) for s, e in matched_spans):
            continue
        if _is_allowlisted(token):
            continue
        entropy = _shannon_entropy(token)
        if entropy >= entropy_threshold:
            findings.append(("SEC-ENT", "credential", tstart, tend))
            matched_spans.append((tstart, tend))

    return findings


def _redact_text(text: str, findings: list[tuple[str, str, int, int]]) -> str:
    """Replace each finding span with [REDACTED:<secret_type>].

    Applied in reverse span order to preserve offsets of earlier findings.
    Secret values are NEVER logged — the function only replaces byte positions.
    """
    # Sort by start descending.
    sorted_findings = sorted(findings, key=lambda f: f[2], reverse=True)
    chars = list(text)
    for _pid, stype, start, end in sorted_findings:
        replacement = list(_REDACT_TEMPLATE.format(secret_type=stype))
        chars[start:end] = replacement
    return "".join(chars)


def redact(
    text: str,
    *,
    min_token_len: int,
    entropy_threshold: float,
) -> str:
    """Return a copy of *text* with detected secrets replaced by [REDACTED:<type>].

    This is the canonical, pure redaction function shared by SecretOutboundHook
    and _redact_in_place (CHANGE 1).  It is idempotent: re-running on already-
    redacted text (which contains '[REDACTED:...]' markers) yields identical
    output because the markers do not match any detection pattern.

    The secret VALUE is never logged or emitted from this function.
    """
    findings = _find_secrets(
        text,
        min_token_len=min_token_len,
        entropy_threshold=entropy_threshold,
    )
    if not findings:
        return text
    return _redact_text(text, findings)


class SecretInboundHook(PreRequestHook):
    """Pre-request (inbound) secret detection.

    Scans context.original_user_content (joined pre-mask user messages).
    On any finding → BLOCK (action_taken="blocked", HTTP 403).
    """

    detector_slug = "data-protection"

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Scan inbound user content for secrets.  Returns "block" or "pass"."""
        # Scan the pre-mask snapshot (threat #5 line-split: joined content).
        scan_text = getattr(context, "original_user_content", content)

        if not scan_text:
            return DetectorResult(action="pass")

        findings = _find_secrets(
            scan_text,
            min_token_len=self._settings.min_token_length_for_entropy,
            entropy_threshold=self._settings.entropy_threshold,
        )

        if not findings:
            return DetectorResult(action="pass")

        # Use the first finding for the event (one event per call; cap enforced
        # at registry level across multiple calls).
        _pid, stype, _s, _e = findings[0]

        event = {
            "event_type": "secret_leaked",
            "secret_type": stype,
            "direction": "inbound",
            "action_taken": "blocked",
            # Secret value NEVER included (D7 / threat #11).
        }

        return DetectorResult(action="block", event=event)


class SecretOutboundHook(PostResponseHook):
    """Post-response (outbound) secret detection.

    Scans response content (full for non-stream; windowed for stream via the
    gateway integration).

    Phase-aware action (ADR-0007 §5 / FIX-1):
      - stream (phase="post_response" called from sliding-window loop): BLOCK
        the stream so no raw secret reaches the client.  The gateway's
        except (HookBlockedError, HookFailSafeError) block emits the SSE
        error frame and closes the stream.  action_taken="blocked".
      - non-stream (phase="post_response" called once on full response): MASK
        the content so the client receives the redacted body.
        action_taken="masked".

    The phase is read from context.phase; the gateway sets "post_response" for
    both paths.  To distinguish stream vs non-stream within post_response the
    gateway passes an additional attribute: context._is_stream (bool).  If that
    attribute is absent the hook defaults to mask (non-stream safe default).
    """

    detector_slug = "data-protection"

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Scan outbound response content for secrets.  Returns "block", "mask", or "pass".

        Returns "block" when the context indicates a streaming phase so the
        gateway stops the stream immediately (no raw secret emitted).
        Returns "mask" for non-stream so the client gets the redacted body.
        """
        if not content:
            return DetectorResult(action="pass")

        findings = _find_secrets(
            content,
            min_token_len=self._settings.min_token_length_for_entropy,
            entropy_threshold=self._settings.entropy_threshold,
        )

        if not findings:
            return DetectorResult(action="pass")

        _pid, stype, _s, _e = findings[0]

        # Determine whether this call is in a streaming context.  The gateway
        # sets _is_stream=True on the post_hook_ctx it builds for the stream
        # path.  Absence of the attribute or any non-True value means non-stream
        # (safe default: mask).  We use `is True` (strict identity) to guard
        # against MagicMock objects (used in tests) that return truthy proxies
        # for any attribute access.
        is_stream = getattr(context, "_is_stream", False) is True

        if is_stream:
            # Streaming: BLOCK immediately — no raw secret must be yielded.
            event = {
                "event_type": "secret_leaked",
                "secret_type": stype,
                "direction": "outbound",
                "action_taken": "blocked",
            }
            return DetectorResult(action="block", event=event)
        else:
            # Non-stream: MASK — client receives the redacted body.
            # defer_emit=True: the registry must NOT emit this event immediately.
            # The gateway handler emits it only AFTER json.loads confirms the
            # redacted body is still valid JSON.  If validation fails, the handler
            # raises internal_error and emits NO secret_leaked event (HIGH-B).
            event = {
                "event_type": "secret_leaked",
                "secret_type": stype,
                "direction": "outbound",
                "action_taken": "masked",
            }
            redacted = redact(
                content,
                min_token_len=self._settings.min_token_length_for_entropy,
                entropy_threshold=self._settings.entropy_threshold,
            )
            return DetectorResult(
                action="mask",
                event=event,
                modified_payload=redacted,
                defer_emit=True,
            )
