"""Self-hosted content detectors (R-008) — PII / injection / secret, regex + entropy only.

Each ``detect_*`` function takes the raw message content and returns a bare ``bool`` (a
category-level block/pass verdict) — NEVER the matched substring, NEVER the offending content,
matching the contract's ``InspectionResult.detectors`` "metadata only" guarantee at the source
(there is nothing here to leak upward even by accident).

DATA SOVEREIGNTY (verbatim honesty boundary): every detector below is a pure, in-process
function — regex + arithmetic only. NOTHING here makes a network call, calls out to Sentinel,
or calls a third-party DLP/classification API. Message content never leaves this process for
inspection, which is the R-008 "absolute data sovereignty" requirement at the detector layer.

HONESTY BOUNDARY (verbatim): these are BOUNDED HEURISTIC detectors (regex pattern lists +
Shannon-entropy scoring for the secret category), mirroring Sentinel F-005's own regex-rule
posture — NOT Presidio-grade PII NER and NOT an ML injection classifier. "High-coverage
detection", not "100% detection" (root CLAUDE.md honest-language convention). False negatives
on novel phrasing/formats are expected; the fail-closed pipeline this seam runs in (R-005 FORK D)
means a detector that misses something bad passes it, but a detector that raises or times out is
still converted to a fail-closed BLOCK by the caller (``sentinel_inspector.py`` / ``pipeline.py``),
never a silent pass.
"""

from __future__ import annotations

import math
import re

# --- PII --------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_pii(content: str) -> bool:
    """Email, phone number, SSN, or a Luhn-valid card-shaped digit run."""
    if _EMAIL_RE.search(content):
        return True
    if _PHONE_RE.search(content):
        return True
    if _SSN_RE.search(content):
        return True
    for match in _CARD_CANDIDATE_RE.finditer(content):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


# --- injection ----------------------------------------------------------------------------

# Bounded phrase list — instruction-override / jailbreak framing aimed at an AI system prompt.
# Case-insensitive; each is a plain substring/phrase check compiled once.
_INJECTION_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (?:all )?(?:previous|prior|the above) instructions",
        r"disregard (?:all )?(?:previous|prior|the above)(?: instructions)?",
        r"you are now (?:in )?(?:a|an)? ?(?:unrestricted|jailbroken|dan)",
        r"act as if you (?:have no|had no|are not) (?:restrictions|rules|guidelines)",
        r"reveal your (?:system prompt|system instructions|instructions)",
        r"bypass (?:your |all )?(?:restrictions|safety|filters|guardrails)",
        r"\bjailbreak\b",
        r"\bdeveloper mode\b",
        r"do anything now",
        r"pretend (?:you have|to have) no (?:restrictions|content policy)",
    )
)


def detect_injection(content: str) -> bool:
    """Any bounded instruction-override / jailbreak phrase (regex rule list, no ML escalation)."""
    return any(pattern.search(content) for pattern in _INJECTION_PATTERNS)


# --- secret -------------------------------------------------------------------------------

_SECRET_PATTERNS = tuple(
    re.compile(p)
    for p in (
        r"AKIA[0-9A-Z]{16}",  # AWS access key id
        r"ASIA[0-9A-Z]{16}",  # AWS STS temporary access key id
        r"-----BEGIN(?: RSA| EC| OPENSSH| DSA)? PRIVATE KEY-----",
        r"xox[baprs]-[0-9A-Za-z-]{10,}",  # Slack token
        r"gh[pousr]_[A-Za-z0-9]{36,}",  # GitHub token
        r"sk-[A-Za-z0-9]{20,}",  # generic "sk-" secret-key-shaped token
        r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+]{16,}['\"]?",
    )
)

# Shannon-entropy fallback for an unlabeled high-entropy token (generic secret material with no
# recognizable prefix). Only long, charset-diverse "words" are scored — short/common words never
# reach the length floor, keeping the false-positive rate low.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
_ENTROPY_BITS_THRESHOLD = 4.0


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def detect_secret(content: str) -> bool:
    """A labeled secret pattern, or an unlabeled high-entropy token (Shannon entropy fallback)."""
    if any(pattern.search(content) for pattern in _SECRET_PATTERNS):
        return True
    for token in _TOKEN_RE.findall(content):
        if _shannon_entropy(token) >= _ENTROPY_BITS_THRESHOLD:
            return True
    return False
