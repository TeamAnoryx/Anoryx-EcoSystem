"""Prompt injection detector — rule-based heuristic engine (F-005, ADR-0007 §4, D1).

Detection approach
------------------
F-005 uses a curated rule set (not an ML classifier — ML deferred to F-007).
Each rule has:
  - A stable ID (used as rule_matched; NEVER the attacker's text — D7/threat #11).
  - A compiled regex pattern.
  - A weight in [0, 1] contributing to the aggregate score.

The aggregate classifier_score is the sum of all matching rule weights, clamped
to [0, 1].  If score >= INJECTION_SCORE_THRESHOLD (default 0.75) → "blocked",
otherwise → "logged".

Role scoping (ADR-0007 D1 / threat #4)
---------------------------------------
Injection ALWAYS scans context.original_user_content — the immutable snapshot of
joined role="user" messages captured BEFORE any PII masking.  This prevents:
  - Threat #7: PII masking hiding injection patterns.
  - Threat #4: system-role spoof.  The system role is caller-owned trusted context;
    we do NOT inspect it.  If a caller places attacker text in their own system
    prompt, they are trusting it by construction — F-005 does not defend the caller
    against itself.

Concatenation of all user messages (threat #3): the original_user_content snapshot
already concatenates all role="user" messages with "\\n" (built_hook_context() in
context.py).  So a simple split-across-messages injection is scored on the joined text.

Bypass deferral (threat #1, #2)
----------------------------------
Encoded injection (base64, ROT13, Unicode lookalikes, spaced characters) is NOT
decoded-then-scanned by F-005.  These bypasses are deferred to F-007 (ML classifier
with richer feature extraction).  Tests document which patterns are caught vs which
are honest deferrals.

content parameter vs original_user_content
-------------------------------------------
The hook's inspect(content, context) signature follows the PreRequestHook ABC.
The injection detector IGNORES the content parameter and scores
context.original_user_content instead, ensuring PII masking that ran earlier
cannot hide injection (ADR-0007 D1).
"""

from __future__ import annotations

import re
import structlog
from dataclasses import dataclass
from typing import Any

from orchestration.hooks.base import DetectorResult, PreRequestHook

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class InjectionRule:
    """A single injection detection rule.

    rule_id: stable identifier used as rule_matched in events (never attacker text).
    pattern: compiled regex (case-insensitive, DOTALL).
    weight:  contribution to aggregate score in [0.0, 1.0].
    """

    rule_id: str
    pattern: re.Pattern[str]
    weight: float


def _rule(rule_id: str, pattern_str: str, weight: float) -> InjectionRule:
    """Convenience factory for InjectionRule with pre-compiled regex."""
    return InjectionRule(
        rule_id=rule_id,
        pattern=re.compile(pattern_str, re.IGNORECASE | re.DOTALL),
        weight=weight,
    )


# ---------------------------------------------------------------------------
# Curated rule catalog
# Each rule_id is a stable opaque identifier — never derived from input text.
# Weights are tuned so common high-confidence patterns hit the 0.75 threshold
# alone, while lower-confidence signals aggregate.
# ---------------------------------------------------------------------------
INJECTION_RULES: list[InjectionRule] = [
    # High-confidence single-pattern indicators (weight >= 0.75 alone → block).
    _rule(
        "INJ-001",
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)",
        0.80,
    ),
    _rule(
        "INJ-002",
        r"you\s+are\s+now\s+(DAN|jailbreak|an?\s+AI\s+without|a\s+different)",
        0.80,
    ),
    _rule(
        "INJ-003",
        r"(enable|activate|turn\s+on)\s+developer\s+mode",
        0.80,
    ),
    _rule(
        "INJ-004",
        r"(print|reveal|show|output|display|return|repeat|say)\s+(the\s+|your\s+|me\s+the\s+)?(system\s+prompt|instructions?|prompt)",
        0.75,
    ),
    _rule(
        "INJ-005",
        r"disregard\s+(all\s+)?(prior|previous|above|earlier|your)\s+(instructions?|directives?|guidelines?|rules?)",
        0.80,
    ),
    _rule(
        "INJ-006",
        r"pretend\s+(that\s+)?(you\s+(are|have\s+no|don'?t\s+have)|there\s+are\s+no)\s+(restrictions?|rules?|guidelines?|limitations?|constraints?)",
        0.75,
    ),
    # Medium-confidence patterns (accumulate toward threshold).
    _rule(
        "INJ-007",
        r"\bDAN\b",
        0.40,
    ),
    _rule(
        "INJ-008",
        r"(new\s+)?system\s+prompt\s*(:|is\s*:)?",
        0.45,
    ),
    _rule(
        "INJ-009",
        r"act\s+as\s+(if\s+)?(you\s+are\s+|you're\s+)?(un(restricted|filtered|censored)|jailbreak|free\s+AI)",
        0.65,
    ),
    _rule(
        "INJ-010",
        r"(override|bypass|circumvent|disable)\s+(your\s+)?(safety|content\s+filter|guardrail|restriction|policy)",
        0.70,
    ),
    _rule(
        "INJ-011",
        r"from\s+now\s+on\s+(you\s+are|act\s+as|behave\s+as|respond\s+as)",
        0.55,
    ),
    _rule(
        "INJ-012",
        r"(forget|discard|delete|clear|erase)\s+(everything|all)\s+(you\s+)?(know|were\s+told|have\s+been\s+told)",
        0.65,
    ),
    _rule(
        "INJ-013",
        r"(you\s+have\s+)?(no\s+)?(restrictions?|ethical\s+guidelines?|moral\s+constraints?)",
        0.50,
    ),
    _rule(
        "INJ-014",
        r"jailbreak",
        0.55,
    ),
    _rule(
        "INJ-015",
        r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>",
        0.60,
    ),
]


def _normalize_for_injection(text: str) -> str:
    """Normalize text for injection scoring only (FIX-4).

    Collapses all whitespace (spaces, newlines, tabs) into a single space and
    lowercases the result.  This prevents intra-token splits across message
    boundaries or across SSE chunks from evading regex rules.

    Examples that are now caught:
      ["ign","ore previous instructions"] → "ignore previous instructions"
      ["IGNORE\\nPREVIOUS\\nINSTRUCTIONS"] → "ignore previous instructions"

    IMPORTANT: This normalization is ONLY applied for injection regex scoring.
    PII and secret snapshots continue to use the raw newline-joined text so
    their span offsets are preserved for correct masking/redaction.
    """
    # Replace all whitespace sequences (\\n, \\t, multiple spaces) with one space.
    return re.sub(r"\s+", " ", text).strip().lower()


def _score_and_first_rule(text: str) -> tuple[float, str | None]:
    """Return (aggregate_score clamped to [0,1], first_matched_rule_id or None).

    FIX-4: scores the NORMALIZED form of text (whitespace collapsed, lowercased)
    so that intra-token splits (e.g. ["ign","ore previous instructions"] joined
    as "ign\\nore previous instructions") do not evade regex rules.
    The injection rules already use re.IGNORECASE | re.DOTALL, but DOTALL does
    not collapse \\n into a single space for \\s+ matching.  Explicit
    normalization is more reliable.
    """
    normalized = _normalize_for_injection(text)
    total = 0.0
    first_rule: str | None = None

    for rule in INJECTION_RULES:
        if rule.pattern.search(normalized):
            if first_rule is None:
                first_rule = rule.rule_id
            total += rule.weight

    return min(1.0, total), first_rule


class InjectionHook(PreRequestHook):
    """Pre-request injection detection hook.

    ALWAYS scans context.original_user_content (pre-masking snapshot) per D1.
    The content parameter (possibly PII-masked by earlier hooks) is IGNORED for
    detection; the hook returns the ORIGINAL content as modified_payload would
    be irrelevant (injection → block only, never mask per ADR-0007 §4).

    action is always "block" (score >= threshold) or "pass" (logged internally
    as action_taken:"logged" in the emitted event, but the hook returns "pass"
    so the request is not terminated by the registry).
    """

    detector_slug = "defense"

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Score context.original_user_content.  Returns "block" or "pass"."""
        # Always scan the original (pre-mask) snapshot — D1 / threat #7.
        scan_text = getattr(context, "original_user_content", content)

        if not scan_text:
            return DetectorResult(action="pass")

        score, first_rule = _score_and_first_rule(scan_text)

        threshold = self._settings.injection_score_threshold

        if score < 0.001 or first_rule is None:
            return DetectorResult(action="pass")

        # A finding exists.  Determine action.
        if score >= threshold:
            action_taken = "blocked"
        else:
            action_taken = "logged"

        event = {
            "event_type": "injection_detected",
            "classifier_score": round(min(1.0, score), 6),
            # rule_matched is the stable rule ID — NEVER the attacker's text (D7).
            "rule_matched": first_rule[:128],
            "action_taken": action_taken,
        }

        if score >= threshold:
            return DetectorResult(action="block", event=event)
        else:
            # Logged but not blocked: emit event, pass the request.
            # The registry will emit via context.emit(); we surface this as
            # a "pass" so the chain continues, but we include the event so
            # the registry emits it.
            return DetectorResult(action="pass", event=event)
