"""Judge adapter contract + verdict type (F-007, ADR-0010 §3).

A `JudgeAdapter` turns suspect user text into a `JudgeVerdict` by invoking the
F-006 provider layer with FORCED structured output (R6).  The adapter itself is
provider-agnostic: it delegates the transport + provider-native structured-output
request to the F-006 `ProviderAdapter` passed at call time (which owns the
config-pinned client and SSRF defense, threat #9), then validates the returned
dict into a `JudgeVerdict`.

The verdict schema is the SINGLE structural contract the judge may return.  It is
enforced by the provider (tool-use input_schema / response_format json_schema), so
the judge cannot be talked into free-form output (recursive-injection defense
layer 2, R6).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Event-type names (the seven F-007 variants; api-architect mirrors these in
# contracts/events.schema.json at STEP 6 — single source for the string here).
# ---------------------------------------------------------------------------
EVENT_INJECTION_ML = "prompt_injection_detected_ml"
EVENT_UNCONFIGURED = "classifier_unconfigured"
EVENT_DEGRADED = "classifier_degraded"
EVENT_INVOCATION_FAILED = "classifier_invocation_failed"
EVENT_RECURSIVE = "recursive_injection_attempt"
EVENT_JUDGE_BILLING = "judge_billing_event"
EVENT_SHADOW_OUTBOUND = "shadow_ai_detected_outbound"

# The forced-JSON contract the judge MUST return (R6).  Bounded + closed so the
# structured-output enforcement (tool-use / json_schema strict) is exact.
VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "score": {"type": "number", "minimum": 0, "maximum": 1},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reason": {"type": "string", "maxLength": 200},
    },
    "required": ["score", "confidence", "reason"],
    "additionalProperties": False,
}

# Small output cap for the judge call (verdict is tiny — keeps latency + cost low).
JUDGE_MAX_TOKENS = 256


class JudgeError(Exception):
    """Base for judge-layer errors."""


class JudgeParseError(JudgeError):
    """The provider returned output that is not a valid verdict (→ invocation_failed)."""


@dataclass(frozen=True)
class JudgeVerdict:
    """A structured classifier verdict.

    score:      likelihood the text is an injection/jailbreak attempt, [0, 1].
    confidence: the judge's confidence in `score`, [0, 1].
    reason:     a short category label (never the attacker's text — D7).
    """

    score: float
    confidence: float
    reason: str


def verdict_from_dict(parsed: Any) -> JudgeVerdict:
    """Validate a forced-JSON dict into a JudgeVerdict, or raise JudgeParseError.

    Defense-in-depth: even though the provider enforces the schema, we re-validate
    types and bounds here so a malformed/partial structured response cannot smuggle
    an out-of-range score into the blend (R9 fail-safe).
    """
    if not isinstance(parsed, dict):
        raise JudgeParseError("verdict is not an object")
    try:
        score = float(parsed["score"])
        confidence = float(parsed["confidence"])
        reason = parsed["reason"]
    except (KeyError, TypeError, ValueError) as exc:
        raise JudgeParseError("verdict missing/invalid fields") from exc
    if not isinstance(reason, str):
        raise JudgeParseError("reason is not a string")
    if not (0.0 <= score <= 1.0) or not (0.0 <= confidence <= 1.0):
        raise JudgeParseError("score/confidence out of [0,1]")
    # Defensively sanitize the reason label: restrict to a safe charset and bound
    # length, so even if the model echoes attacker text into `reason` it cannot
    # smuggle control characters / prompt content downstream (it is never emitted to
    # the audit log, but this closes the latent log-injection / content-leak risk).
    safe_reason = re.sub(r"[^A-Za-z0-9 _:.-]", "", reason)[:200]
    return JudgeVerdict(score=score, confidence=confidence, reason=safe_reason)


class JudgeAdapter(ABC):
    """Provider-agnostic judge.  Subclasses set `preset`; transport is delegated.

    `provider` and `model` are derived from the preset string
    "<provider>:<model>" (e.g. "anthropic:claude-haiku-4-5").
    """

    @property
    @abstractmethod
    def preset(self) -> str:
        """The canonical preset string "<provider>:<model>"."""

    @property
    def provider(self) -> str:
        return self.preset.split(":", 1)[0]

    @property
    def model(self) -> str:
        return self.preset.split(":", 1)[1]

    async def classify(
        self,
        prompt: str,
        *,
        provider_adapter: Any,
        ctx: Any,
    ) -> tuple[JudgeVerdict, int, int]:
        """Invoke the F-006 provider adapter with forced structured output (R5/R6).

        Returns (verdict, tokens_in, tokens_out).  Raises ProviderError (transport,
        from the adapter) or JudgeParseError (invalid structured output).
        """
        from orchestration.judge.prompts import JUDGE_SYSTEM_PROMPT

        parsed, tokens_in, tokens_out = await provider_adapter.classify_structured(
            system=JUDGE_SYSTEM_PROMPT,
            user=prompt,
            schema=VERDICT_JSON_SCHEMA,
            model=self.model,
            ctx=ctx,
        )
        return verdict_from_dict(parsed), tokens_in, tokens_out
