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
from dataclasses import dataclass
from typing import Any

import structlog

from orchestration.hooks.base import DetectorResult, PreRequestHook
from orchestration.judge.base import EVENT_INJECTION_ML, EVENT_RECURSIVE
from orchestration.judge.config import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_FLOOR_THRESHOLD,
    UNCONFIGURED,
    ClassifierConfig,
)

log = structlog.get_logger(__name__)

_DETECTOR_SLUG = "defense"

# Known jailbreak-family rule ids (high-confidence single-pattern indicators).
# When one of these is the first match, the regex already strongly indicates an
# attack — skip the LLM judge (safe-by-default pre-filter, R7).
JAILBREAK_FAMILY_RULE_IDS: frozenset[str] = frozenset(
    {"INJ-001", "INJ-002", "INJ-003", "INJ-005", "INJ-006"}
)

# Patterns that indicate the prompt is targeting the CLASSIFIER itself (recursive
# injection).  Matching one emits a recursive_injection_attempt event (layer-4
# observability of the recursive-injection defense, ADR-0010 §5).
_META_ATTACK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"you\s+are\s+(a|the)\s+(security\s+)?classifier",
        r"(ignore|disregard|forget)\s+your\s+(classifier\s+|verdict\s+|system\s+)?"
        r"(instructions?|rules?|prompt)",
        r"(return|report|set|give)\s+(a\s+|the\s+)?(score|confidence)\s+(of\s+)?0",
        r"report_verdict",
    )
]


def _matches_meta_attack(text: str) -> bool:
    """True if the text appears to target the classifier surface (recursive injection)."""
    return any(p.search(text) for p in _META_ATTACK_PATTERNS)


async def _resolve_classifier_config(context: Any) -> ClassifierConfig:
    """Resolve the tenant's classifier config (B2C inheritance walk, ADR-0010 §6).

    Reads on a tenant session (RLS, R13) via the repository.  Any error → UNCONFIGURED
    (fail-safe: the detector then uses the regex score only, never "allow").
    """
    try:
        from persistence.repositories.tenant_routing_policy_repository import get_classifier_config

        return await get_classifier_config(context.tenant_context)
    except Exception:
        log.error(
            "orchestration.classifier_config.resolve_error",
            request_id=getattr(context, "request_id", "?"),
        )
        return UNCONFIGURED


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


def _regex_verdict(score: float, first_rule: str | None, threshold: float) -> DetectorResult:
    """F-005 regex-only verdict — byte-identical to the pre-F-007 behavior (R4).

    Returns "block" (score >= threshold) or "pass" (logged / no finding). The
    rule_matched is the stable rule ID, NEVER the attacker's text (D7).
    """
    if score < 0.001 or first_rule is None:
        return DetectorResult(action="pass")
    action_taken = "blocked" if score >= threshold else "logged"
    event = {
        "event_type": "injection_detected",
        "classifier_score": round(min(1.0, score), 6),
        "rule_matched": first_rule[:128],
        "action_taken": action_taken,
    }
    action = "block" if score >= threshold else "pass"
    return DetectorResult(action=action, event=event)


def _ml_event(
    *,
    regex_score: float,
    verdict: Any,
    final: float,
    judge_model: str,
    audit_mode: str,
    first_rule: str | None,
    action_taken: str,
) -> dict[str, Any]:
    """Build a prompt_injection_detected_ml event.

    CONTENT-FREE by construction in BOTH modes: only scores, the stable rule label,
    and the audit_mode flag — never prompt text (R10's MUST is satisfied for both
    modes). request_id (stamped by HookContext.emit) is the forensic join-key, so no
    separate prompt-hash column is allocated (per the approved migration 0009/0010).
    audit_mode records the tenant's privacy posture for downstream consumers.
    """
    event: dict[str, Any] = {
        "event_type": EVENT_INJECTION_ML,
        "action_taken": action_taken,
        "classifier_score": round(min(1.0, regex_score), 6),  # the regex component
        "judge_score": round(verdict.score, 6),
        "judge_confidence": round(verdict.confidence, 6),
        "judge_model": judge_model,
        "final_score": round(min(1.0, final), 6),
        "audit_mode": audit_mode,
    }
    if first_rule is not None:
        event["rule_matched"] = first_rule[:128]
    return event


def _recursive_event(
    regex_score: float, first_rule: str | None, action_taken: str
) -> dict[str, Any]:
    """Build a recursive_injection_attempt event (the classifier surface was targeted)."""
    event: dict[str, Any] = {
        "event_type": EVENT_RECURSIVE,
        "action_taken": action_taken,
        "classifier_score": round(min(1.0, regex_score), 6),
    }
    if first_rule is not None:
        event["rule_matched"] = first_rule[:128]
    return event


class InjectionHook(PreRequestHook):
    """Pre-request injection detection hook (F-005 regex + F-007 LLM-as-judge).

    ALWAYS scans context.original_user_content (pre-masking snapshot) per D1; the
    content parameter is ignored (injection → block only, never mask per §4).

    F-005 (classifier disabled): a curated regex score; block iff score >=
    injection_score_threshold (0.75), else logged. Byte-identical to pre-F-007 (R4).

    F-007 (classifier_enabled AND the request passes the pre-filter, R7): an
    LLM-as-judge step runs AFTER the regex pass, THROUGH the F-006 provider layer
    (R5). final_score = max(regex_score, judge_score); a low-confidence / failed /
    unconfigured judge falls back to the regex score — NEVER "allow" (R9).
    """

    detector_slug = "defense"

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Score original_user_content (regex + optional judge). Returns block/pass."""
        scan_text = getattr(context, "original_user_content", content)
        if not scan_text:
            return DetectorResult(action="pass")

        regex_score, first_rule = _score_and_first_rule(scan_text)
        threshold = self._settings.injection_score_threshold

        # Cheap global gates first (NO DB read): the classifier-off / non-gateway /
        # known-jailbreak-family path stays on the regex verdict, byte-identical to
        # F-005 (R8). Resolving per-tenant config never happens on this path.
        if not self._judge_gates_pass(first_rule, context):
            return _regex_verdict(regex_score, first_rule, threshold)

        # Past the gates: resolve the per-tenant config ONCE (one RLS read, ADR-0025
        # Fork-4). The thresholds gate WHETHER the judge runs / counts — never the
        # max(regex, judge) blend — so no setting can lower final below regex (R1).
        cfg = await _resolve_classifier_config(context)
        floor, skip = self._band(cfg)

        # The judge runs only in the per-tenant uncertain band [floor, skip). Outside
        # it the regex verdict stands (obvious-clean / obvious-attack skip). Skipping
        # the judge can only keep (never lower) the verdict — escalation-only (R7).
        if regex_score < floor or regex_score >= skip:
            return _regex_verdict(regex_score, first_rule, threshold)

        result = await self._judge_verdict(
            scan_text, regex_score, first_rule, threshold, context, cfg
        )

        # Recursive-injection observability (layer 4, ADR-0010 §5): emit ONLY when the
        # judge surface was actually reached (in-band) AND the prompt targeted the
        # classifier. The gate / out-of-band paths emit no new event types (R4).
        if _matches_meta_attack(scan_text):
            taken = "blocked" if result.action == "block" else "logged"
            await context.emit(
                _recursive_event(regex_score, first_rule, taken), detector_slug=_DETECTOR_SLUG
            )

        return result

    def _judge_gates_pass(self, first_rule: str | None, context: Any) -> bool:
        """Cheap, DB-free eligibility gates (R8 / ADR-0025 Fork-4).

        These never read tenant config, so the classifier-off / non-gateway /
        known-jailbreak-family path returns the regex verdict with NO DB read.
        Require an explicit bool True for classifier_enabled — a mocked/absent
        settings attribute (F-005 MagicMock) must stay on the regex path (R4).
        """
        if getattr(self._settings, "classifier_enabled", False) is not True:
            return False
        if getattr(context, "provider_registry", None) is None:
            return False  # no judge wiring (test / non-gateway path) → regex only
        if first_rule in JAILBREAK_FAMILY_RULE_IDS:
            return False  # known jailbreak family — safe-by-default skip
        return True

    def _band(self, cfg: ClassifierConfig) -> tuple[float, float]:
        """Resolve the per-tenant uncertain band [floor, skip) (ADR-0025).

        A NULL per-tenant column falls back to the default: floor → 0.0 (no
        obvious-clean skip, today's behavior); skip → the existing `judge_skip_score`
        SETTING (default 0.9), so a deployment that customized that setting is
        preserved. A per-tenant column overrides the default.
        """
        floor = cfg.floor_threshold if cfg.floor_threshold is not None else DEFAULT_FLOOR_THRESHOLD
        skip = (
            cfg.skip_threshold
            if cfg.skip_threshold is not None
            else getattr(self._settings, "judge_skip_score", 0.9)
        )
        return floor, skip

    async def _judge_verdict(
        self,
        scan_text: str,
        regex_score: float,
        first_rule: str | None,
        threshold: float,
        context: Any,
        cfg: ClassifierConfig,
    ) -> DetectorResult:
        """Run the judge through the F-006 layer; blend or fall back to regex (R9)."""
        from orchestration.judge.invoker import JudgeRan, run_judge

        gw = getattr(context, "gateway_settings", None)
        request_budget = float(
            getattr(gw, "request_timeout_seconds", self._settings.judge_timeout_seconds)
        )
        outcome = await run_judge(
            scan_text=scan_text,
            preset=cfg.model_id,
            context=context,
            provider_registry=context.provider_registry,
            judge_timeout_s=self._settings.judge_timeout_seconds,
            request_budget_s=request_budget,
        )

        # Per-tenant confidence floor (NULL → 0.5, the historical hardcode).
        confidence_floor = (
            cfg.confidence_threshold
            if cfg.confidence_threshold is not None
            else DEFAULT_CONFIDENCE_THRESHOLD
        )

        # Fallback (unconfigured / degraded / invocation_failed / policy_denied) or
        # below the per-tenant confidence floor → regex score only. run_judge already
        # emitted its events. Never "allow" (R9).
        if not isinstance(outcome, JudgeRan) or outcome.verdict.confidence < confidence_floor:
            return _regex_verdict(regex_score, first_rule, threshold)

        verdict = outcome.verdict
        final = min(1.0, max(regex_score, verdict.score))
        action_taken = "blocked" if final >= threshold else "logged"
        event = _ml_event(
            regex_score=regex_score,
            verdict=verdict,
            final=final,
            judge_model=outcome.judge_model,
            audit_mode=cfg.audit_mode,
            first_rule=first_rule,
            action_taken=action_taken,
        )
        action = "block" if final >= threshold else "pass"
        return DetectorResult(action=action, event=event)
