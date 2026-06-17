"""LLM-as-judge injection classifier (F-007, ADR-0010 §2-§4).

This package adds a semantic classification step to the F-005 regex injection
detector.  It is OPTIONAL and OPT-IN: a tenant must configure a classifier preset
(via `sentinel-cli classifier set`) for the judge to run.  When unconfigured,
degraded, or low-confidence, the detector falls back to the regex score — NEVER
to "allow" (the F-005 fail-safe posture, R9).

All judge calls go THROUGH the F-006 provider layer (`ProviderAdapter`), never a
raw provider SDK (R5), with structured-output FORCING (tool-use / json_schema, R6)
and a static, hardened system prompt that never interpolates user text (R8).
"""

from __future__ import annotations

from orchestration.judge.base import JudgeAdapter, JudgeParseError, JudgeVerdict
from orchestration.judge.registry import JudgeRegistry

__all__ = [
    "JudgeAdapter",
    "JudgeParseError",
    "JudgeVerdict",
    "JudgeRegistry",
]
