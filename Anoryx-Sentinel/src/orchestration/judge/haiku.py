"""HaikuJudge — Anthropic Claude Haiku preset (F-007, ADR-0010 §3).

Preset: "anthropic:claude-haiku-4-5".  Structured-output forcing is performed by
the F-006 AnthropicAdapter.classify_structured (tool-use); this class only fixes
the preset string.  Transport, base-URL pinning, and ProviderError handling live
in the F-006 adapter (R5).
"""

from __future__ import annotations

from orchestration.judge.base import JudgeAdapter

PRESET = "anthropic:claude-haiku-4-5"


class HaikuJudge(JudgeAdapter):
    """Anthropic Haiku classifier preset."""

    @property
    def preset(self) -> str:
        return PRESET
