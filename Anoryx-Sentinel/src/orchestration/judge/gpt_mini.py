"""GptMiniJudge — OpenAI gpt-4o-mini preset (F-007, ADR-0010 §3).

Preset: "openai:gpt-4o-mini".  Structured-output forcing is performed by the F-006
OpenAiAdapter.classify_structured (response_format=json_schema, strict); this class
only fixes the preset string.  Transport + pinning live in the F-006 adapter (R5).
"""

from __future__ import annotations

from orchestration.judge.base import JudgeAdapter

PRESET = "openai:gpt-4o-mini"


class GptMiniJudge(JudgeAdapter):
    """OpenAI gpt-4o-mini classifier preset."""

    @property
    def preset(self) -> str:
        return PRESET
