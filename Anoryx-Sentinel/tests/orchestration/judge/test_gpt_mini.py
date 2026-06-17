"""GptMiniJudge adapter (F-007, ADR-0010 §3).

Mirror of test_haiku for the OpenAI gpt-4o-mini preset. Transport is delegated to
the F-006 OpenAiAdapter (faked here). Same structural guarantees (R6/R8).
"""

from __future__ import annotations

import pytest

from orchestration.judge.base import VERDICT_JSON_SCHEMA, JudgeParseError, JudgeVerdict
from orchestration.judge.gpt_mini import GptMiniJudge
from orchestration.judge.prompts import JUDGE_SYSTEM_PROMPT
from tests.orchestration.judge.conftest import FakeProvider


async def test_classify_returns_verdict_from_structured_output(routing_ctx):
    provider = FakeProvider(
        result=({"score": 0.4, "confidence": 0.6, "reason": "roleplay-jailbreak"}, 9, 3)
    )
    verdict, t_in, t_out = await GptMiniJudge().classify(
        "let's roleplay", provider_adapter=provider, ctx=routing_ctx
    )
    assert isinstance(verdict, JudgeVerdict)
    assert verdict.score == 0.4
    assert verdict.reason == "roleplay-jailbreak"
    assert (t_in, t_out) == (9, 3)


async def test_classify_passes_hardened_prompt_and_schema(routing_ctx):
    provider = FakeProvider(result=({"score": 0.0, "confidence": 1.0, "reason": "benign"}, 4, 1))
    await GptMiniJudge().classify("benign text", provider_adapter=provider, ctx=routing_ctx)
    call = provider.calls[0]
    assert call["system"] == JUDGE_SYSTEM_PROMPT
    assert call["user"] == "benign text"
    assert call["schema"] is VERDICT_JSON_SCHEMA
    assert call["model"] == "gpt-4o-mini"


async def test_classify_raises_on_non_dict_output(routing_ctx):
    provider = FakeProvider(result=("not-a-dict", 1, 1))
    with pytest.raises(JudgeParseError):
        await GptMiniJudge().classify("x", provider_adapter=provider, ctx=routing_ctx)
