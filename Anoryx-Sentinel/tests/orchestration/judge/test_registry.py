"""JudgeRegistry preset resolution (F-007, ADR-0010 §3).

The preset is authoritative: it names provider AND model. Only the two
contract-allowed presets resolve; everything else is unconfigured.
"""

from __future__ import annotations

from orchestration.judge.gpt_mini import GptMiniJudge
from orchestration.judge.haiku import HaikuJudge
from orchestration.judge.registry import ALLOWED_PRESETS, JudgeRegistry


def test_resolve_haiku_preset_returns_haiku_adapter():
    adapter = JudgeRegistry.resolve("anthropic:claude-haiku-4-5")
    assert isinstance(adapter, HaikuJudge)
    assert adapter.provider == "anthropic"
    assert adapter.model == "claude-haiku-4-5"


def test_resolve_gpt_mini_preset_returns_gpt_mini_adapter():
    adapter = JudgeRegistry.resolve("openai:gpt-4o-mini")
    assert isinstance(adapter, GptMiniJudge)
    assert adapter.provider == "openai"
    assert adapter.model == "gpt-4o-mini"


def test_resolve_none_is_unconfigured():
    assert JudgeRegistry.resolve(None) is None


def test_resolve_empty_string_is_unconfigured():
    assert JudgeRegistry.resolve("") is None


def test_resolve_unknown_preset_is_unconfigured():
    # A preset not in the contract-allowed set never resolves (D1 / fail-safe).
    assert JudgeRegistry.resolve("anthropic:claude-3-opus") is None
    assert JudgeRegistry.resolve("openai:gpt-4") is None
    assert JudgeRegistry.resolve("bedrock:anything") is None


def test_provider_model_mapping():
    assert JudgeRegistry.provider_model("anthropic:claude-haiku-4-5") == (
        "anthropic",
        "claude-haiku-4-5",
    )
    assert JudgeRegistry.provider_model("openai:gpt-4o-mini") == ("openai", "gpt-4o-mini")
    assert JudgeRegistry.provider_model("nope") is None


def test_allowed_presets_are_exactly_the_two_contract_presets():
    assert ALLOWED_PRESETS == {"anthropic:claude-haiku-4-5", "openai:gpt-4o-mini"}
