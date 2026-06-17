"""JudgeRegistry — preset string → adapter resolution (F-007, ADR-0010 §3).

The preset is AUTHORITATIVE: it names both the provider and the model. The tenant
routing policy's `fallback_order` is NOT consulted for classifier routing (D1).
Only the two contract-allowed presets resolve; anything else is treated as
unconfigured (defensive — migration 0009's CHECK already restricts the stored
value to these two or NULL).
"""

from __future__ import annotations

from orchestration.judge.base import JudgeAdapter
from orchestration.judge.gpt_mini import PRESET as GPT_MINI_PRESET
from orchestration.judge.gpt_mini import GptMiniJudge
from orchestration.judge.haiku import PRESET as HAIKU_PRESET
from orchestration.judge.haiku import HaikuJudge

# Stateless singletons — the adapters carry no per-request state.
_ADAPTERS: dict[str, JudgeAdapter] = {
    HAIKU_PRESET: HaikuJudge(),
    GPT_MINI_PRESET: GptMiniJudge(),
}

# The two presets the contract (migration 0009 CHECK) permits.
ALLOWED_PRESETS: frozenset[str] = frozenset(_ADAPTERS.keys())


class JudgeRegistry:
    """Resolve a preset string to a judge adapter and its (provider, model)."""

    @staticmethod
    def resolve(preset: str | None) -> JudgeAdapter | None:
        """Return the adapter for a preset, or None if unconfigured/unknown."""
        if not preset:
            return None
        return _ADAPTERS.get(preset)

    @staticmethod
    def provider_model(preset: str | None) -> tuple[str, str] | None:
        """Return (provider, model) for a known preset, else None."""
        adapter = JudgeRegistry.resolve(preset)
        if adapter is None:
            return None
        return adapter.provider, adapter.model
