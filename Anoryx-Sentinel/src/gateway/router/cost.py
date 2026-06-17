"""Client-side cost estimation primitives (F-006, ADR-0008 §7).

HONEST LANGUAGE (CLAUDE.md): everything here is a CLIENT-SIDE COST ESTIMATE,
never an authoritative bill. The COST_TABLE is hard-coded for F-006; dynamic /
live pricing is deferred to F-008 (ADR-0008 §12).

The estimator is used in two places:
  - PRE-REQUEST (§7.2): estimate from a word-count prompt proxy + max_tokens,
    compared to the tenant cost_ceiling_cents. Breach => RoutingBlockedError("cost").
  - PER-ATTEMPT (§7.3): recomputed for the ACTUAL resolved (provider, model) on
    every attempt, so a fallback to an expensive provider cannot silently overspend.

Rates are (in_cents_per_1k, out_cents_per_1k) keyed by (provider, model_prefix).
Unknown (provider, model) -> a documented conservative DEFAULT rate (best-effort).
"""

from __future__ import annotations

from gateway.models import CreateChatCompletionRequest

# (provider, model_prefix) -> (input cents / 1k tokens, output cents / 1k tokens).
# Longest matching prefix wins. These are coarse public list-price proxies as of
# F-006 authoring; they are NOT a bill. Cents, per 1,000 tokens.
COST_TABLE: dict[tuple[str, str], tuple[float, float]] = {
    # --- OpenAI ---
    ("openai", "gpt-4o-mini"): (0.015, 0.06),
    ("openai", "gpt-4o"): (0.25, 1.0),
    ("openai", "gpt-4-turbo"): (1.0, 3.0),
    ("openai", "gpt-4"): (3.0, 6.0),
    ("openai", "gpt-3.5-turbo"): (0.05, 0.15),
    ("openai", "gpt-3.5"): (0.05, 0.15),
    # --- Anthropic ---
    ("anthropic", "claude-3-5-haiku"): (0.08, 0.4),
    ("anthropic", "claude-3-5-sonnet"): (0.3, 1.5),
    ("anthropic", "claude-3-haiku"): (0.025, 0.125),
    ("anthropic", "claude-3-sonnet"): (0.3, 1.5),
    ("anthropic", "claude-3-opus"): (1.5, 7.5),
    ("anthropic", "claude-opus"): (1.5, 7.5),
    ("anthropic", "claude-sonnet"): (0.3, 1.5),
    ("anthropic", "claude"): (0.3, 1.5),
    # --- Bedrock (Anthropic-on-Bedrock + Titan/Llama families) ---
    ("bedrock", "anthropic.claude-3-5-sonnet"): (0.3, 1.5),
    ("bedrock", "anthropic.claude-3-haiku"): (0.025, 0.125),
    ("bedrock", "anthropic.claude"): (0.3, 1.5),
    ("bedrock", "amazon.titan"): (0.02, 0.06),
    ("bedrock", "meta.llama"): (0.03, 0.06),
}

# Conservative default rate for unknown (provider, model) — deliberately HIGH so
# an unknown model is never UNDER-estimated against a cost ceiling (§7.1).
# Cents per 1k tokens.
DEFAULT_RATE_IN_PER_1K: float = 3.0
DEFAULT_RATE_OUT_PER_1K: float = 6.0


def lookup_rate(provider: str, model: str) -> tuple[float, float]:
    """Return (in_per_1k_cents, out_per_1k_cents) for (provider, model).

    Longest-prefix match within the provider; conservative default if unknown.
    """
    best_len = -1
    best: tuple[float, float] | None = None
    for (p, prefix), rate in COST_TABLE.items():
        if p == provider and model.startswith(prefix) and len(prefix) > best_len:
            best_len = len(prefix)
            best = rate
    if best is None:
        return (DEFAULT_RATE_IN_PER_1K, DEFAULT_RATE_OUT_PER_1K)
    return best


def _prompt_word_proxy(body: CreateChatCompletionRequest) -> int:
    """Cheap word-count token proxy of the prompt (mirrors the gateway's
    existing stream token accounting, chat_completions.py:552/598).

    This is a pre-flight proxy only — it is NOT a tokenizer count.
    """
    return sum(len(m.content.split()) for m in body.messages)


def estimate_pre_request(
    body: CreateChatCompletionRequest,
    provider: str,
    model: str,
) -> float:
    """Pre-request client-side cost ESTIMATE in cents for (provider, model).

    estimate = prompt_words/1k * in_rate + max_tokens/1k * out_rate.

    max_tokens is the only output signal available pre-flight; when the client
    omitted it we conservatively use the prompt-word proxy as the output proxy
    so an unbounded request is not estimated as zero output cost.
    """
    in_rate, out_rate = lookup_rate(provider, model)
    prompt_tokens = _prompt_word_proxy(body)
    out_tokens = body.max_tokens if body.max_tokens is not None else max(prompt_tokens, 1)
    estimate = (prompt_tokens / 1000.0) * in_rate + (out_tokens / 1000.0) * out_rate
    return estimate


def estimate_from_tokens(
    provider: str,
    model: str,
    tokens_in: int,
    tokens_out: int,
) -> float:
    """Client-side cost ESTIMATE in cents from concrete token counts.

    Used for the running stream-time estimate (§7.4) and to reflect the final
    successful provider+model rate on the usage event (§7.5).
    """
    in_rate, out_rate = lookup_rate(provider, model)
    return (tokens_in / 1000.0) * in_rate + (tokens_out / 1000.0) * out_rate
