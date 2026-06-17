"""Cost-estimator unit tests (F-006, ADR-0008 §7).

The estimator is a CLIENT-SIDE COST ESTIMATE only. These tests pin the lookup,
the conservative default for unknown models, and the pre-request math.
"""

from __future__ import annotations

from gateway.models import CreateChatCompletionRequest
from gateway.router import cost


def _body(content="one two three four five", max_tokens=None, model="gpt-4o"):
    return CreateChatCompletionRequest(
        model=model,
        messages=[{"role": "user", "content": content}],  # type: ignore[list-item]
        max_tokens=max_tokens,
    )


def test_lookup_rate_known_longest_prefix_wins():
    # gpt-4o-mini must beat gpt-4o (longer prefix).
    assert cost.lookup_rate("openai", "gpt-4o-mini") == (0.015, 0.06)
    assert cost.lookup_rate("openai", "gpt-4o") == (0.25, 1.0)


def test_lookup_rate_unknown_uses_conservative_default():
    rate = cost.lookup_rate("openai", "totally-unknown-model")
    assert rate == (cost.DEFAULT_RATE_IN_PER_1K, cost.DEFAULT_RATE_OUT_PER_1K)
    # Default must be HIGH (conservative) so unknown models are not under-estimated.
    assert rate[0] >= 1.0 and rate[1] >= 1.0


def test_lookup_rate_per_provider_isolated():
    # An anthropic model name must not match an openai prefix and vice versa.
    assert cost.lookup_rate("anthropic", "gpt-4o") == (
        cost.DEFAULT_RATE_IN_PER_1K,
        cost.DEFAULT_RATE_OUT_PER_1K,
    )


def test_estimate_pre_request_uses_max_tokens_for_output():
    body = _body(content="a b c d", max_tokens=1000, model="gpt-4o")
    in_rate, out_rate = cost.lookup_rate("openai", "gpt-4o")
    # 4 prompt words / 1000 * in_rate + 1000/1000 * out_rate
    expected = (4 / 1000.0) * in_rate + (1000 / 1000.0) * out_rate
    assert abs(cost.estimate_pre_request(body, "openai", "gpt-4o") - expected) < 1e-9


def test_estimate_pre_request_omitted_max_tokens_not_zero_output():
    body = _body(content="a b c d e", max_tokens=None, model="gpt-4o")
    est = cost.estimate_pre_request(body, "openai", "gpt-4o")
    # Output cost must be non-zero even when max_tokens omitted (uses prompt proxy).
    assert est > 0


def test_estimate_from_tokens_matches_rate():
    in_rate, out_rate = cost.lookup_rate("anthropic", "claude-3-opus")
    est = cost.estimate_from_tokens("anthropic", "claude-3-opus", 2000, 1000)
    expected = (2000 / 1000.0) * in_rate + (1000 / 1000.0) * out_rate
    assert abs(est - expected) < 1e-9


def test_fallback_to_expensive_provider_costs_more():
    # Per-attempt recalculation (§7.3): the same request on a pricier provider
    # must produce a higher estimate.
    body = _body(content="x " * 50, max_tokens=500)
    cheap = cost.estimate_pre_request(body, "openai", "gpt-3.5-turbo")
    pricey = cost.estimate_pre_request(body, "anthropic", "claude-3-opus")
    assert pricey > cheap
