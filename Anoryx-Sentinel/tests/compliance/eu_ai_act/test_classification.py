"""Unit tests for F-030 EU AI Act risk classification (no DB)."""

from __future__ import annotations

from compliance.eu_ai_act.classification import (
    classify,
    known_high_risk_tags,
    known_prohibited_tags,
)


def test_prohibited_beats_high_risk():
    result = classify(["employment", "social_scoring"])
    assert result.tier == "prohibited"
    assert result.matched_prohibited
    # high-risk match is still recorded but the tier is prohibited
    assert result.matched_high_risk


def test_high_risk_annex_iii():
    result = classify(["employment"])
    assert result.tier == "high_risk"
    assert any("Annex III(4)" in m for m in result.matched_high_risk)
    assert any("Art.12" in h for h in result.obligations_hint)


def test_limited_or_minimal_when_no_match():
    result = classify(["chatbot_faq"])
    assert result.tier == "limited_or_minimal"
    # unknown tag is noted, not an error
    assert any("unrecognised" in n for n in result.notes)


def test_empty_tags_is_limited():
    result = classify([])
    assert result.tier == "limited_or_minimal"


def test_multiple_high_risk_tags_all_reported():
    result = classify(["employment", "creditworthiness", "law_enforcement"])
    assert result.tier == "high_risk"
    assert len(result.matched_high_risk) == 3


def test_case_insensitive_and_whitespace_tolerant():
    result = classify(["  Employment  "])
    assert result.tier == "high_risk"


def test_known_tag_lists_nonempty_and_sorted():
    prohibited = known_prohibited_tags()
    high = known_high_risk_tags()
    assert "social_scoring" in prohibited
    assert "employment" in high
    assert list(prohibited) == sorted(prohibited)
    assert list(high) == sorted(high)


def test_result_always_carries_disclaimer():
    for tags in ([], ["employment"], ["social_scoring"]):
        assert "NOT legal advice" in classify(tags).disclaimer
