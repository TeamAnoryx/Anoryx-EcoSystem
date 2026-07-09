"""Unit tests for F-028 masking (span merge + reverse-order replacement)."""

from __future__ import annotations

from data_protection.custom_pii.engine import CustomPiiSpan
from data_protection.custom_pii.masking import apply_masks, merge_spans


def _s(start, end, name="X", score=0.85, action=None):
    return CustomPiiSpan(start=start, end=end, name=name, score=score, action=action)


class TestMergeSpans:
    def test_non_overlapping_unchanged(self):
        merged = merge_spans([_s(0, 3), _s(5, 8)])
        assert [(m.start, m.end) for m in merged] == [(0, 3), (5, 8)]

    def test_overlapping_merged_to_union(self):
        merged = merge_spans([_s(0, 5), _s(3, 8)])
        assert [(m.start, m.end) for m in merged] == [(0, 8)]

    def test_overlap_takes_higher_score_label(self):
        merged = merge_spans([_s(0, 5, name="LOW", score=0.5), _s(3, 8, name="HIGH", score=0.9)])
        assert merged[0].name == "HIGH"

    def test_empty(self):
        assert merge_spans([]) == []


class TestApplyMasks:
    def test_mask_replaces_span(self):
        text = "id EMP-123456 end"
        out = apply_masks(text, [_s(3, 13, name="EMPLOYEE_ID")], action="mask")
        assert out == "id [REDACTED:EMPLOYEE_ID] end"
        assert "EMP-123456" not in out

    def test_tokenize_uses_token_marker(self):
        out = apply_masks("EMP-123456", [_s(0, 10, name="EMPLOYEE_ID")], action="tokenize")
        assert out.startswith("[TOKEN:EMPLOYEE_ID:0:10]")

    def test_block_returns_unchanged(self):
        text = "EMP-123456"
        assert apply_masks(text, [_s(0, 10)], action="block") == text

    def test_multiple_spans_all_masked_offsets_preserved(self):
        text = "EMP-111111 x EMP-222222"
        spans = [_s(0, 10, name="E"), _s(13, 23, name="E")]
        out = apply_masks(text, spans, action="mask")
        assert out == "[REDACTED:E] x [REDACTED:E]"

    def test_overlapping_spans_do_not_corrupt(self):
        text = "abcdefgh"
        out = apply_masks(text, [_s(0, 5, name="A"), _s(3, 8, name="B", score=0.9)], action="mask")
        # merged into one [0,8) redaction with the higher-score label
        assert out == "[REDACTED:B]"
