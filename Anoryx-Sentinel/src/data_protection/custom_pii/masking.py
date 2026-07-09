"""Masking / tokenization for custom-PII spans (F-028, ADR-0034).

Mirrors orchestration.detectors.pii_detector._apply_pii_masks' reverse-order
replacement, but additionally MERGES overlapping spans first — custom patterns
come from independent tenant-supplied regexes that can overlap, and naively
replacing overlapping spans would corrupt offsets / double-redact. Overlapping
spans collapse into one redaction covering their union (label taken from the
highest-score contributing span).
"""

from __future__ import annotations

from data_protection.custom_pii.engine import CustomPiiSpan

_MASK_TEMPLATE = "[REDACTED:{name}]"


def merge_spans(spans: list[CustomPiiSpan]) -> list[CustomPiiSpan]:
    """Collapse overlapping/adjacent spans into non-overlapping ones.

    Returned spans are sorted ascending by start and never overlap. When spans
    overlap, the merged span spans their union and takes the label/score/action
    of the highest-score contributor (deterministic tie-break: first by start).
    """
    if not spans:
        return []
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[CustomPiiSpan] = []
    cur = ordered[0]
    for nxt in ordered[1:]:
        if nxt.start < cur.end:  # overlap
            winner = cur if cur.score >= nxt.score else nxt
            cur = CustomPiiSpan(
                start=cur.start,
                end=max(cur.end, nxt.end),
                name=winner.name,
                score=winner.score,
                action=winner.action,
            )
        else:
            merged.append(cur)
            cur = nxt
    merged.append(cur)
    return merged


def apply_masks(text: str, spans: list[CustomPiiSpan], *, action: str) -> str:
    """Return `text` with every (merged) span replaced per `action`.

    action="block" returns text unchanged (blocked content is never forwarded).
    Replacements are applied in reverse start order so earlier offsets are
    preserved (same technique as the built-in PII detector).
    """
    if action == "block":
        return text
    merged = merge_spans(spans)
    chars = list(text)
    for span in sorted(merged, key=lambda s: s.start, reverse=True):
        if action == "tokenize":
            replacement = f"[TOKEN:{span.name}:{span.start}:{span.end}]"
        else:
            replacement = _MASK_TEMPLATE.format(name=span.name)
        chars[span.start : span.end] = list(replacement)
    return "".join(chars)
