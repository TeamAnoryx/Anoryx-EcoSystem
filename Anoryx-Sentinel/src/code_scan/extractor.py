"""Fenced code-block extractor for LLM response text (F-016, ADR-0019 §11).

Parses fenced Markdown code blocks (triple-backtick ```) and extracts
the language tag from the info string.  Applies hard caps BEFORE returning
blocks to any scanner so oversized input cannot exhaust memory or subprocess
resources.

Constants (module-level, documented here and tested in tests/code_scan/):

    MAX_BLOCKS            = 20
        Maximum number of fenced code blocks returned per response.
        Additional blocks are silently skipped (counted in ``skipped_count``).
        Rationale: most LLM responses contain 0-5 code blocks; a response with
        >20 is likely adversarial or a model hallucination padding.

    MAX_BYTES_PER_BLOCK   = 65_536  (64 KiB)
        Maximum byte length of a single block's content.  Blocks larger than
        this are truncated to exactly MAX_BYTES_PER_BLOCK bytes (UTF-8 encoded)
        before being passed to scanners.  A ``truncated`` flag is set.
        Rationale: Semgrep/Bandit parse arbitrary code; a 64 KiB limit bounds
        the per-block parse time without losing meaningful signal (real code
        files are rarely >64 KiB).

    MAX_TOTAL_BYTES       = 524_288  (512 KiB)
        Maximum total byte count across all returned blocks.  Once this budget
        is exhausted subsequent blocks are skipped (counted in ``skipped_count``).
        Rationale: even with MAX_BLOCKS=20 blocks each ≤64 KiB we cap the total
        at 512 KiB so the cumulative subprocess I/O and subprocess memory stay
        bounded regardless of block distribution.

Extraction algorithm:
    - Scans for lines matching the opening fence (``^```<info>```) using a
      pre-compiled regex.
    - Does NOT recurse into nested fences — the closing fence is the first
      ``^`````` line after the opening.
    - Non-code text (no fenced blocks found) returns an empty list cheaply
      (no allocation beyond the regex scan).
    - The language tag is the first whitespace-delimited token of the info
      string, lowercased, stripped of leading/trailing whitespace.  Empty
      info string → language = "".
    - Block content does NOT include the opening or closing fence lines.
    - The extractor is pure (no I/O, no subprocess, no state).

Return type: ``ExtractionResult`` dataclass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Hard caps (DoS guards — ADR-0019 §5 Extraction row)
# ---------------------------------------------------------------------------

MAX_BLOCKS: int = 20
"""Maximum number of fenced code blocks returned per response."""

MAX_BYTES_PER_BLOCK: int = 65_536  # 64 KiB
"""Maximum byte length (UTF-8) per single code block before truncation."""

MAX_TOTAL_BYTES: int = 524_288  # 512 KiB
"""Maximum cumulative byte length across all returned blocks."""

# Pre-compiled fence-open regex.  The info string (after ```) is captured.
_FENCE_OPEN_RE = re.compile(r"^```(.*)$")
_FENCE_CLOSE_RE = re.compile(r"^```\s*$")


@dataclass(frozen=True)
class CodeBlock:
    """A single extracted fenced code block.

    Attributes
    ----------
    language:
        Language tag from the info string (lowercased first token), e.g.
        "python", "javascript", "".  Never None.
    content:
        The raw block content between fences (may be truncated).
    truncated:
        True if ``content`` was truncated to ``MAX_BYTES_PER_BLOCK`` bytes.
    """

    language: str
    content: str
    truncated: bool = False


@dataclass
class ExtractionResult:
    """Result of a fenced-block extraction pass.

    Attributes
    ----------
    blocks:
        List of extracted ``CodeBlock`` objects after caps are applied.
    skipped_count:
        Number of blocks skipped due to MAX_BLOCKS or MAX_TOTAL_BYTES limits.
        A non-zero value should trigger a ``code_scan_warned`` event noting
        that the response was too large to scan in full.
    total_bytes:
        Sum of byte lengths of all returned block contents (after truncation).
    """

    blocks: list[CodeBlock] = field(default_factory=list)
    skipped_count: int = 0
    total_bytes: int = 0


def extract_code_blocks(text: str) -> ExtractionResult:
    """Parse *text* for fenced Markdown code blocks and return an ``ExtractionResult``.

    Applies MAX_BLOCKS, MAX_BYTES_PER_BLOCK, and MAX_TOTAL_BYTES caps before
    returning — scanners always receive pre-bounded input.

    Non-code text (no triple-backtick fences found) returns an
    ``ExtractionResult`` with an empty ``blocks`` list cheaply.

    Parameters
    ----------
    text:
        The full LLM response text (or accumulated streaming text).

    Returns
    -------
    ExtractionResult
        Contains the bounded list of ``CodeBlock`` objects, the skip count,
        and the total byte count of returned block contents.
    """
    if not text:
        return ExtractionResult()

    result = ExtractionResult()
    lines = text.splitlines()
    n = len(lines)
    i = 0

    while i < n:
        line = lines[i]
        m = _FENCE_OPEN_RE.match(line)
        if m is None:
            i += 1
            continue

        # Found an opening fence.  Extract the language tag from the info string.
        info = m.group(1).strip()
        language = info.split()[0].lower() if info.split() else ""

        # Collect body lines until closing fence or end of text.
        body_lines: list[str] = []
        i += 1
        while i < n:
            if _FENCE_CLOSE_RE.match(lines[i]):
                i += 1  # consume the closing fence line
                break
            body_lines.append(lines[i])
            i += 1
        # If we hit end-of-text without a closing fence, treat what we have as
        # the block content (common in streaming partial responses).

        content_raw = "\n".join(body_lines)

        # Apply per-block byte cap.
        content_bytes = content_raw.encode("utf-8", errors="replace")
        truncated = False
        if len(content_bytes) > MAX_BYTES_PER_BLOCK:
            content_bytes = content_bytes[:MAX_BYTES_PER_BLOCK]
            content_raw = content_bytes.decode("utf-8", errors="replace")
            truncated = True

        block_byte_len = len(content_bytes)

        # Check total-bytes budget.
        if result.total_bytes + block_byte_len > MAX_TOTAL_BYTES:
            # Exceeds total cap: skip this block (do not partially include it).
            result.skipped_count += 1
            continue

        # Check block-count cap.
        if len(result.blocks) >= MAX_BLOCKS:
            result.skipped_count += 1
            continue

        result.blocks.append(CodeBlock(language=language, content=content_raw, truncated=truncated))
        result.total_bytes += block_byte_len

    return result
