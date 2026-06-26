"""F-007-FU vector 5: static sweep (no DB).

Asserts no `get_tenant_session(...) as NAME:` is followed by `NAME.begin(` anywhere
under src/. get_tenant_session autobegins, so wrapping it in session.begin() raises
InvalidRequestError — the ADR-0026 double-begin class. This guards against the bug
silently returning in a future feature (the corrected database.py docstring is the
other half of that guard).

Privileged-session sites (`get_privileged_session() as session: ... session.begin()`)
are correct — those sessions do NOT autobegin — and never match this pattern.
"""

from __future__ import annotations

import os
import re

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))

# Anchor: a get_tenant_session(...) call bound to a name (matches the _get_tenant_session
# alias too, since the prefix is a substring). Excludes get_privileged_session.
# NOTE: matches only single-line `async with get_tenant_session(...) as name:`
# expressions. A multi-line async-with (args split across lines) would not be
# detected — a documented false-negative surface; the current tree uses none.
_ANCHOR_RE = re.compile(r"get_tenant_session\s*\([^)]*\)\s+as\s+(\w+)\s*:")
_LOOKAHEAD = 7


def _offenders() -> list[str]:
    out: list[str] = []
    for root, _dirs, files in os.walk(_SRC):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8") as fh:
                lines = fh.readlines()
            for i, line in enumerate(lines):
                if line.lstrip().startswith("#"):
                    continue
                m = _ANCHOR_RE.search(line)
                if not m:
                    continue
                begin_re = re.compile(rf"\b{re.escape(m.group(1))}\.begin\s*\(")
                # The double-begin pattern places begin() as the next statement(s).
                for look in lines[i + 1 : i + 1 + _LOOKAHEAD]:
                    if look.lstrip().startswith("#"):
                        continue  # skip comments that merely mention session.begin()
                    if begin_re.search(look):
                        out.append(f"{path}:{i + 1}")
                        break
    return out


def test_no_remaining_double_begin_after_get_tenant_session():
    offenders = _offenders()
    assert offenders == [], (
        "get_tenant_session autobegins; wrapping it in session.begin() raises "
        "InvalidRequestError (ADR-0026 double-begin fail-open class). Offenders: "
        + ", ".join(offenders)
    )
