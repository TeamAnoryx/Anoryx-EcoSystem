"""Backup key naming convention, shared by backup.py and both sinks (F-024).

Key shape: `sentinel-backup-{YYYYMMDDTHHMMSSZ}.dump` — the timestamp is the
sole source of truth for a backup's created_at (not filesystem mtime, which a
sink's storage layer may not preserve faithfully) and for retention-cleanup
ordering.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

_PREFIX = "sentinel-backup-"
_SUFFIX = ".dump"
_TS_FORMAT = "%Y%m%dT%H%M%SZ"
_KEY_RE = re.compile(rf"^{re.escape(_PREFIX)}(\d{{8}}T\d{{6}}Z){re.escape(_SUFFIX)}$")


def make_key(now: datetime) -> str:
    """Mint a backup key for the given (timezone-aware) timestamp."""
    return f"{_PREFIX}{now.astimezone(UTC).strftime(_TS_FORMAT)}{_SUFFIX}"


def parse_created_at(key: str) -> str | None:
    """Return the RFC3339 UTC created_at encoded in key, or None if key is
    not one of ours (foreign file in the same directory/bucket)."""
    m = _KEY_RE.match(key)
    if m is None:
        return None
    ts = datetime.strptime(m.group(1), _TS_FORMAT).replace(tzinfo=UTC)
    return ts.isoformat().replace("+00:00", "Z")
