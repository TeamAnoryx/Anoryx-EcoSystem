#!/usr/bin/env python3
"""
policy_schema_guard.py

Load-bearing safety control for the Anoryx unattended pipeline.

Purpose
    Fail CI (and local checks) if policy.schema.json has changed from its
    pinned baseline. In unattended cloud runs there is NO interactive
    security-auditor gate, so this guard is what stops the policy schema from
    being silently widened.

Baseline
    Originally locked at F-008 (commit a9e2344). Consciously RE-PINNED to the
    current reviewed schema after F-016 (CodeScanPolicy), F-017 (DataLockPolicy),
    and F-019 (ModelApprovalPolicy) legitimately extended it via the CRIT-2
    process. Current pinned baseline commit: 1a823bf.
    Re-pinning is a rare, deliberate, reviewed act — see SETUP.md.

Usage
    python policy_schema_guard.py               -> exit 0 if unchanged, 1 if changed/invalid
    python policy_schema_guard.py --print-hash   -> print sha256 of the current schema file
    pytest                                       -> discovers test_policy_schema_unchanged

What this guard does and does NOT do
    - It makes ANY modification to the schema loud and CI-blocking: the hash
      flips, the check goes red, and the change cannot land without a human
      deliberately re-pinning the lock in a visible diff.
    - It does NOT cryptographically stop a single PR that edits BOTH the schema
      and the lock file at once. That is caught by your kept human merge gate
      (the diff shows both files) plus a CODEOWNERS rule on both paths.

Intentionally strict: this blocks ALL changes (even tightening), not just
widening. Re-pinning is meant to be a rare, deliberate, reviewed act.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# --- SLOTS: real repo paths (relative to repo root) --------------------------
POLICY_SCHEMA_PATH = Path("Anoryx-Sentinel/contracts/policy.schema.json")
POLICY_SCHEMA_LOCK = Path("Anoryx-Sentinel/contracts/policy.schema.lock")
# Baseline re-pinned to current reviewed schema (commit 1a823bf),
# was F-008 a9e2344, extended by F-016/F-017/F-019. See SETUP.md to re-pin.
# -----------------------------------------------------------------------------


def _repo_root() -> Path:
    """Walk up to the repo root (.git may be a dir OR a worktree file)."""
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / ".git").exists():
            return parent
    # Fallback: GitHub Actions checks out at the working dir root.
    return Path.cwd()


def _schema_bytes(root: Path) -> bytes:
    path = root / POLICY_SCHEMA_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"policy schema not found at {POLICY_SCHEMA_PATH} (resolved: {path}). "
            f"Fix POLICY_SCHEMA_PATH in policy_schema_guard.py."
        )
    return path.read_bytes()


def current_hash(root: Path | None = None) -> str:
    root = root or _repo_root()
    data = _schema_bytes(root)
    # Fail fast if the schema is not even valid JSON.
    try:
        json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"policy schema is not valid UTF-8 JSON: {exc}") from exc
    return hashlib.sha256(data).hexdigest()


def pinned_hash(root: Path | None = None) -> str:
    root = root or _repo_root()
    lock = root / POLICY_SCHEMA_LOCK
    if not lock.exists():
        raise FileNotFoundError(
            f"lock file not found at {POLICY_SCHEMA_LOCK} (resolved: {lock}). "
            f"Create it once:\n"
            f"  python policy_schema_guard.py --print-hash > {POLICY_SCHEMA_LOCK}"
        )
    return lock.read_text(encoding="utf-8").strip()


def verify() -> None:
    root = _repo_root()
    have = current_hash(root)
    want = pinned_hash(root)
    if have != want:
        raise SystemExit(
            "POLICY SCHEMA GUARD FAILED\n"
            f"  file    : {POLICY_SCHEMA_PATH}\n"
            f"  baseline: {want}  (pinned baseline 1a823bf)\n"
            f"  current : {have}\n\n"
            "The pinned policy schema was modified. In unattended mode there is no\n"
            "security-auditor gate, so this is blocked by design.\n\n"
            "If this change is intentional AND reviewed by a human:\n"
            "  1) confirm the new schema is correct\n"
            f"  2) re-pin: python policy_schema_guard.py --print-hash > {POLICY_SCHEMA_LOCK}\n"
            "  3) commit BOTH files in the same PR so the diff is visible for review\n"
        )


def test_policy_schema_unchanged() -> None:
    """pytest entry point."""
    assert current_hash() == pinned_hash(), (
        "policy.schema.json changed from its pinned baseline (1a823bf). "
        "See policy_schema_guard.py output / SETUP.md to re-pin."
    )


def main(argv: list[str]) -> int:
    if "--print-hash" in argv:
        print(current_hash())
        return 0
    verify()
    print(f"policy schema guard OK - {POLICY_SCHEMA_PATH} matches pinned baseline (1a823bf).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
