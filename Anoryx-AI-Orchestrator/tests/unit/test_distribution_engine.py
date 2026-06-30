"""Unit tests for the engine's pure parent-state aggregation (O-004, ADR-0004). No DB.

_aggregate_state honestly folds per-target states into the parent enum (Fork C): all
distributed (and >=1 target) → distributed; some distributed → partial; none → failed; a
zero-target distribution → failed (honest: nothing to distribute to). This is the only place
faking is unnecessary — it is a pure function; the non-stubbed e2e proves the full engine.
"""

from __future__ import annotations

from orchestrator.distribution.engine import _aggregate_state


def test_all_distributed_is_distributed():
    assert _aggregate_state(["distributed", "distributed"]) == "distributed"


def test_single_distributed_is_distributed():
    assert _aggregate_state(["distributed"]) == "distributed"


def test_mixed_is_partial():
    assert _aggregate_state(["distributed", "failed"]) == "partial"


def test_distributed_with_pending_is_partial():
    assert _aggregate_state(["distributed", "pending"]) == "partial"


def test_none_distributed_is_failed():
    assert _aggregate_state(["failed", "failed"]) == "failed"


def test_all_pending_is_failed():
    assert _aggregate_state(["pending", "pending"]) == "failed"


def test_zero_targets_is_failed():
    assert _aggregate_state([]) == "failed"
