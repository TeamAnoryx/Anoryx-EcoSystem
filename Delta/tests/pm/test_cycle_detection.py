"""Pure unit tests for D-015's dependency-cycle detection — no DB, no I/O."""

from __future__ import annotations

from delta.pm.service import _would_create_cycle


def test_no_edges_no_cycle() -> None:
    assert _would_create_cycle([], new_blocking="A", new_blocked="B") is False


def test_independent_tasks_no_cycle() -> None:
    edges = [("X", "Y")]
    assert _would_create_cycle(edges, new_blocking="A", new_blocked="B") is False


def test_direct_cycle_detected() -> None:
    # A already blocks B. Adding "B blocks A" would create a 2-node cycle.
    edges = [("A", "B")]
    assert _would_create_cycle(edges, new_blocking="B", new_blocked="A") is True


def test_transitive_cycle_detected() -> None:
    # A blocks B blocks C. Adding "C blocks A" would close a 3-node cycle.
    edges = [("A", "B"), ("B", "C")]
    assert _would_create_cycle(edges, new_blocking="C", new_blocked="A") is True


def test_diamond_shape_new_edge_creates_cycle() -> None:
    # A blocks B and C; B and C both block D. Adding "D blocks A" closes a cycle
    # (A -> B -> D would then require D before A, while A already precedes D).
    edges = [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")]
    assert _would_create_cycle(edges, new_blocking="D", new_blocked="A") is True


def test_diamond_shape_unrelated_edge_no_cycle() -> None:
    edges = [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")]
    assert _would_create_cycle(edges, new_blocking="E", new_blocked="A") is False


def test_self_reference_flagged_as_cycle_by_the_pure_check() -> None:
    # The service layer rejects self-dependencies earlier with a dedicated
    # SelfDependencyError, but the graph-traversal primitive itself should still
    # correctly identify a self-edge as degenerate/cyclic if ever called directly.
    assert _would_create_cycle([], new_blocking="A", new_blocked="A") is True


def test_long_chain_cycle_detected() -> None:
    edges = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E")]
    assert _would_create_cycle(edges, new_blocking="E", new_blocked="A") is True


def test_long_chain_unrelated_new_edge_no_cycle() -> None:
    # A->B->C->D exists. A brand new, disconnected task E blocking D is fine — E
    # doesn't appear anywhere in the existing chain, so no path back to E exists.
    edges = [("A", "B"), ("B", "C"), ("C", "D")]
    assert _would_create_cycle(edges, new_blocking="E", new_blocked="D") is False
