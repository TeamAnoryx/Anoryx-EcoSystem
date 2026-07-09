"""Pure unit tests for D-016's greedy rebalance suggestion — no DB, no I/O."""

from __future__ import annotations

from delta.capacity.service import _greedy_rebalance, _MovableTask, _TeamSnapshot


def test_no_over_capacity_teams_no_suggestions() -> None:
    teams = [_TeamSnapshot("A", "Team A", capacity=10, remaining=5)]
    assert _greedy_rebalance(teams, []) == []


def test_over_and_under_team_with_exact_fit_task() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=15),  # 5 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=5),  # 5 spare
    ]
    tasks = [_MovableTask("t1", "Fix bug", story_points=5, team_id="A")]
    suggestions = _greedy_rebalance(teams, tasks)
    assert len(suggestions) == 1
    assert suggestions[0].task_id == "t1"
    assert suggestions[0].from_team_id == "A"
    assert suggestions[0].to_team_id == "B"


def test_no_under_capacity_teams_no_suggestions_even_with_movable_tasks() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=15),
        _TeamSnapshot("B", "Team B", capacity=10, remaining=10),  # exactly balanced, not under
    ]
    tasks = [_MovableTask("t1", "Fix bug", story_points=5, team_id="A")]
    assert _greedy_rebalance(teams, tasks) == []


def test_stops_after_one_move_once_excess_cleared() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=13),  # 3 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=5),  # 5 spare
    ]
    tasks = [
        _MovableTask("t1", "Small task", story_points=3, team_id="A"),
        _MovableTask("t2", "Big task", story_points=8, team_id="A"),
    ]
    suggestions = _greedy_rebalance(teams, tasks)
    # Largest-first: the 8-point task is tried before the 3-point one and alone
    # clears (overshoots) the 3-point excess, so the loop stops there — the
    # 3-point task is never suggested.
    assert len(suggestions) == 1
    assert suggestions[0].task_id == "t2"


def test_no_movable_tasks_for_over_team_yields_no_suggestion() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=15),
        _TeamSnapshot("B", "Team B", capacity=10, remaining=5),
    ]
    assert _greedy_rebalance(teams, []) == []


def test_largest_task_moved_first() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=20),  # 10 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=0),  # 10 spare
    ]
    tasks = [
        _MovableTask("small", "Small", story_points=2, team_id="A"),
        _MovableTask("big", "Big", story_points=8, team_id="A"),
    ]
    suggestions = _greedy_rebalance(teams, tasks)
    assert suggestions[0].task_id == "big"


def test_picks_under_team_with_most_spare_capacity() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=15),  # 5 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=8),  # 2 spare
        _TeamSnapshot("C", "Team C", capacity=10, remaining=2),  # 8 spare
    ]
    tasks = [_MovableTask("t1", "Task", story_points=4, team_id="A")]
    suggestions = _greedy_rebalance(teams, tasks)
    assert suggestions[0].to_team_id == "C"


def test_exactly_balanced_team_is_neither_source_nor_target() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=15),  # 5 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=10),  # exactly balanced
        _TeamSnapshot("C", "Team C", capacity=10, remaining=5),  # 5 spare
    ]
    tasks = [_MovableTask("t1", "Task", story_points=5, team_id="A")]
    suggestions = _greedy_rebalance(teams, tasks)
    assert len(suggestions) == 1
    assert suggestions[0].to_team_id == "C"


def test_multiple_over_teams_each_get_suggestions_independently() -> None:
    teams = [
        _TeamSnapshot("A", "Team A", capacity=10, remaining=13),  # 3 over
        _TeamSnapshot("B", "Team B", capacity=10, remaining=12),  # 2 over
        _TeamSnapshot("C", "Team C", capacity=10, remaining=0),  # 10 spare
    ]
    tasks = [
        _MovableTask("a1", "A task", story_points=3, team_id="A"),
        _MovableTask("b1", "B task", story_points=2, team_id="B"),
    ]
    suggestions = _greedy_rebalance(teams, tasks)
    assert {s.task_id for s in suggestions} == {"a1", "b1"}
    assert all(s.to_team_id == "C" for s in suggestions)
