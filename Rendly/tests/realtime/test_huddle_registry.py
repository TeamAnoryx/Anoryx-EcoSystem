"""R-007 ``HuddleRegistry`` — pure unit tests (no DB, no WebSocket; state machine only).

Lives under ``tests/realtime`` alongside ``test_frames.py`` (also DB-gated at collection by
``conftest.py``, even though neither needs a database) so ``rendly.realtime`` stays measured in
ONE coverage lane (the ``rendly-db`` DB lane — see ``pyproject.toml`` / ``.coveragerc-persistence``
/ ``rendly-ci.yml``), matching the existing precedent.
"""

from __future__ import annotations

from rendly.realtime.huddle import (
    ACTIVE_STATES,
    TERMINAL_STATES,
    Huddle,
    HuddleRegistry,
    new_huddle_id,
)


def _huddle(**overrides: object) -> Huddle:
    defaults: dict = {
        "huddle_id": new_huddle_id(),
        "tenant_id": "t1",
        "inviter_user_id": "u1",
        "peer_user_id": "u2",
        "channel_id": None,
        "state": "ringing",
    }
    defaults.update(overrides)
    return Huddle(**defaults)


def test_new_huddle_id_is_a_uuid_string() -> None:
    hid = new_huddle_id()
    assert isinstance(hid, str)
    assert len(hid) == 36
    assert new_huddle_id() != hid  # not constant, not reused


def test_other_and_participants_and_is_participant() -> None:
    h = _huddle()
    assert h.other("u1") == "u2"
    assert h.other("u2") == "u1"
    assert h.participants() == ("u1", "u2")
    assert h.is_participant("u1") and h.is_participant("u2")
    assert not h.is_participant("stranger")


def test_active_and_terminal_state_sets_are_disjoint_and_cover_the_wire_enum() -> None:
    wire_states = {"ringing", "accepted", "active", "declined", "ended", "busy"}
    assert ACTIVE_STATES | TERMINAL_STATES == wire_states
    assert ACTIVE_STATES.isdisjoint(TERMINAL_STATES)


def test_create_registers_both_participants_as_busy() -> None:
    reg = HuddleRegistry()
    h = _huddle()
    reg.create(h)
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u1") == h.huddle_id
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u2") == h.huddle_id
    assert reg.get(h.huddle_id) is h


def test_transition_to_terminal_state_retires_both_participants() -> None:
    reg = HuddleRegistry()
    h = _huddle()
    reg.create(h)
    reg.transition(h.huddle_id, "ended")
    assert reg.get(h.huddle_id) is None
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u1") is None
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u2") is None


def test_transition_to_active_state_keeps_both_participants_busy() -> None:
    reg = HuddleRegistry()
    h = _huddle()
    reg.create(h)
    reg.transition(h.huddle_id, "accepted")
    assert reg.get(h.huddle_id).state == "accepted"
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u1") == h.huddle_id
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u2") == h.huddle_id


def test_transition_unknown_huddle_id_is_a_noop() -> None:
    reg = HuddleRegistry()
    assert reg.transition("does-not-exist", "ended") is None


def test_end_active_for_user_ends_and_returns_the_huddle() -> None:
    reg = HuddleRegistry()
    h = _huddle()
    reg.create(h)
    ended = reg.end_active_for_user(tenant_id="t1", user_id="u1")
    assert ended is h
    assert ended.state == "ended"
    assert reg.get(h.huddle_id) is None
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u2") is None


def test_end_active_for_user_with_no_session_returns_none() -> None:
    reg = HuddleRegistry()
    assert reg.end_active_for_user(tenant_id="t1", user_id="ghost") is None


def test_next_seq_is_monotonic_per_tenant_and_independent_across_tenants() -> None:
    reg = HuddleRegistry()
    assert [reg.next_seq("t1") for _ in range(3)] == [0, 1, 2]
    assert reg.next_seq("t2") == 0  # a different tenant starts its own counter at 0


def test_one_active_session_per_user_is_enforceable_by_the_caller() -> None:
    """The registry does not itself reject a second create() — the pipeline checks
    active_huddle_id_for() BEFORE calling create() (see pipeline.handle_huddle_invite). This test
    documents that contract: a caller who skips the check can still corrupt the busy index."""
    reg = HuddleRegistry()
    h1 = _huddle(huddle_id="h1")
    reg.create(h1)
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u1") == "h1"
    h2 = _huddle(huddle_id="h2", inviter_user_id="u1", peer_user_id="u3")
    reg.create(h2)  # not gated by the registry itself
    # The busy index now points at the LAST create() for u1 — proving callers must gate with
    # active_huddle_id_for() first, which the pipeline does.
    assert reg.active_huddle_id_for(tenant_id="t1", user_id="u1") == "h2"
