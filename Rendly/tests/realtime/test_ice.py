"""R-007 ``IceServerConfig`` / ``build_ice_servers`` — pure unit tests (no DB, no HTTP).

Lives under ``tests/realtime`` for the same coverage-lane reason as ``test_huddle_registry.py``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from rendly.realtime.ice import IceServerConfig, build_ice_servers

_NOW = 1_700_000_000


def test_empty_config_returns_no_servers_but_a_valid_ttl() -> None:
    config = IceServerConfig()
    body = build_ice_servers(config, user_id="u1", now_epoch=_NOW)
    assert body["ice_servers"] == []
    assert body["ttl_seconds"] == 600


def test_stun_only_config_never_carries_a_username_or_credential() -> None:
    config = IceServerConfig(stun_urls=("stun:turn.internal:3478",))
    body = build_ice_servers(config, user_id="u1", now_epoch=_NOW)
    assert body["ice_servers"] == [
        {"urls": ["stun:turn.internal:3478"], "username": None, "credential": None}
    ]


def test_turn_without_a_secret_is_never_issued() -> None:
    """A TURN url with no shared secret configured must NOT be handed out (no fabricated cred)."""
    config = IceServerConfig(turn_urls=("turn:turn.internal:3478",), turn_secret=None)
    body = build_ice_servers(config, user_id="u1", now_epoch=_NOW)
    assert body["ice_servers"] == []


def test_turn_with_secret_issues_a_short_lived_hmac_credential() -> None:
    config = IceServerConfig(
        turn_urls=("turn:turn.internal:3478",), turn_secret="s3cr3t", ttl_seconds=120
    )
    body = build_ice_servers(config, user_id="user-42", now_epoch=_NOW)
    assert len(body["ice_servers"]) == 1
    entry = body["ice_servers"][0]
    assert entry["urls"] == ["turn:turn.internal:3478"]
    expected_username = f"{_NOW + 120}:user-42"
    assert entry["username"] == expected_username
    expected_credential = base64.b64encode(
        hmac.new(b"s3cr3t", expected_username.encode(), hashlib.sha1).digest()
    ).decode("ascii")
    assert entry["credential"] == expected_credential
    assert body["ttl_seconds"] == 120


def test_stun_and_turn_can_both_be_present() -> None:
    config = IceServerConfig(
        stun_urls=("stun:turn.internal:3478",),
        turn_urls=("turn:turn.internal:3478",),
        turn_secret="s3cr3t",
    )
    body = build_ice_servers(config, user_id="u1", now_epoch=_NOW)
    assert len(body["ice_servers"]) == 2


def test_credential_differs_per_user_and_is_never_reused() -> None:
    config = IceServerConfig(turn_urls=("turn:turn.internal:3478",), turn_secret="s3cr3t")
    a = build_ice_servers(config, user_id="alice", now_epoch=_NOW)["ice_servers"][0]
    b = build_ice_servers(config, user_id="bob", now_epoch=_NOW)["ice_servers"][0]
    assert a["username"] != b["username"]
    assert a["credential"] != b["credential"]


@pytest.mark.parametrize(
    "env,expected",
    [
        ({}, 600),
        ({"RENDLY_ICE_TTL_SECONDS": "120"}, 120),
        ({"RENDLY_ICE_TTL_SECONDS": "not-a-number"}, 600),  # malformed -> safe default
        ({"RENDLY_ICE_TTL_SECONDS": "999999"}, 86400),  # clamped to the contract-locked max
        ({"RENDLY_ICE_TTL_SECONDS": "0"}, 1),  # clamped to the contract-locked min
    ],
)
def test_from_env_ttl_parsing_is_bounded_and_fails_safe(monkeypatch, env, expected) -> None:
    monkeypatch.delenv("RENDLY_ICE_TTL_SECONDS", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert IceServerConfig.from_env().ttl_seconds == expected


def test_from_env_reads_comma_separated_urls(monkeypatch) -> None:
    monkeypatch.setenv("RENDLY_STUN_URLS", "stun:a:3478, stun:b:3478")
    monkeypatch.setenv("RENDLY_TURN_URLS", "turn:c:3478")
    monkeypatch.setenv("RENDLY_TURN_SECRET", "sek")
    config = IceServerConfig.from_env()
    assert config.stun_urls == ("stun:a:3478", "stun:b:3478")
    assert config.turn_urls == ("turn:c:3478",)
    assert config.turn_secret == "sek"


def test_from_env_defaults_to_no_servers_when_unset(monkeypatch) -> None:
    for var in ("RENDLY_STUN_URLS", "RENDLY_TURN_URLS", "RENDLY_TURN_SECRET"):
        monkeypatch.delenv(var, raising=False)
    config = IceServerConfig.from_env()
    assert config.stun_urls == ()
    assert config.turn_urls == ()
    assert config.turn_secret is None
