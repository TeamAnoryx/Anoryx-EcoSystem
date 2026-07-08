"""D-007 fail-loud config resolution — pure unit, no DB."""

from __future__ import annotations

import pytest

from delta.allocation_admin.config import load_settings


def test_missing_token_fails_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DELTA_ADMIN_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="DELTA_ADMIN_TOKEN"):
        load_settings()


def test_configured_token_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DELTA_ADMIN_TOKEN", "a-token")
    settings = load_settings()
    assert settings.admin_token == "a-token"  # noqa: S105 — test value, not a secret
