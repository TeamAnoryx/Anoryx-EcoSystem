"""Attribution unit tests (F-018, ADR-0021 §6, R4).

Vector covered:
  2  test_attribution_uses_server_identity — server-stamped fields only;
     a fabricated caller claim does NOT change attribution.

Pure unit tests — no DB, no I/O.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from shadow_ai.attribution import attribution_key

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _row(
    *,
    team_id: str = "team-server",
    project_id: str = "proj-server",
    detected_endpoint: str = "api.anthropic.com",
    selected_provider: str = "anthropic",
    # Caller-supplied claim fields that must NOT influence attribution
    caller_team: str = "caller-claimed-team",
    caller_agent: str = "caller-claimed-agent",
) -> Any:
    """Build a duck-typed row exposing server-stamped + caller fields."""
    return SimpleNamespace(
        team_id=team_id,
        project_id=project_id,
        detected_endpoint=detected_endpoint,
        selected_provider=selected_provider,
        # These caller-supplied fields exist on the object but must be ignored
        caller_team=caller_team,
        caller_agent=caller_agent,
    )


# ---------------------------------------------------------------------------
# Vector 2: attribution uses server identity; caller claim is irrelevant
# ---------------------------------------------------------------------------


class TestAttributionUsesServerIdentity:
    """ADR-0021 §9 vector 2 — attribution key reads ONLY server-stamped columns."""

    def test_key_uses_server_team_id(self) -> None:
        row = _row(team_id="real-server-team", caller_team="fake-caller-team")
        key = attribution_key(row)
        team, *_ = key
        assert team == "real-server-team"
        assert team != "fake-caller-team"

    def test_key_uses_server_project_id(self) -> None:
        row = _row(project_id="real-server-project")
        key = attribution_key(row)
        _, project, *_ = key
        assert project == "real-server-project"

    def test_key_uses_detected_endpoint(self) -> None:
        row = _row(detected_endpoint="api.openai.com")
        key = attribution_key(row)
        _, _, endpoint, _ = key
        assert endpoint == "api.openai.com"

    def test_key_uses_selected_provider(self) -> None:
        row = _row(selected_provider="openai")
        key = attribution_key(row)
        _, _, _, provider = key
        assert provider == "openai"

    def test_caller_claim_does_not_change_attribution(self) -> None:
        """Changing caller_team/caller_agent must NOT change the attribution key."""
        row_a = _row(team_id="server-team", caller_team="attacker-claim-A")
        row_b = _row(team_id="server-team", caller_team="attacker-claim-B")
        assert attribution_key(row_a) == attribution_key(row_b)

    def test_caller_agent_does_not_change_attribution(self) -> None:
        row_a = _row(team_id="server-team", caller_agent="agent-A")
        row_b = _row(team_id="server-team", caller_agent="agent-B")
        assert attribution_key(row_a) == attribution_key(row_b)

    def test_different_server_teams_produce_different_keys(self) -> None:
        row_a = _row(team_id="team-alpha")
        row_b = _row(team_id="team-beta")
        assert attribution_key(row_a) != attribution_key(row_b)

    def test_different_endpoints_produce_different_keys(self) -> None:
        row_a = _row(detected_endpoint="api.openai.com")
        row_b = _row(detected_endpoint="api.anthropic.com")
        assert attribution_key(row_a) != attribution_key(row_b)

    def test_key_is_a_4_tuple(self) -> None:
        row = _row()
        key = attribution_key(row)
        assert isinstance(key, tuple)
        assert len(key) == 4

    def test_none_endpoint_falls_back_to_empty_string(self) -> None:
        row = _row(detected_endpoint=None)  # type: ignore[arg-type]
        key = attribution_key(row)
        _, _, endpoint, _ = key
        assert endpoint == ""

    def test_none_provider_falls_back_to_empty_string(self) -> None:
        row = _row(selected_provider=None)  # type: ignore[arg-type]
        key = attribution_key(row)
        _, _, _, provider = key
        assert provider == ""

    def test_attribution_key_function_reads_only_four_columns(self) -> None:
        """attribution_key must only reference the four server-stamped column names."""
        import inspect

        import shadow_ai.attribution as attr_mod

        source = inspect.getsource(attr_mod.attribution_key)
        # Must reference these four
        assert "team_id" in source
        assert "project_id" in source
        assert "detected_endpoint" in source
        assert "selected_provider" in source
        # Must NOT reference caller/client-side fields
        forbidden = ["caller_team", "caller_agent", "request_body", "response_body"]
        for field in forbidden:
            assert field not in source, (
                f"attribution_key references caller field {field!r} — "
                "attribution must use only server-stamped columns (R4)."
            )
