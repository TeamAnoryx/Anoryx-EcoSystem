"""Shared fakes for judge-adapter tests (F-007).

A FakeProvider stands in for an F-006 ProviderAdapter's classify_structured: it
records the call kwargs and returns a canned (dict, tokens_in, tokens_out) or
raises a canned exception. No network, no real provider.
"""

from __future__ import annotations

from typing import Any

import pytest

from gateway.router.context import RoutingContext


class FakeProvider:
    """Records classify_structured calls; returns a canned result or raises."""

    def __init__(self, *, result: Any = None, exc: BaseException | None = None) -> None:
        self._result = result
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def classify_structured(
        self, *, system: str, user: str, schema: dict, model: str, ctx: Any
    ) -> tuple[dict, int, int]:
        self.calls.append(
            {"system": system, "user": user, "schema": schema, "model": model, "ctx": ctx}
        )
        if self._exc is not None:
            raise self._exc
        return self._result


@pytest.fixture()
def routing_ctx() -> RoutingContext:
    return RoutingContext(
        request_id="req-judge-test",
        resolved_provider="anthropic",
        resolved_model="claude-haiku-4-5",
        remaining_budget=5.0,
    )
