"""Transient vs permanent classification (UNIT, no DB) — ADR-0004 Fork 5 / ADR-0026.

A DOWN database surfaces as OSError (ConnectionRefusedError) or a SQLAlchemy
OperationalError / InterfaceError / TimeoutError — all TRANSIENT (retry, never
dead-letter). A schema/logic failure (ValueError / PermanentIngestError) is PERMANENT.
``is_transient`` also walks the ``__cause__`` / ``__context__`` chain so a driver OSError
wrapped in a higher-level error is still classified transient.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.exc import InterfaceError, OperationalError

from delta.ingest.errors import DeadLetterReason, PermanentIngestError, is_transient


@pytest.mark.parametrize(
    "exc",
    [
        OSError("disk gone"),
        ConnectionRefusedError("connection refused"),
        ConnectionError("reset by peer"),
        TimeoutError("timed out"),
        asyncio.TimeoutError(),
    ],
)
def test_connectivity_errors_are_transient(exc):
    assert is_transient(exc) is True


def test_sqlalchemy_operational_error_is_transient():
    err = OperationalError("SELECT 1", None, Exception("server closed the connection"))
    assert is_transient(err) is True


def test_sqlalchemy_interface_error_is_transient():
    err = InterfaceError("connect", None, Exception("connection is closed"))
    assert is_transient(err) is True


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("bad value"),
        PermanentIngestError(DeadLetterReason.MALFORMED_PAYLOAD, "nope"),
        KeyError("missing"),
    ],
)
def test_logic_errors_are_not_transient(exc):
    assert is_transient(exc) is False


def test_wrapped_transient_cause_is_transient():
    # A non-transient surface error whose __cause__ is an OSError is still transient.
    def _boom() -> None:
        try:
            raise OSError("connection refused")
        except OSError as cause:
            raise ValueError("wrapper around a down DB") from cause

    with pytest.raises(ValueError) as exc:
        _boom()
    assert is_transient(exc.value) is True


def test_wrapped_transient_context_is_transient():
    # An implicit chain (__context__, no `from`) is also walked.
    def _boom() -> None:
        try:
            raise ConnectionRefusedError("down")
        except ConnectionRefusedError:
            raise ValueError("during handling of the down DB")  # noqa: B904 - implicit context

    with pytest.raises(ValueError) as exc:
        _boom()
    assert is_transient(exc.value) is True
