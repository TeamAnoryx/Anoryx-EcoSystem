"""Pure unit tests for D-017's role-rank check — no DB, no I/O."""

from __future__ import annotations

from delta.rbac.service import role_at_least


def test_admin_satisfies_admin_minimum() -> None:
    assert role_at_least("tenant_admin", "tenant_admin") is True


def test_admin_satisfies_auditor_minimum() -> None:
    assert role_at_least("tenant_admin", "tenant_auditor") is True


def test_auditor_satisfies_auditor_minimum() -> None:
    assert role_at_least("tenant_auditor", "tenant_auditor") is True


def test_auditor_does_not_satisfy_admin_minimum() -> None:
    assert role_at_least("tenant_auditor", "tenant_admin") is False


def test_unrecognized_actual_role_fails_closed() -> None:
    assert role_at_least("bogus_role", "tenant_auditor") is False


def test_unrecognized_minimum_role_fails_closed() -> None:
    assert role_at_least("tenant_admin", "bogus_role") is False


def test_both_unrecognized_fails_closed() -> None:
    assert role_at_least("bogus", "also_bogus") is False


def test_empty_string_role_fails_closed() -> None:
    assert role_at_least("", "tenant_auditor") is False
