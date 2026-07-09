"""Pure Pydantic validation tests for D-017 RBAC schemas — no DB, no I/O."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.rbac.schemas import AccessTokenCreateRequest, AccessTokenRevokeRequest

_TENANT = "11111111-1111-4111-8111-111111111111"


def test_token_create_accepts_valid_request() -> None:
    req = AccessTokenCreateRequest(tenant_id=_TENANT, name="CI viewer key", role="tenant_auditor")
    assert req.role == "tenant_auditor"


def test_token_create_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        AccessTokenCreateRequest(tenant_id=_TENANT, name="Key\n1", role="tenant_auditor")


def test_token_create_rejects_unknown_role() -> None:
    with pytest.raises(ValidationError):
        AccessTokenCreateRequest(tenant_id=_TENANT, name="Key", role="super_admin")


def test_token_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AccessTokenCreateRequest(
            tenant_id=_TENANT, name="Key", role="tenant_admin", unexpected="field"
        )


def test_token_create_rejects_empty_name() -> None:
    with pytest.raises(ValidationError):
        AccessTokenCreateRequest(tenant_id=_TENANT, name="", role="tenant_admin")


def test_token_revoke_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AccessTokenRevokeRequest(tenant_id=_TENANT, unexpected="field")
