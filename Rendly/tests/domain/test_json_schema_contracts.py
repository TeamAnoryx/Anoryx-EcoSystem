"""JSON Schema conformance: the domain types serialize to schema-valid payloads,
and the schema rejects malformed ones. Uses the jsonschema Draft 2020-12 idiom the
ecosystem contracts mandate (same as Delta D-001's test_json_schema_contracts).

Proves: (a) every object def is closed (additionalProperties:false), (b) canonical
Pydantic-serialized payloads validate, (c) malformed payloads (extra key,
out-of-shape id, missing tenant_id, bad enum) are rejected.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from rendly.channel import Channel
from rendly.enums import ChannelRole, ChannelType, OrgRole, PresenceStatus
from rendly.membership import Membership
from rendly.profile import Profile
from rendly.tenant import Tenant
from rendly.user import User

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "contracts" / "rendly-domain.schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_ISO = _NOW.isoformat()
_T = "12121212-1212-4212-8212-121212121212"
_U = "13131313-1313-4313-8313-131313131313"
_C = "14141414-1414-4414-8414-141414141414"


def _validator(defname: str) -> Draft202012Validator:
    # $ref + $defs sibling at root resolves internal #/$defs/... refs (Draft 2020-12).
    root = {"$ref": f"#/$defs/{defname}", "$defs": _SCHEMA["$defs"]}
    return Draft202012Validator(root, format_checker=Draft202012Validator.FORMAT_CHECKER)


# --- (a) schema is well-formed and every object def is closed --------------------
def test_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_SCHEMA)


def test_every_object_def_forbids_additional_properties():
    for name, definition in _SCHEMA["$defs"].items():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False, f"{name} not closed"


# --- (b) canonical payloads validate --------------------------------------------
def test_tenant_canonical_valid():
    t = Tenant(tenant_id=_T, created_at=_NOW)
    assert _validator("Tenant").is_valid(t.model_dump(mode="json"))


def test_user_canonical_valid():
    u = User(
        user_id=_U,
        tenant_id=_T,
        display_name="Alex",
        presence=PresenceStatus.ONLINE,
        created_at=_NOW,
    )
    errors = list(_validator("User").iter_errors(u.model_dump(mode="json")))
    assert errors == [], errors


def test_profile_canonical_valid():
    p = Profile(user_id=_U, tenant_id=_T, org_role=OrgRole.MEMBER, team="platform")
    assert _validator("Profile").is_valid(p.model_dump(mode="json"))


def test_channel_canonical_valid():
    c = Channel(
        channel_id=_C,
        tenant_id=_T,
        name="eng",
        type=ChannelType.PUBLIC,
        created_by=_U,
        created_at=_NOW,
    )
    errors = list(_validator("Channel").iter_errors(c.model_dump(mode="json")))
    assert errors == [], errors


def test_membership_canonical_valid():
    m = Membership(channel_id=_C, tenant_id=_T, user_id=_U, role=ChannelRole.OWNER, added_at=_NOW)
    assert _validator("Membership").is_valid(m.model_dump(mode="json"))


# --- (c) malformed payloads rejected --------------------------------------------
def test_extra_key_rejected_by_schema():
    payload = Tenant(tenant_id=_T, created_at=_NOW).model_dump(mode="json")
    payload["smuggled"] = "x"
    assert not _validator("Tenant").is_valid(payload)


def test_noncanonical_uuid_rejected_by_schema():
    assert not _validator("Tenant").is_valid({"tenant_id": "not-a-uuid", "created_at": _ISO})


def test_missing_tenant_id_rejected_by_schema():
    # A tenant-scoped shape without tenant_id is invalid (cross-tenant leakage guard).
    payload = {"channel_id": _C, "user_id": _U, "role": "owner", "added_at": _ISO}
    assert not _validator("Membership").is_valid(payload)


def test_bad_presence_rejected_by_schema():
    bad = {
        "user_id": _U,
        "tenant_id": _T,
        "display_name": "Alex",
        "presence": "dnd",
        "created_at": _ISO,
    }
    assert not _validator("User").is_valid(bad)


@pytest.mark.parametrize("defname", ["Tenant", "User", "Profile", "Channel", "Membership"])
def test_all_expected_defs_present(defname):
    assert defname in _SCHEMA["$defs"]
