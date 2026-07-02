"""R-006 role-based channel authorization + manual team mapping — non-stubbed e2e on real Postgres.

The deliverable of R-006 is correct ACCESS CONTROL, so authorization IS the headline test surface.
Every integration test drives the REAL chat app (Starlette TestClient = the real ASGI HTTP + WS,
not a stub) against a REAL local Postgres, and asserts on the live authz outcome / live DB row.

Proven here:
  * AUTHORIZATION MATRIX (pure + integration): the permitted role x type x action cells succeed and
    the forbidden ones are DENIED — a guest cannot post; a non-member cannot read a private channel;
    only a channel owner/admin (NOT a bare ``channels:admin`` scope) can manage members / map to a
    team; a member cannot self-escalate via mapping; a DM cannot be team-mapped.
  * SECURITY SPINE (tenant): cross-tenant management/read stays denied (R-005 RLS intact, not
    weakened by the mapping layer); a forged-tenant token gets zero rows; a shared ``external_ref``
    label is NOT a cross-tenant access vector.
  * SAME DECISION EVERYWHERE: the WS path and the REST path reach the SAME authz outcome for the
    same (principal, channel) — both call the ONE decision point.
  * RESOLVER SEAM: the manual resolver returns admin-managed membership; an unresolvable / raising
    resolver FAILS CLOSED (even the owner is denied — no phantom members, no open access).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from chatdata import RaisingResolver, UnresolvableResolver, recv_until

_FULL = "channels:write channels:admin chat:read chat:write"
_REALTIME = "/v1/realtime"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_channel(client, token: str, *, ctype: str = "private", name: str = "c") -> str:
    resp = client.post("/v1/channels", json={"name": name, "type": ctype}, headers=_auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()["channel_id"]


def _add_member(client, owner_token: str, channel_id: str, user_id: str, role: str) -> None:
    resp = client.put(
        f"/v1/channels/{channel_id}/members/{user_id}",
        json={"role": role},
        headers=_auth(owner_token),
    )
    assert resp.status_code == 200, resp.text


def _channel_row(tenant_id: str, channel_id: str):
    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as session:
        return (
            session.execute(
                text(
                    "SELECT source, external_ref, type FROM rendly.channels "
                    "WHERE tenant_id=:t AND channel_id=:c"
                ),
                {"t": tenant_id, "c": channel_id},
            )
            .mappings()
            .first()
        )


# --- the PURE permission matrix (no DB) — evaluate(type, role, action) -----------------------------

from rendly.enums import ChannelRole, ChannelType  # noqa: E402
from rendly.realtime.authz import ChannelAction, evaluate  # noqa: E402

_MEMBER_ROLES = [ChannelRole.OWNER, ChannelRole.ADMIN, ChannelRole.MEMBER, ChannelRole.GUEST]
_TYPES = [ChannelType.PUBLIC, ChannelType.PRIVATE, ChannelType.DM]


def test_matrix_non_member_is_denied_every_action():
    for channel_type in _TYPES:
        for action in ChannelAction:
            assert evaluate(channel_type, None, action) is False


def test_matrix_read_requires_membership_any_role():
    for channel_type in _TYPES:
        for role in _MEMBER_ROLES:
            assert evaluate(channel_type, role, ChannelAction.READ) is True
        assert evaluate(channel_type, None, ChannelAction.READ) is False


def test_matrix_post_allows_member_up_denies_guest_and_non_member():
    for channel_type in _TYPES:
        for role in (ChannelRole.OWNER, ChannelRole.ADMIN, ChannelRole.MEMBER):
            assert evaluate(channel_type, role, ChannelAction.POST) is True
        assert evaluate(channel_type, ChannelRole.GUEST, ChannelAction.POST) is False
        assert evaluate(channel_type, None, ChannelAction.POST) is False


def test_matrix_manage_and_map_are_owner_admin_only_and_never_on_dm():
    for action in (ChannelAction.MANAGE_MEMBERS, ChannelAction.MAP_TO_TEAM):
        for channel_type in (ChannelType.PUBLIC, ChannelType.PRIVATE):
            assert evaluate(channel_type, ChannelRole.OWNER, action) is True
            assert evaluate(channel_type, ChannelRole.ADMIN, action) is True
            assert evaluate(channel_type, ChannelRole.MEMBER, action) is False
            assert evaluate(channel_type, ChannelRole.GUEST, action) is False
            assert evaluate(channel_type, None, action) is False
        # A DM's roster is its two participants — not administrable or mappable by ANY role.
        for role in [*_MEMBER_ROLES, None]:
            assert evaluate(ChannelType.DM, role, action) is False


def test_authorize_denies_on_tenant_mismatch_before_touching_the_resolver():
    """Defense in depth over RLS: a channel from another tenant handed to a principal fails closed on
    the tenant guard BEFORE the resolver/session is consulted (``session=None`` proves it)."""
    from rendly.channel import Channel
    from rendly.enums import ChannelSource
    from rendly.realtime.authz import AuthzPrincipal, authorize

    channel = Channel(
        channel_id="11111111-1111-1111-1111-111111111111",
        tenant_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        name="c",
        type=ChannelType.PRIVATE,
        source=ChannelSource.MANUAL,
        external_ref=None,
        created_by="22222222-2222-2222-2222-222222222222",
        created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        archived=False,
    )
    principal = AuthzPrincipal(
        tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        user_id="22222222-2222-2222-2222-222222222222",
        scopes=frozenset({"chat:read"}),
    )
    decision = asyncio.run(
        authorize(
            None,
            principal=principal,
            channel=channel,
            action=ChannelAction.READ,
            resolver=UnresolvableResolver(),
        )
    )
    assert decision.allowed is False
    assert decision.reason == "tenant"


# --- manage-members requires the channel owner/admin ROLE, not a bare scope (the closed hole) ------


def test_manage_members_requires_channel_role_not_bare_admin_scope(
    make_client, seed_user, mint_token, new_uuid
):
    """A MEMBER holding the ``channels:admin`` scope cannot manage members — R-006 requires the
    per-channel owner/admin role. The owner can. Closes R-005's bare-scope hole."""
    tenant, owner, member, target = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for user in (owner, member, target):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    _add_member(client, owner_tok, cid, member, "member")
    member_admin_tok = mint_token(
        user_id=member, tenant_id=tenant, scope="channels:admin chat:read"
    )
    denied = client.put(
        f"/v1/channels/{cid}/members/{target}",
        json={"role": "member"},
        headers=_auth(member_admin_tok),
    )
    assert denied.status_code == 404  # role deny, no oracle
    allowed = client.put(
        f"/v1/channels/{cid}/members/{target}", json={"role": "member"}, headers=_auth(owner_tok)
    )
    assert allowed.status_code == 200


def test_non_member_with_admin_scope_cannot_manage_private_channel(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, owner, outsider, target = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for user in (owner, outsider, target):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    outsider_tok = mint_token(user_id=outsider, tenant_id=tenant, scope="channels:admin chat:read")
    resp = client.put(
        f"/v1/channels/{cid}/members/{target}", json={"role": "member"}, headers=_auth(outsider_tok)
    )
    assert resp.status_code == 404


def test_channel_admin_role_can_manage_members(make_client, seed_user, mint_token, new_uuid):
    tenant, owner, chan_admin, target = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for user in (owner, chan_admin, target):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    _add_member(client, owner_tok, cid, chan_admin, "admin")
    admin_tok = mint_token(user_id=chan_admin, tenant_id=tenant, scope="channels:admin chat:read")
    resp = client.put(
        f"/v1/channels/{cid}/members/{target}", json={"role": "member"}, headers=_auth(admin_tok)
    )
    assert resp.status_code == 200


# --- manual team mapping ---------------------------------------------------------------------------


def test_owner_maps_channel_to_team_sets_source_and_external_ref(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, owner = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=owner)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    resp = client.put(
        f"/v1/channels/{cid}/team",
        json={"external_ref": "delta.team.eng-42"},
        headers=_auth(owner_tok),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == "delta_team"
    assert body["external_ref"] == "delta.team.eng-42"
    row = _channel_row(tenant, cid)
    assert row["source"] == "delta_team"
    assert row["external_ref"] == "delta.team.eng-42"


def test_member_cannot_map_channel_to_team_no_self_escalation(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, owner, member = new_uuid(), new_uuid(), new_uuid()
    for user in (owner, member):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    _add_member(client, owner_tok, cid, member, "member")
    member_tok = mint_token(user_id=member, tenant_id=tenant, scope="channels:admin chat:read")
    resp = client.put(
        f"/v1/channels/{cid}/team", json={"external_ref": "team.x"}, headers=_auth(member_tok)
    )
    assert resp.status_code == 404
    row = _channel_row(tenant, cid)
    assert row["source"] == "manual"  # unchanged — no self-escalation into a mapping
    assert row["external_ref"] is None


def test_dm_channel_cannot_be_team_mapped(make_client, seed_user, mint_token, new_uuid):
    tenant, owner = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=owner)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok, ctype="dm")
    resp = client.put(
        f"/v1/channels/{cid}/team", json={"external_ref": "team.x"}, headers=_auth(owner_tok)
    )
    assert resp.status_code == 404  # matrix denies mapping a DM (no oracle)
    assert _channel_row(tenant, cid)["source"] == "manual"


def test_map_rejects_invalid_external_ref(make_client, seed_user, mint_token, new_uuid):
    tenant, owner = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=owner)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    resp = client.put(
        f"/v1/channels/{cid}/team",
        json={"external_ref": "bad ref!with spaces"},
        headers=_auth(owner_tok),
    )
    assert resp.status_code == 400  # closed-schema / pattern violation -> Error envelope 400


def test_mapped_channel_membership_stays_admin_managed_and_role_enforced(
    make_client, seed_user, mint_token, new_uuid
):
    """After mapping to a team label the manual resolver treats ``external_ref`` as OPAQUE: membership
    is still the admin-managed set — an admin-added member reads, an outsider is denied."""
    tenant, owner, member, outsider = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for user in (owner, member, outsider):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    assert (
        client.put(
            f"/v1/channels/{cid}/team",
            json={"external_ref": "delta.team.x"},
            headers=_auth(owner_tok),
        ).status_code
        == 200
    )
    _add_member(client, owner_tok, cid, member, "member")
    member_tok = mint_token(user_id=member, tenant_id=tenant, scope="chat:read")
    outsider_tok = mint_token(user_id=outsider, tenant_id=tenant, scope="chat:read")
    assert client.get(f"/v1/channels/{cid}/messages", headers=_auth(member_tok)).status_code == 200
    assert (
        client.get(f"/v1/channels/{cid}/messages", headers=_auth(outsider_tok)).status_code == 404
    )


# --- guest is read-only; non-member cannot read ---------------------------------------------------


def test_guest_can_read_but_cannot_post(make_client, seed_user, mint_token, new_uuid):
    tenant, owner, guest = new_uuid(), new_uuid(), new_uuid()
    for user in (owner, guest):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    _add_member(client, owner_tok, cid, guest, "guest")
    guest_tok = mint_token(user_id=guest, tenant_id=tenant, scope="chat:read chat:write")
    assert client.get(f"/v1/channels/{cid}/messages", headers=_auth(guest_tok)).status_code == 200
    with client.websocket_connect(_REALTIME, headers=_auth(guest_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {"msg_type": "chat.send", "client_msg_id": "g1", "channel_id": cid, "content": "hi"}
        )
        assert recv_until(ws, "error")["error_code"] == "unauthorized"


def test_non_member_denied_read_of_private_channel(make_client, seed_user, mint_token, new_uuid):
    tenant, owner, outsider = new_uuid(), new_uuid(), new_uuid()
    for user in (owner, outsider):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    outsider_tok = mint_token(user_id=outsider, tenant_id=tenant, scope="chat:read")
    assert (
        client.get(f"/v1/channels/{cid}/messages", headers=_auth(outsider_tok)).status_code == 404
    )


# --- tenant spine: the mapping layer opens no cross-tenant path ------------------------------------


def test_forged_tenant_token_cannot_manage_read_or_map_another_tenants_channel(
    make_client, seed_user, mint_token, new_uuid
):
    """A token for tenant B (even with FULL scope) cannot read / manage / map tenant A's channel: the
    channel is invisible under B's RLS (load -> None -> 404). The mapping layer weakens nothing."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    client = make_client()
    a_tok = mint_token(user_id=ua, tenant_id=ta, scope=_FULL)
    cid = _create_channel(client, a_tok)
    b_tok = mint_token(user_id=ub, tenant_id=tb, scope=_FULL)
    assert client.get(f"/v1/channels/{cid}/messages", headers=_auth(b_tok)).status_code == 404
    assert (
        client.put(
            f"/v1/channels/{cid}/members/{ub}", json={"role": "member"}, headers=_auth(b_tok)
        ).status_code
        == 404
    )
    assert (
        client.put(
            f"/v1/channels/{cid}/team", json={"external_ref": "team.x"}, headers=_auth(b_tok)
        ).status_code
        == 404
    )
    assert _channel_row(ta, cid)["source"] == "manual"  # tenant A's channel untouched


def test_shared_external_ref_label_is_not_a_cross_tenant_access_vector(
    make_client, seed_user, mint_token, new_uuid
):
    """Two tenants may map channels to the SAME opaque label; membership stays tenant-scoped (RLS), so
    the shared label grants no cross-tenant access."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    client = make_client()
    a_tok = mint_token(user_id=ua, tenant_id=ta, scope=_FULL)
    b_tok = mint_token(user_id=ub, tenant_id=tb, scope=_FULL)
    ca = _create_channel(client, a_tok, name="A")
    cb = _create_channel(client, b_tok, name="B")
    label = "delta.team.shared"
    assert (
        client.put(
            f"/v1/channels/{ca}/team", json={"external_ref": label}, headers=_auth(a_tok)
        ).status_code
        == 200
    )
    assert (
        client.put(
            f"/v1/channels/{cb}/team", json={"external_ref": label}, headers=_auth(b_tok)
        ).status_code
        == 200
    )
    # ua (tenant A) is NOT a member of cb (tenant B) despite the shared label -> 404.
    a_read_tok = mint_token(user_id=ua, tenant_id=ta, scope="chat:read")
    assert client.get(f"/v1/channels/{cb}/messages", headers=_auth(a_read_tok)).status_code == 404


# --- the WS path and the REST path reach the SAME decision -----------------------------------------


def test_ws_and_rest_reach_the_same_authz_decision(make_client, seed_user, mint_token, new_uuid):
    """A member is allowed on BOTH paths (REST read 200 + WS post accepted); a non-member is denied on
    BOTH (REST read 404 + WS post unauthorized). Both paths call the ONE decision point."""
    tenant, owner, member, outsider = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for user in (owner, member, outsider):
        seed_user(tenant_id=tenant, user_id=user)
    client = make_client()
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)
    _add_member(client, owner_tok, cid, member, "member")
    member_tok = mint_token(user_id=member, tenant_id=tenant, scope="chat:read chat:write")
    outsider_tok = mint_token(user_id=outsider, tenant_id=tenant, scope="chat:read chat:write")

    # MEMBER: allowed on both paths.
    assert client.get(f"/v1/channels/{cid}/messages", headers=_auth(member_tok)).status_code == 200
    with client.websocket_connect(_REALTIME, headers=_auth(member_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {"msg_type": "chat.send", "client_msg_id": "m1", "channel_id": cid, "content": "hi"}
        )
        assert recv_until(ws, "chat.ack")["status"] == "accepted"

    # NON-MEMBER: denied on both paths.
    assert (
        client.get(f"/v1/channels/{cid}/messages", headers=_auth(outsider_tok)).status_code == 404
    )
    with client.websocket_connect(_REALTIME, headers=_auth(outsider_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {"msg_type": "chat.send", "client_msg_id": "o1", "channel_id": cid, "content": "hi"}
        )
        assert recv_until(ws, "error")["error_code"] == "unauthorized"


# --- resolver seam fails closed --------------------------------------------------------------------


@pytest.mark.parametrize("resolver", [UnresolvableResolver(), RaisingResolver()])
def test_resolver_failure_fails_closed_even_for_the_owner(
    make_client, seed_user, mint_token, new_uuid, resolver
):
    """An unresolvable / raising resolver -> the authz point DENIES even the real owner: no phantom
    members, no open access. Channel CREATE (scope-only, not resolver-gated) still works, but every
    resolver-gated action (read / manage / map / post) is denied."""
    tenant, owner, other = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=owner)
    seed_user(tenant_id=tenant, user_id=other)
    client = make_client(resolver=resolver)
    owner_tok = mint_token(user_id=owner, tenant_id=tenant, scope=_FULL)
    cid = _create_channel(client, owner_tok)  # create is scope-only -> still works
    assert client.get(f"/v1/channels/{cid}/messages", headers=_auth(owner_tok)).status_code == 404
    assert (
        client.put(
            f"/v1/channels/{cid}/members/{other}", json={"role": "member"}, headers=_auth(owner_tok)
        ).status_code
        == 404
    )
    assert (
        client.put(
            f"/v1/channels/{cid}/team", json={"external_ref": "team.x"}, headers=_auth(owner_tok)
        ).status_code
        == 404
    )
    with client.websocket_connect(_REALTIME, headers=_auth(owner_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {"msg_type": "chat.send", "client_msg_id": "x1", "channel_id": cid, "content": "hi"}
        )
        assert recv_until(ws, "error")["error_code"] == "unauthorized"
