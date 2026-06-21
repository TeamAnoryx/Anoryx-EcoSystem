"""Per-tenant IdP-config + group→role-mapping admin routes (F-014 STEP 3, ADR-0017 D3/D6).

Mounted under admin_router (so EVERY route inherits require_admin — the existing
env-token BREAK-GLASS path; the operator-session SSO branch is a LATER step, not
STEP 3). Each route also runs validate_tenant_id_path and opens
get_tenant_session(TARGET) so RLS scopes every read/write to the named tenant.

R6 (encrypt-at-rest, never to browser/logs/audit):
  - POST accepts client_secret / sp_private_key in the body; the repository
    encrypts them via secret_box BEFORE storing (the route never touches the
    bytes again). If the encryption key is unavailable the write fails-closed
    (503) and NOTHING is stored.
  - GET / POST responses return METADATA ONLY (client_secret_set / sp_private_key_set
    booleans) — NEVER the secret, NEVER the ciphertext.
  - idp_config_changed audit rows (emit_sso_event on a SEPARATE privileged
    session, agent_id="admin-console", actor_id=None for break-glass) carry NO
    secret material. Mutate-then-audit (the F-012a accepted-residual pattern).
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from admin.scope import enforce_admin_scope
from admin.sso.audit import ADMIN_CONSOLE_PRINCIPAL, OPERATOR_SSO_PRINCIPAL, emit_sso_event
from admin.sso.secret_box import IdpSecretKeyError
from admin.util import actor_id, parse_body, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.idp_config_repository import IdpConfigRepository
from persistence.repositories.idp_group_role_map_repository import (
    IdpGroupRoleMapRepository,
)

# Router deps: validate the path tenant_id, then enforce the operator's tenant-pin
# + role (ADR-0017 §3 D2). Now that SSO tenant_admins exist these routes may be
# reached by an SSO operator (own tenant, tenant_admin) OR break-glass — both
# allowed by enforce_admin_scope. require_admin runs at the parent admin_router.
idp_router = APIRouter(
    tags=["admin", "sso"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)

_ROLE_VALUES = ("tenant_admin", "tenant_auditor")
_IDP_GROUP_RE = re.compile(r"^[\w .:/@-]{1,256}$")

_SERVICE_UNAVAILABLE = 503


def _attribution(request: Request) -> tuple[str, str | None]:
    """Return (agent_id slug, actor_id) for the idp_config_changed event (D9).

    Now that SSO tenant_admins can reach these routes (enforce_admin_scope), the
    acting principal may be an SSO operator OR break-glass:
      * SSO operator -> agent_id="operator-sso", actor_id=the operator's
        admin_users.id (honest per-operator attribution, vector 16).
      * break-glass  -> agent_id="admin-console", actor_id=None (exact STEP-3
        behavior; no per-operator identity).
    """
    aid = actor_id(request)
    if aid is not None:
        return OPERATOR_SSO_PRINCIPAL, aid
    return ADMIN_CONSOLE_PRINCIPAL, None


# --------------------------------------------------------------------------- #
# Request / response schemas (extra='forbid' — closed input, R8).
# Secrets are WRITE-ONLY inputs; no response model carries them (R6).
# --------------------------------------------------------------------------- #
class IdpConfigUpsertRequest(BaseModel):
    """Create/update an IdP config. client_secret / sp_private_key are write-only.

    Only the non-secret metadata is echoed back (via the repository's metadata
    projection). The two secret fields are encrypted at rest and never returned.
    """

    model_config = ConfigDict(extra="forbid")

    protocol: str = Field(max_length=8)
    # OIDC
    issuer: str | None = Field(default=None, max_length=2048)
    client_id: str | None = Field(default=None, max_length=2048)
    client_secret: str | None = Field(default=None, max_length=4096, repr=False)
    scopes: str | None = Field(default=None, max_length=2048)
    # SAML
    idp_entity_id: str | None = Field(default=None, max_length=2048)
    idp_sso_url: str | None = Field(default=None, max_length=2048)
    idp_x509_cert: str | None = Field(default=None, max_length=16384)
    sp_acs_url: str | None = Field(default=None, max_length=2048)
    audience: str | None = Field(default=None, max_length=2048)
    sp_private_key: str | None = Field(default=None, max_length=16384, repr=False)

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, v: str) -> str:
        if v not in ("oidc", "saml"):
            raise ValueError("protocol must be 'oidc' or 'saml'")
        return v


class IdpGroupMappingRequest(BaseModel):
    """Set a single IdP group → role mapping."""

    model_config = ConfigDict(extra="forbid")

    idp_group: str = Field(max_length=256)
    role: str = Field(max_length=32)

    @field_validator("idp_group")
    @classmethod
    def _group(cls, v: str) -> str:
        if not _IDP_GROUP_RE.match(v):
            raise ValueError("idp_group has invalid characters")
        return v

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in _ROLE_VALUES:
            raise ValueError(f"role must be one of {_ROLE_VALUES!r}")
        return v


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@idp_router.post(
    "/tenants/{tenant_id}/idp",
    status_code=status.HTTP_201_CREATED,
)
async def upsert_idp_config(tenant_id: str, request: Request) -> dict:
    """Create/update the target tenant's IdP config. Returns METADATA only (R6).

    The body's client_secret / sp_private_key (if present) are encrypted at rest
    by the repository before storage and are NEVER echoed back. Emits
    idp_config_changed via break-glass attribution (agent_id="admin-console",
    actor_id=None) on a separate privileged session (mutate-then-audit).
    """
    body = await parse_body(request, IdpConfigUpsertRequest)
    rid = request_id(request)

    non_secret = {
        k: v
        for k, v in (
            ("issuer", body.issuer),
            ("client_id", body.client_id),
            ("scopes", body.scopes),
            ("idp_entity_id", body.idp_entity_id),
            ("idp_sso_url", body.idp_sso_url),
            ("idp_x509_cert", body.idp_x509_cert),
            ("sp_acs_url", body.sp_acs_url),
            ("audience", body.audience),
        )
    }

    async with get_tenant_session(tenant_id) as ts:
        repo = IdpConfigRepository(ts)
        try:
            # The repo encrypts the two secrets via secret_box BEFORE storing.
            await repo.upsert(
                tenant_id=tenant_id,
                protocol=body.protocol,
                caller_tenant_id=tenant_id,
                client_secret_plaintext=body.client_secret,
                sp_private_key_plaintext=body.sp_private_key,
                **non_secret,
            )
        except IdpSecretKeyError:
            # Fail-closed (R6): the encryption key is unavailable — refuse the
            # write rather than store a config with a plaintext/absent secret.
            # The transaction is not committed, so nothing persists.
            raise HTTPException(
                status_code=_SERVICE_UNAVAILABLE, detail="idp_secret_encryption_unavailable"
            ) from None
        meta = await repo.get_metadata(
            tenant_id=tenant_id, protocol=body.protocol, caller_tenant_id=tenant_id
        )
        await ts.commit()

    agent_slug, aid = _attribution(request)
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_sso_event(
                ps,
                event_type="idp_config_changed",
                target_tenant_id=tenant_id,
                request_id=rid,
                agent_id=agent_slug,  # operator-sso (SSO) or admin-console (break-glass)
                actor_id=aid,  # the operator's admin_users.id for SSO; None for break-glass
            )
    return {"config": meta}


@idp_router.get("/tenants/{tenant_id}/idp")
async def list_idp_config(tenant_id: str) -> dict:
    """List the target tenant's active IdP config metadata. NEVER secrets (R6)."""
    async with get_tenant_session(tenant_id) as ts:
        configs = await IdpConfigRepository(ts).list_for_tenant(
            tenant_id=tenant_id, caller_tenant_id=tenant_id
        )
    return {"configs": configs, "count": len(configs)}


@idp_router.post(
    "/tenants/{tenant_id}/idp/groups",
    status_code=status.HTTP_201_CREATED,
)
async def set_group_mapping(tenant_id: str, request: Request) -> dict:
    """Set a group→role mapping for the target tenant. Emits idp_config_changed."""
    body = await parse_body(request, IdpGroupMappingRequest)
    rid = request_id(request)

    async with get_tenant_session(tenant_id) as ts:
        repo = IdpGroupRoleMapRepository(ts)
        await repo.set_mapping(
            tenant_id=tenant_id,
            idp_group=body.idp_group,
            role=body.role,
            caller_tenant_id=tenant_id,
        )
        await ts.commit()

    agent_slug, aid = _attribution(request)
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_sso_event(
                ps,
                event_type="idp_config_changed",
                target_tenant_id=tenant_id,
                request_id=rid,
                agent_id=agent_slug,
                actor_id=aid,
            )
    return {"mapping": {"idp_group": body.idp_group, "role": body.role}}


@idp_router.get("/tenants/{tenant_id}/idp/groups")
async def list_group_mappings(tenant_id: str) -> dict:
    """List the target tenant's group→role mappings."""
    async with get_tenant_session(tenant_id) as ts:
        mappings = await IdpGroupRoleMapRepository(ts).list_for_tenant(
            tenant_id=tenant_id, caller_tenant_id=tenant_id
        )
    return {"mappings": mappings, "count": len(mappings)}
