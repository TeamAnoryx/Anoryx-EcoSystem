"""Zero-arg ASGI factory for the served Rendly app (R-010, ADR-0010).

``create_chat_app``/``create_db_app``/``create_app`` all take the ES256 ``KeyMaterial`` as
an explicit constructor argument (by design — R-003 FORK A/D: no default key, no in-repo
key). ``uvicorn --factory`` calls its target with NO arguments, so this module is the one
place that bridges the two: it loads the signing key fail-closed from
``RENDLY_JWT_PRIVATE_KEY_PEM`` (``rendly.auth.keys.load_key_material``) and builds the full
chat app — auth (R-003) + DB-backed persistence (R-004) + realtime chat/huddles/archiving
(R-005..R-009) — which is the superset every prior Rendly task built toward serving.

Every other collaborator here (``DbUserStore``/``DbRefreshTokenStore``, the realtime
``ConnectionRegistry``/``HuddleManager``/inspector/resolver/ICE provider) already reads its
own config lazily from the environment on first use, so this factory needs no other inputs.
"""

from __future__ import annotations

from fastapi import FastAPI

from .auth.keys import load_key_material
from .realtime.app import create_chat_app


def create_app_from_env() -> FastAPI:
    """Build the served Rendly app, loading the ES256 signing key from the environment.

    Fail-closed: an absent/malformed/wrong-curve ``RENDLY_JWT_PRIVATE_KEY_PEM`` raises
    ``KeyConfigError`` here, before any route can serve traffic.
    """
    return create_chat_app(key=load_key_material())
