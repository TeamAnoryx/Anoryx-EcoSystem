"""OIDC pre-auth single-use login transaction store (F-014 STEP 4).

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-21

ADR-0017 §5 (D4) requires server-side, single-use state for the OIDC
authorization-code + PKCE flow:
  * `state`         — CSRF defence (vector 9). Unguessable random PK; the only
                      handle the browser carries back on the callback.
  * `nonce`         — ID-token replay defence (vector 10), stored server-side so
                      a forged/replayed nonce cannot pass.
  * `code_verifier` — PKCE S256 verifier (vector 13), stored server-side and sent
                      at the token exchange so a stolen authorization code is
                      useless without it.
  * `tenant_id` / `idp_config_id` — the R1 tenant binding: the tenant is the OWNER
                      of the matched idp_config recorded HERE at login-start, never
                      read from the returned token (vector 2).

WHY THIS TABLE IS GLOBAL (no RLS, privileged-session only):
  The OIDC login endpoints are UNAUTHENTICATED — the assertion IS the auth — so at
  login-start there is NO operator/tenant session context yet (RLS GUC is unset).
  This table is therefore keyed by an unguessable random `state` and binds
  `tenant_id` as a column, mirroring the global `tenants` registry pattern: it is
  written and read through get_privileged_session() (owner role). sentinel_app
  receives NO grant on it — the NOBYPASSRLS app role never touches the pre-auth
  store. Confidentiality rests on `state` being a high-entropy random token, not
  on RLS, exactly as a signed-cookie OIDC state would — except this store also
  enforces SINGLE-USE (consumed_at), which a stateless signed cookie cannot.

Single-use (replay rejection): `consumed_at` is set atomically on the FIRST
consume of a row; a second consume of the same `state` matches nothing and returns
None (vector 10). Expired rows (`expires_at < now()`) are likewise non-consumable
and are opportunistically deleted.

Reversible: downgrade() drops the table and its index. Loss-free — pre-F-014 data
is untouched and the table holds only short-lived (≤TTL) pre-auth handles.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "oidc_login_transaction"
_EXPIRES_INDEX = "ix_oidc_login_transaction_expires_at"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        # `state` is the unguessable random handle AND the primary key — the only
        # value the browser round-trips. VARCHAR(64): a token_urlsafe(32) state is
        # ~43 chars; 64 leaves head-room.
        sa.Column("state", sa.String(64), primary_key=True),
        sa.Column("nonce", sa.String(64), nullable=False),
        # PKCE S256 code_verifier: 43–128 chars per RFC 7636.
        sa.Column("code_verifier", sa.String(128), nullable=False),
        # The R1 tenant binding — the idp_config OWNER, recorded at login-start.
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("idp_config_id", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Hard TTL; a row past expires_at is non-consumable (fail-closed).
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # Set once, atomically, on first consume — single-use replay guard.
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Index supports the opportunistic expired-row cleanup sweep.
    op.create_index(_EXPIRES_INDEX, _TABLE, ["expires_at"])

    # No GRANT to sentinel_app and no RLS policy: this pre-auth store is global and
    # is touched ONLY by the privileged (owner) session, which owns the table by
    # default. The NOBYPASSRLS app role must never read or write it.


def downgrade() -> None:
    op.drop_index(_EXPIRES_INDEX, table_name=_TABLE)
    op.drop_table(_TABLE)
