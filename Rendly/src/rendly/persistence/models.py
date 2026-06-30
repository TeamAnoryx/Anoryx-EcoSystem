"""SQLAlchemy declarative models for Rendly identity persistence (R-004).

ORM row classes schema-qualified into ``rendly``. The store + repo build statements
against these; the AUTHORITATIVE DDL is the Alembic migration
(``migrations/versions/0001_identity_schema.py``) — these classes describe only the
columns the query layer references and are kept in lock-step with it (FK/RLS/role/grants
live in the migration, mirroring Delta D-003's models-describe-columns split).

ID/COLUMN SHAPE (critical, from R-002 ``identifiers.py``): ids are PLAIN dashed-hex UUID
strings (maxLength 64, case-INSENSITIVE, NO version-nibble check, NO canonicalization),
so every id column is ``String(64)`` — never a native ``uuid`` type — and values are
NEVER lower-cased on write or read. Timestamps are ``timestamptz`` (tz-aware UTC).
Enums persist as their lowercase ``StrEnum`` ``.value`` text and are reconstructed on read.
"""

from __future__ import annotations

from sqlalchemy import Boolean, DateTime, ForeignKeyConstraint, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, mapped_column

from . import RENDLY_SCHEMA

# The FK constraints below mirror the AUTHORITATIVE migration DDL. They are declared on the
# ORM models (not just the migration) for ONE reason: the unit-of-work needs them to order
# dependent INSERTs (tenants -> users -> profiles/credentials; families -> tokens). They are
# never used to emit DDL (the migration owns the schema; create_all is never called).


class Base(DeclarativeBase):
    """Declarative base; every table is qualified into the ``rendly`` schema."""


class TenantRow(Base):
    """Global tenant registry (NO RLS — like Sentinel's tenants table)."""

    __tablename__ = "tenants"
    __table_args__ = {"schema": RENDLY_SCHEMA}

    tenant_id = mapped_column(String(64), primary_key=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)


class UserRow(Base):
    """A tenant-local user identity (RLS table). PK is (tenant_id, user_id)."""

    __tablename__ = "users"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{RENDLY_SCHEMA}.tenants.tenant_id"]),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(64), primary_key=True)
    display_name = mapped_column(String(128), nullable=False)
    status_text = mapped_column(String(256), nullable=True)
    presence = mapped_column(String(16), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)


class ProfileRow(Base):
    """A user's internal org affiliation (RLS table). One profile per user."""

    __tablename__ = "profiles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(64), primary_key=True)
    org_role = mapped_column(String(16), nullable=False)
    team = mapped_column(String(128), nullable=True)


class CredentialRow(Base):
    """A username→credential row (RLS table). ``username`` is the global login key."""

    __tablename__ = "credentials"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    username = mapped_column(String(320), primary_key=True)
    tenant_id = mapped_column(String(64), nullable=False)
    user_id = mapped_column(String(64), nullable=False)
    password_hash = mapped_column(Text, nullable=False)  # Argon2id PHC string
    created_at = mapped_column(DateTime(timezone=True), nullable=False)


class RefreshTokenFamilyRow(Base):
    """A refresh-token family (RLS table). Revoking the family burns every generation."""

    __tablename__ = "refresh_token_families"
    __table_args__ = {"schema": RENDLY_SCHEMA}

    family_id = mapped_column(String(32), primary_key=True)
    tenant_id = mapped_column(String(64), nullable=False)
    user_id = mapped_column(String(64), nullable=False)
    revoked = mapped_column(Boolean, nullable=False, default=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)


class RefreshTokenRow(Base):
    """A single refresh token at rest — SHA-256 hex only, never the raw token (RLS table)."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        ForeignKeyConstraint(["family_id"], [f"{RENDLY_SCHEMA}.refresh_token_families.family_id"]),
        {"schema": RENDLY_SCHEMA},
    )

    token_hash = mapped_column(String(64), primary_key=True)  # sha256 hex
    family_id = mapped_column(String(32), nullable=False)
    tenant_id = mapped_column(String(64), nullable=False)
    user_id = mapped_column(String(64), nullable=False)
    generation = mapped_column(Integer, nullable=False)
    used = mapped_column(Boolean, nullable=False, default=False)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    scopes = mapped_column(ARRAY(Text), nullable=False)
    roles = mapped_column(ARRAY(Text), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)
