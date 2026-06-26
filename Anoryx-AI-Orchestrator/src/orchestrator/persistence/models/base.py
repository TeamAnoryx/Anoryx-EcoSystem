"""Declarative base for the Orchestrator ORM models (O-003)."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base. Models register their tables on Base.metadata."""
