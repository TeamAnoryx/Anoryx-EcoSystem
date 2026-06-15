"""Declarative base for all Anoryx-Sentinel ORM models (F-003).

All ORM models inherit from Base. Alembic env.py imports Base.metadata
for autogenerate support. No application logic lives here.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all Sentinel persistence models."""
