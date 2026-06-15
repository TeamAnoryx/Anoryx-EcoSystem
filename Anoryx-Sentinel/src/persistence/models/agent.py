"""Agent ORM model (F-003).

Agents are internal Sentinel component names (lowercase slugs) per contracts/ids.md.
agent_id is VARCHAR(64) with slug pattern enforcement at the application layer.
An agent row is the canonical registry of known Sentinel agent component names.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

_AGENT_ID_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"


class Agent(Base):
    """Registry of internal Sentinel agent component names (slug identifiers)."""

    __tablename__ = "agents"

    # agent_id: lowercase slug e.g. "gateway-core", "data-protection"
    # Pattern validation is enforced by the repository and Pydantic schemas.
    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return f"<Agent agent_id={self.agent_id!r}>"
