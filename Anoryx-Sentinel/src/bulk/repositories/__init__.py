"""Bulk-pipeline repositories (F-015). All operate on a TENANT session (RLS)."""

from __future__ import annotations

from bulk.repositories.batch_repository import BatchRepository

__all__ = ["BatchRepository"]
