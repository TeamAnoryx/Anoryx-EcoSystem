"""Bulk-pipeline ORM models (F-015, ADR-0018 §9).

Both `batches` and `batch_files` are tenant-scoped: RLS (ENABLE+FORCE, the F-003b
NULLIF predicate) + the sentinel_app GRANT are applied in migration 0018. Importing
this package registers the models on Base.metadata.
"""

from __future__ import annotations

from bulk.models.batch import (
    BATCH_STATUSES,
    Batch,
)
from bulk.models.batch_file import (
    FILE_OUTCOMES,
    FILE_STATUSES,
    FILE_TERMINAL_STATUSES,
    BatchFile,
)

__all__ = [
    "Batch",
    "BatchFile",
    "BATCH_STATUSES",
    "FILE_STATUSES",
    "FILE_TERMINAL_STATUSES",
    "FILE_OUTCOMES",
]
