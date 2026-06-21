"""Bulk-pipeline exceptions (F-015).

All bulk errors derive from BulkError. Storage / key / content errors are raised
at the ingest + worker boundaries and converted to contract-shaped HTTP errors
(submission API) or to a failed-file outcome (worker). NEVER embed raw object
bytes, secrets, or PII in an exception message (CLAUDE.md non-negotiable #6).
"""

from __future__ import annotations


class BulkError(Exception):
    """Base class for all F-015 bulk-pipeline errors."""


class InvalidObjectKey(BulkError):
    """An object key failed validation (traversal, wrong tenant prefix, bad shape)."""


class StorageError(BulkError):
    """A storage backend operation failed (connect / get / head / delete)."""


class StorageDependencyMissing(BulkError):
    """The optional storage client is not installed.

    Raised with the exact `pip install` hint so a slim deploy without the
    [bulk] extra fails loud and actionable (mirrors the F-006 bedrock /
    F-005 pii-spacy optional-extra discipline).
    """


class ObjectTooLarge(BulkError):
    """An object exceeded the configured per-file size cap (fetch-time backstop)."""


class UnsupportedContent(BulkError):
    """Object bytes are not processable (binary / undecodable). v1 = UTF-8 text only.

    The DECLARED content-type is never trusted; this is raised after sniffing the
    actual bytes (R4 / vector 6).
    """


class BatchLimitExceeded(BulkError):
    """A per-tenant batch / file cap was hit (backpressure, R8 / vector 16)."""
