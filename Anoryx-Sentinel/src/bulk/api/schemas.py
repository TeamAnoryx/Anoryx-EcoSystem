"""Request/response schemas for the bulk data-plane API (F-015, ADR-0018).

Closed Pydantic models (extra fields rejected) — the same edge-discipline as the
gateway's CreateChatCompletionRequest. Bounds are belt-and-suspenders; the route
also validates counts against BulkSettings caps.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class UploadMintRequest(BaseModel):
    """Request N presigned single-object upload grants."""

    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=1, le=100_000)


class UploadGrantOut(BaseModel):
    """One presigned upload grant (S3 POST policy form)."""

    object_key: str
    url: str
    fields: dict[str, str]
    max_bytes: int
    expires_in: int


class UploadMintResponse(BaseModel):
    uploads: list[UploadGrantOut]


class BatchSubmitRequest(BaseModel):
    """Submit a batch: an idempotency key + the object keys to process."""

    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=1, max_length=255)
    # Hard structural ceiling (DoS backstop) — the configured per-tenant cap
    # (bulk_max_files_per_batch) is enforced in the route. The 1 MiB body cap is the
    # other backstop. Each key is bounded too (canonical key is 105 chars).
    object_keys: list[str] = Field(min_length=1, max_length=100_000)
    # Optional target model — when set, F-008 model allow/deny applies per file.
    model: str | None = Field(default=None, max_length=256)


class BatchStatusResponse(BaseModel):
    batch_id: str
    status: str
    total_files: int
    counts: dict[str, int]


class BatchFileItem(BaseModel):
    file_id: str
    object_key: str
    status: str
    outcome: str | None
    attempt_count: int
    failure_class: str | None


class BatchManifestResponse(BaseModel):
    batch_id: str
    files: list[BatchFileItem]
