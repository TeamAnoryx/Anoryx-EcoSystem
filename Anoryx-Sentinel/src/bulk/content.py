"""Content validation for fetched objects (F-015, ADR-0018 §6, R4 / vector 6).

The DECLARED content-type is NEVER trusted. After bytes are fetched we sniff the
ACTUAL content and decide whether it is processable. v1 processes UTF-8 TEXT only
(the F-005 detectors operate on text); binary / undecodable content is rejected,
not silently passed.

This keeps the batch path honest: a file claiming `text/plain` that is actually a
binary blob is rejected, and a file claiming `application/octet-stream` that is
valid UTF-8 text is still processed on its real bytes.
"""

from __future__ import annotations

from bulk.exceptions import ObjectTooLarge, UnsupportedContent


def decode_text(data: bytes, *, max_bytes: int) -> str:
    """Validate + decode object bytes to text, ignoring any declared type.

    Rejects (raises) when the content is oversize, contains NUL bytes (a strong
    binary signal), or is not valid UTF-8. Returns the decoded text otherwise.

    max_bytes is re-checked here as a backstop even though the presigned upload
    already capped size at the storage layer (vector 5 defense-in-depth).
    """
    if len(data) > max_bytes:
        raise ObjectTooLarge("object exceeds per-file size cap")
    if b"\x00" in data:
        # NUL bytes do not occur in valid UTF-8 text; treat as binary.
        raise UnsupportedContent("object is not UTF-8 text (binary content)")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Never include the raw bytes / partial decode in the message (PII risk).
        raise UnsupportedContent("object is not valid UTF-8 text") from exc
