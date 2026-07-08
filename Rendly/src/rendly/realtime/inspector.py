"""The Sentinel message-inspection SEAM (R-005 FORK D) — interface + fail-closed no-op.

R-001 locks the inspection contract: the send path runs inspection SYNCHRONOUSLY (in-line,
awaited) BEFORE the message is persisted or fanned out, and the result is fail-closed — a
``blocked`` verdict OR a seam that cannot complete (``seam_unavailable``) BOTH stop the send
(the message is never persisted and never delivered). R-005 built the SEAM and wired it into
the send pipeline, shipping ONLY the no-op pass-through. R-008 (``sentinel_inspector.py``)
swaps in real PII / injection / secret detection via a different :class:`MessageInspector` —
no pipeline change, exactly as designed.

HONESTY BOUNDARY (verbatim): SEAM ONLY, not inspection. ``NoOpMessageInspector`` performs NO
detection — it always returns ``pass``. It exists so the fail-closed wiring (a rejecting or
unavailable inspector stops the send before persist + fan-out) is REAL and testable now, and
remains available for tests that want an explicit pass-through.

FAIL-CLOSED CONTRACT the pipeline enforces around this seam (Sentinel non-negotiable #5):
  * ``inspect`` returns ``pass``           -> the send proceeds (persist + ack accepted + fan-out).
  * ``inspect`` returns ``blocked``        -> chat.ack ``blocked`` / ``message_blocked``; dropped.
  * ``inspect`` returns ``seam_unavailable``
    OR ``inspect`` RAISES any exception    -> chat.ack ``blocked`` / ``inspection_unavailable``;
                                              dropped. An inspector that errors is NEVER a silent
                                              pass — the pipeline converts the failure to a BLOCK.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

InspectionStatus = Literal["pass", "blocked", "seam_unavailable"]
DetectorCategory = Literal["pii", "injection", "secret"]
DetectorOutcome = Literal["pass", "block"]


@dataclass(frozen=True)
class DetectorFinding:
    """One detector's verdict (contracts/messages.schema.json InspectionResult.detectors item).

    Metadata ONLY — ``category`` + ``outcome``, NEVER the offending content or the matched
    substring. Mirrors the Sentinel F-005 detector categories (pii / injection / secret).
    """

    category: DetectorCategory
    outcome: DetectorOutcome


@dataclass(frozen=True)
class InspectionOutcome:
    """The inspection seam's verdict.

    ``detectors`` was RESERVED for R-008 and is now populated by :class:`SentinelMessageInspector`
    (``sentinel_inspector.py``) — up to one finding per category, metadata only. It stays empty
    for :class:`NoOpMessageInspector` and any test fake that does not set it.
    """

    status: InspectionStatus
    evaluated_at: datetime
    detectors: tuple[DetectorFinding, ...] = ()


class MessageInspector(ABC):
    """The inspection seam interface. ``inspect`` is async so a real (R-008) impl can call out
    to Sentinel without blocking the event loop; it is awaited IN-LINE before persist + fan-out.

    An implementation MUST NOT return ``pass`` on an internal failure. It may either return
    ``InspectionOutcome(status="seam_unavailable", ...)`` or raise — the pipeline treats BOTH as
    a fail-closed BLOCK. Returning ``pass`` is a positive assertion that the content was
    inspected and allowed.
    """

    @abstractmethod
    async def inspect(
        self,
        *,
        tenant_id: str,
        channel_id: str,
        sender_user_id: str,
        content: str,
        content_type: str,
    ) -> InspectionOutcome:
        """Inspect outbound chat content and return the verdict (fail-closed at the caller)."""
        raise NotImplementedError


class NoOpMessageInspector(MessageInspector):
    """The R-005 default: NO detection — always ``pass``.

    HONESTY BOUNDARY: this performs no PII / injection / secret detection whatsoever. It is the
    pass-through that lets R-005 ship the send path WITH the fail-closed seam wired in place;
    R-008 replaces it with the real inspector.
    """

    async def inspect(
        self,
        *,
        tenant_id: str,
        channel_id: str,
        sender_user_id: str,
        content: str,
        content_type: str,
    ) -> InspectionOutcome:
        return InspectionOutcome(status="pass", evaluated_at=datetime.now(timezone.utc))
