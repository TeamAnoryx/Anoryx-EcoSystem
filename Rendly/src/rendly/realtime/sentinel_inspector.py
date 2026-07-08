"""``SentinelMessageInspector`` (R-008) — the real PII / injection / secret inspection seam.

Swaps into the R-005 FORK D seam (``realtime/inspector.py``) with NO pipeline change, exactly as
``inspector.py`` and ``realtime/app.py`` document. Runs all three ``detectors.py`` categories
in-process and reduces them to the wire's fail-closed shape: ``blocked`` if ANY category blocks,
``pass`` only if all three pass — the contract has no partial-block / redaction state at the
top level (``contracts/messages.schema.json`` InspectionResult.status is a plain 3-value enum),
so a single blocking category blocks the WHOLE message, never a partial send.

DATA SOVEREIGNTY: no network I/O. See ``detectors.py`` for the per-category honesty boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .detectors import detect_injection, detect_pii, detect_secret
from .inspector import DetectorFinding, InspectionOutcome, MessageInspector


class SentinelMessageInspector(MessageInspector):
    """Self-hosted, in-process PII / injection / secret detection — the R-008 default."""

    async def inspect(
        self,
        *,
        tenant_id: str,
        channel_id: str,
        sender_user_id: str,
        content: str,
        content_type: str,
    ) -> InspectionOutcome:
        findings = (
            DetectorFinding(category="pii", outcome="block" if detect_pii(content) else "pass"),
            DetectorFinding(
                category="injection", outcome="block" if detect_injection(content) else "pass"
            ),
            DetectorFinding(
                category="secret", outcome="block" if detect_secret(content) else "pass"
            ),
        )
        status = "blocked" if any(f.outcome == "block" for f in findings) else "pass"
        return InspectionOutcome(
            status=status, evaluated_at=datetime.now(timezone.utc), detectors=findings
        )
