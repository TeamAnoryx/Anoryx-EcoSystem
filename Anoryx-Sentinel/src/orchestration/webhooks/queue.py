"""Redis Streams plumbing for the F-020 webhook-dispatcher (ADR-0023 §5.3 D3).

This module clones the F-015 pattern from bulk/queue.py VERBATIM:
  - ensure_group()       — XGROUP_CREATE / MKSTREAM (idempotent)
  - CandidateMessage     — typed stream message (producer + consumer side)
  - xadd_candidate()    — XADD a metadata-only candidate onto webhook:candidates
  - dead_letter()        — XADD a failed delivery onto the DLQ stream

The candidate stream key is `webhook:candidates` (configurable).
The consumer group is `webhook-dispatcher-group` (configurable).

Message content is METADATA-ONLY (ADR-0023 D1): the 4 IDs + event_type +
severity + action_taken + violation_type + event_id + event_timestamp +
request_id.  NO prompt/response/PII content — the emit-seam tap in context.py
projects ONLY these fields before XADD.

Reuses the F-009 pool: `gateway.redis_client.get_client`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from gateway.redis_client import get_client
from orchestration.webhooks.config import get_webhook_settings

log = structlog.get_logger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Bounded metadata fields that may ride on the stream (Fork A projection).
# This MUST match the projection in context.py emit() tap and adapters.py.
_CANDIDATE_FIELDS: frozenset[str] = frozenset(
    {
        "event_type",
        "severity",
        "tenant_id",
        "team_id",
        "project_id",
        "agent_id",
        "event_id",
        "event_timestamp",
        "request_id",
        "action_taken",
        "violation_type",
        "webhook_provider",
    }
)


@dataclass(frozen=True, slots=True)
class CandidateMessage:
    """One webhook-candidate message. Flat str fields only (Redis Streams require str)."""

    event_type: str
    severity: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    event_id: str
    event_timestamp: str
    request_id: str
    action_taken: str
    violation_type: str  # empty string when absent
    webhook_provider: str  # empty string when the source event has none

    def to_fields(self) -> dict[str, str]:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "tenant_id": self.tenant_id,
            "team_id": self.team_id,
            "project_id": self.project_id,
            "agent_id": self.agent_id,
            "event_id": self.event_id,
            "event_timestamp": self.event_timestamp,
            "request_id": self.request_id,
            "action_taken": self.action_taken,
            "violation_type": self.violation_type,
            "webhook_provider": self.webhook_provider,
        }

    @classmethod
    def from_fields(cls, fields: dict[str, str]) -> "CandidateMessage":
        """Deserialize + VALIDATE a stream message. Raises KeyError/ValueError on malformed."""
        msg = cls(
            event_type=fields["event_type"],
            severity=fields["severity"],
            tenant_id=fields["tenant_id"],
            team_id=fields["team_id"],
            project_id=fields["project_id"],
            agent_id=fields["agent_id"],
            event_id=fields["event_id"],
            event_timestamp=fields["event_timestamp"],
            request_id=fields["request_id"],
            action_taken=fields.get("action_taken", ""),
            violation_type=fields.get("violation_type", ""),
            webhook_provider=fields.get("webhook_provider", ""),
        )
        # Validate the four stable IDs are UUIDs (defense-in-depth; poison-message guard).
        for uid in (msg.tenant_id, msg.team_id, msg.project_id):
            if not _UUID_RE.match(uid):
                raise ValueError(f"webhook candidate carries a non-UUID stable id: {uid!r}")
        if not msg.event_id or not msg.event_type:
            raise ValueError("webhook candidate missing event_id or event_type")
        return msg

    def to_envelope(self) -> dict[str, str]:
        """Return the bounded metadata envelope (keys restricted to _CANDIDATE_FIELDS)."""
        return {k: v for k, v in self.to_fields().items() if k in _CANDIDATE_FIELDS}


async def ensure_group() -> None:
    """Create the webhook consumer group (idempotent) — MKSTREAM so it works pre-XADD."""
    settings = get_webhook_settings()
    async with await get_client() as client:
        try:
            await client.xgroup_create(
                settings.webhook_candidates_stream_key,
                settings.webhook_consumer_group,
                id="0",
                mkstream=True,
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise


async def xadd_candidate(fields: dict[str, str]) -> None:
    """XADD one bounded metadata candidate to the webhook:candidates stream (producer).

    Called by the context.emit() tap — best-effort (caller wraps in try/except).
    """
    settings = get_webhook_settings()
    async with await get_client() as client:
        await client.xadd(settings.webhook_candidates_stream_key, fields)


async def dead_letter(msg: CandidateMessage, *, failure_class: str) -> None:
    """XADD a dead-lettered delivery to the DLQ stream (mirrors bulk/queue.py dead_letter)."""
    settings = get_webhook_settings()
    fields = msg.to_fields()
    fields["failure_class"] = failure_class
    async with await get_client() as client:
        await client.xadd(settings.webhook_dlq_stream_key, fields)
