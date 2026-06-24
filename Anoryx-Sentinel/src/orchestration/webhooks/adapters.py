"""Provider adapters — map a metadata event envelope to a provider request body (F-020).

Each adapter takes the ALREADY-STAMPED metadata envelope (the bounded
events.schema.json projection carrying the 4 IDs, event_type, severity,
verdict/action_taken, webhook_provider, event_id, event_timestamp) and returns
a JSON-serializable dict that forms the outbound HTTP request body.

HARD RULE (ADR-0023 D1): adapters are STRUCTURALLY INCAPABLE of egressing
prompt, response, or PII content because the candidate envelope they receive
contains NONE of those fields (the emit-seam tap in context.emit() projects
only the metadata fields — see context.py).

adapter_for(provider) is the single dispatch function used by the worker.

NEVER log: target URLs, credentials, raw response bodies, or any field not in
the bounded metadata projection.
"""

from __future__ import annotations

import json
from collections.abc import Callable

# ---------------------------------------------------------------------------
# Bounded metadata field list (mirrors the emit-seam projection in context.py).
# This is the ONLY set of fields that may appear in outbound bodies.
# ---------------------------------------------------------------------------
_ALLOWED_ENVELOPE_KEYS: frozenset[str] = frozenset(
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


def _safe_projection(envelope: dict) -> dict:
    """Return a copy of *envelope* containing ONLY allowed metadata keys.

    Defense-in-depth: even if an unexpected key were somehow present in the
    envelope, it would be stripped here before it reaches the adapter body.
    """
    return {k: v for k, v in envelope.items() if k in _ALLOWED_ENVELOPE_KEYS}


# ---------------------------------------------------------------------------
# Slack adapter
# ---------------------------------------------------------------------------


def build_slack_body(envelope: dict) -> str:
    """Build a Slack incoming-webhook JSON payload from the metadata envelope.

    Format: a Block Kit 'section' with a single text block.  Metadata-only —
    only fields from the bounded projection.
    """
    safe = _safe_projection(envelope)

    event_type = safe.get("event_type", "unknown")
    severity = safe.get("severity", "")
    action_taken = safe.get("action_taken", "")
    event_id = safe.get("event_id", "")
    event_timestamp = safe.get("event_timestamp", "")
    tenant_id = safe.get("tenant_id", "")

    severity_label = f"*{severity.upper()}*" if severity else ""
    text_parts = [
        f"Sentinel alert [{event_type}]",
    ]
    if severity_label:
        text_parts.append(f"Severity: {severity_label}")
    if action_taken:
        text_parts.append(f"Action: {action_taken}")
    if event_id:
        text_parts.append(f"Event ID: {event_id}")
    if event_timestamp:
        text_parts.append(f"Timestamp: {event_timestamp}")
    if tenant_id:
        text_parts.append(f"Tenant: {tenant_id}")

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(text_parts),
                },
            }
        ]
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Jira adapter
# ---------------------------------------------------------------------------


def build_jira_body(envelope: dict, *, project_key: str = "SEN") -> str:
    """Build a Jira REST API v3 create-issue payload from the metadata envelope.

    project_key defaults to 'SEN'; the admin builder populates it from the
    webhook_config.credential (decrypted Jira API token + project config).
    For v1 this is a minimal create-issue body — custom-field mapping is
    deferred (ADR-0023 §8).
    """
    safe = _safe_projection(envelope)

    event_type = safe.get("event_type", "unknown")
    severity = safe.get("severity", "")
    action_taken = safe.get("action_taken", "")
    event_id = safe.get("event_id", "")
    event_timestamp = safe.get("event_timestamp", "")
    tenant_id = safe.get("tenant_id", "")

    summary_parts = [f"[Sentinel] {event_type}"]
    if severity:
        summary_parts.append(f"[{severity.upper()}]")

    description_lines = ["Sentinel security-event metadata."]
    if action_taken:
        description_lines.append(f"Action taken: {action_taken}")
    if event_id:
        description_lines.append(f"Event ID: {event_id}")
    if event_timestamp:
        description_lines.append(f"Timestamp: {event_timestamp}")
    if tenant_id:
        description_lines.append(f"Tenant: {tenant_id}")

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": " ".join(summary_parts),
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": "\n".join(description_lines),
                            }
                        ],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
        }
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Splunk HEC adapter
# ---------------------------------------------------------------------------


def build_splunk_body(envelope: dict) -> str:
    """Build a Splunk HTTP Event Collector payload from the metadata envelope.

    Format: a single HEC event JSON object with a 'sourcetype' of
    'sentinel:security-event' and the bounded metadata as 'event'.
    """
    safe = _safe_projection(envelope)

    payload = {
        "sourcetype": "sentinel:security-event",
        "event": safe,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_ADAPTER_MAP: dict[str, Callable[[dict], str]] = {
    "slack": build_slack_body,
    "jira": build_jira_body,
    "splunk": build_splunk_body,
}


def build_body(provider: str, envelope: dict) -> str:
    """Dispatch to the correct provider adapter and return the request body string.

    Raises KeyError for an unknown provider (caller should treat as build_error).
    """
    builder = _ADAPTER_MAP[provider.lower()]
    return builder(envelope)
