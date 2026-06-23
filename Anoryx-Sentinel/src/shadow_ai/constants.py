"""F-018 shadow-AI detection — bounded constants (ADR-0021 §4/§5/§6).

All thresholds live here (coding-style: no inline magic numbers). The honesty
disclaimer (R1) is the single source of truth, returned on every candidates
response and rendered non-removably in the governance panel.
"""

from __future__ import annotations

# The one new audit event variant F-018 emits (detect-only, action_taken="logged").
CANDIDATE_EVENT_TYPE = "shadow_ai_candidate_detected"
# The raw F-007 egress event F-018 consumes (never re-emitted, never rebuilt — R2).
RAW_EGRESS_EVENT_TYPE = "shadow_ai_detected_outbound"
# Emitter slug stamped as the candidate event's envelope agent_id. Per ADR-0007 D8
# the envelope agent_id names the EMITTING component, not the attributed agent
# (the offending team/project are carried in team_id/project_id).
DETECTOR_SLUG = "shadow-ai"

# Bounded scan sizes (newest-first) — the analysis never walks the whole table.
# Both are clamped by AuditLogRepository._LIST_MAX_LIMIT (1000); these are the
# requested limits.
MAX_RAW_EVENTS = 1000
MAX_CANDIDATE_LOOKBACK = 1000
# Cap on NEW candidate events emitted per analysis run. Bounds privileged-session
# appends (each takes the global chain advisory lock), so an adversarial tenant
# cannot turn one poll into a large burst of locked appends. The RETURNED candidate
# list is never truncated — only emission is capped, and a cap hit is logged.
MAX_CANDIDATES_PER_EMIT = 50

# --- Heuristic thresholds (ADR-0021 §5) — explainable, documented ---------------
# 'volume' signal: a (team, project, endpoint) group with at least this many
# disallowed-known-provider calls in the scan window.
VOLUME_THRESHOLD = 5
# 'frequency' signal: at least FREQUENCY_MIN_EVENTS calls within any
# FREQUENCY_WINDOW_SECONDS sliding window for the group.
FREQUENCY_MIN_EVENTS = 3
FREQUENCY_WINDOW_SECONDS = 300  # 5 minutes

# --- Confidence bands (ADR-0021 §5) ---------------------------------------------
BAND_LOW = "low"
BAND_MEDIUM = "medium"
BAND_HIGH = "high"

# --- Signal names (MUST match contracts/events.schema.json fired_signals enum) ---
SIGNAL_DISALLOWED = "disallowed_provider"
SIGNAL_VOLUME = "volume"
SIGNAL_FREQUENCY = "frequency"

# The honesty boundary (R1) — stated verbatim in ADR-0021 §4. Non-removable: a test
# asserts this exact text is present on both the API payload and the UI panel.
HONESTY_DISCLAIMER = (
    "Shadow-AI detection covers only traffic that flows through Sentinel to a "
    "known model provider that is not on the tenant's allow-list. It does NOT "
    "detect tools that bypass Sentinel — a personal device, a phone, a browser "
    "tab, or any client not routed through the gateway (detecting those requires "
    "a CASB or network/DNS control and is out of scope). It also does not yet "
    "observe Bedrock/aioboto3 egress. Detections are review candidates with a "
    "confidence band, not verdicts — a candidate flags likely shadow-AI use by a "
    "team for human review and may be a false positive."
)
