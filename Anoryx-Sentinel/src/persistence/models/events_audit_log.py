"""EventsAuditLog ORM model (F-003).

APPEND-ONLY tamper-evident audit log for all Sentinel events.

Hash-chain design (single-table, nullable variant columns):
- row_hash = SHA-256 of the CANONICAL JSON of all content fields INCLUDING
  event_timestamp and prev_hash (sorted keys, no whitespace, UTF-8).
- prev_hash = row_hash of the immediately preceding row (by sequence_number).
  First row: prev_hash = GENESIS_HASH (documented constant).
- chained_hash is an alias for row_hash (kept for API symmetry with the spec).

Tamper-evidence: altering any field changes row_hash, breaking the chain
for that row and all subsequent rows. An attacker with full DB write access
CAN rebuild the entire chain — this is tamper-EVIDENT, not tamper-PROOF.
Rapid detection + planned future external WORM attestation (see ADR-0004).

APPEND-ONLY enforcement: BEFORE UPDATE and BEFORE DELETE triggers raise an
exception. RLS policies also prevent non-superuser UPDATE/DELETE.

Column naming — F-003 conforms to contracts/events.schema.json (F-002):
  severity        — PiiBlockedEvent.severity (NOT pii_severity)
  status          — ComplianceCheckedEvent.status (NOT compliance_status)
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Index,
    Numeric,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.hash_chain import GENESIS_HASH  # noqa: F401 — re-exported for callers
from persistence.models.base import Base

# event_type enum values (matches contracts/events.schema.json).
VALID_EVENT_TYPES = frozenset(
    {
        "usage",
        "pii_blocked",
        "injection_detected",
        "secret_leaked",
        "policy_violated",
        "compliance_checked",
        "shadow_ai_detected",
        "routing_decision",  # F-006 (ADR-0008 §5)
        # F-008 (ADR-0009 §7) — policy intake + enforcement variants.
        "policy_intake_accepted",
        "policy_intake_rejected_signature",
        "policy_intake_rejected_scope_mismatch",
        "policy_intake_rejected_replay",
        "policy_intake_rejected_schema",
        "policy_decision_allow",
        "policy_decision_deny",
        # F-007 (ADR-0010 §8) — ML classifier + shadow-AI egress variants.
        "prompt_injection_detected_ml",
        "classifier_unconfigured",
        "classifier_degraded",
        "classifier_invocation_failed",
        "shadow_ai_detected_outbound",
        "recursive_injection_attempt",
        "judge_billing_event",
        # F-009 (ADR-0011 §7) — Redis rate-limit observability variants.
        "rate_limit_degraded",
        "rate_limit_recovered",
        "rate_limit_redis_error",
        # F-011 (ADR-0013 §9 D8) — compliance evidence variants.
        "compliance_evidence_generated",
        "compliance_pack_exported",
        # F-012 (ADR-0014 §8/§10 D7/D9) — admin console action variants.
        "admin_tenant_created",
        "admin_tenant_deactivated",
        "admin_key_minted",
        "admin_key_revoked",
        "admin_config_updated",
        "admin_audit_accessed",
        # F-014 (ADR-0017 §10 D9) — SSO + break-glass audit variants.
        "operator_sso_login",
        "operator_sso_denied",
        "admin_breakglass_used",
        "idp_config_changed",
        # F-015 (ADR-0018 §8 D7) — bulk pipeline lifecycle/outcome variants.
        "batch_submitted",
        "batch_file_processed",
        "batch_file_blocked",
        "batch_file_dead_lettered",
        "batch_completed",
    }
)

# Per-variant allowed action_taken values (contracts/events.schema.json):
#   pii_blocked:        masked | tokenized | blocked
#   injection_detected: blocked | logged
#   secret_leaked:      masked | tokenized | blocked
#   policy_violated:    blocked | throttled | warned
ACTION_TAKEN_BY_EVENT_TYPE: dict[str, frozenset[str]] = {
    "pii_blocked": frozenset({"masked", "tokenized", "blocked"}),
    "injection_detected": frozenset({"blocked", "logged"}),
    "secret_leaked": frozenset({"masked", "tokenized", "blocked"}),
    "policy_violated": frozenset({"blocked", "throttled", "warned"}),
    # F-006 (ADR-0008 §5.4): routing_decision carries action_taken.
    "routing_decision": frozenset({"routed", "blocked", "failed_over"}),
    # F-008 (ADR-0009 §7): intake + enforcement variants reuse the existing
    # action_taken enum values 'logged' (accepted/allowed) and 'blocked'
    # (rejected/denied), so ck_eal_action_taken is unchanged.
    "policy_intake_accepted": frozenset({"logged"}),
    "policy_intake_rejected_signature": frozenset({"blocked"}),
    "policy_intake_rejected_scope_mismatch": frozenset({"blocked"}),
    "policy_intake_rejected_replay": frozenset({"blocked"}),
    "policy_intake_rejected_schema": frozenset({"blocked"}),
    "policy_decision_allow": frozenset({"logged"}),
    "policy_decision_deny": frozenset({"blocked"}),
    # F-007 (ADR-0010 §8): reuse the existing 'blocked'/'logged' action values
    # only, so ck_eal_action_taken is UNCHANGED.
    "prompt_injection_detected_ml": frozenset({"blocked", "logged"}),
    "classifier_unconfigured": frozenset({"logged"}),
    "classifier_degraded": frozenset({"logged"}),
    "classifier_invocation_failed": frozenset({"logged"}),
    "shadow_ai_detected_outbound": frozenset({"logged"}),
    "recursive_injection_attempt": frozenset({"blocked", "logged"}),
    "judge_billing_event": frozenset({"logged"}),
    # F-009 (ADR-0011 §7): all three rate-limit observability variants use
    # action_taken='logged' only; ck_eal_action_taken is UNCHANGED.
    "rate_limit_degraded": frozenset({"logged"}),
    "rate_limit_recovered": frozenset({"logged"}),
    "rate_limit_redis_error": frozenset({"logged"}),
    # F-011 (ADR-0013 §9 D8): compliance evidence variants use action_taken='logged'
    # only; ck_eal_action_taken is UNCHANGED.
    "compliance_evidence_generated": frozenset({"logged"}),
    "compliance_pack_exported": frozenset({"logged"}),
    # F-012 (ADR-0014 §8 D7): admin console action variants all use
    # action_taken='logged' only; ck_eal_action_taken is UNCHANGED.
    "admin_tenant_created": frozenset({"logged"}),
    "admin_tenant_deactivated": frozenset({"logged"}),
    "admin_key_minted": frozenset({"logged"}),
    "admin_key_revoked": frozenset({"logged"}),
    "admin_config_updated": frozenset({"logged"}),
    "admin_audit_accessed": frozenset({"logged"}),
    # F-014 (ADR-0017 §10 D9): SSO + break-glass variants. operator_sso_denied
    # uses 'blocked' (a valid assertion but no role/unknown subject); the other
    # three use 'logged'. ck_eal_action_taken is UNCHANGED (all values already
    # present in the existing CHECK constraint).
    "operator_sso_login": frozenset({"logged"}),
    "operator_sso_denied": frozenset({"blocked"}),
    "admin_breakglass_used": frozenset({"logged"}),
    "idp_config_changed": frozenset({"logged"}),
    # F-015 (ADR-0018 §8 D7): bulk variants. batch_file_blocked uses 'blocked'
    # (detector/policy denied the file); the other four use 'logged'.
    # ck_eal_action_taken is UNCHANGED (all values already present).
    "batch_submitted": frozenset({"logged"}),
    "batch_file_processed": frozenset({"logged"}),
    "batch_file_blocked": frozenset({"blocked"}),
    "batch_file_dead_lettered": frozenset({"logged"}),
    "batch_completed": frozenset({"logged"}),
}


class EventsAuditLog(Base):
    """Tamper-evident append-only event log. Never UPDATE or DELETE rows."""

    __tablename__ = "events_audit_log"

    # Monotonic sequence number — used to order the hash chain unambiguously.
    # bigserial: Postgres auto-increment, never reused.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # -----------------------------------------------------------------------
    # Common fields (required on every event per contracts/events.schema.json)
    # -----------------------------------------------------------------------
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_timestamp: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # RFC3339 string; in hash content.
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Four stable IDs (server-resolved, not client-supplied).
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # -----------------------------------------------------------------------
    # Variant-specific columns (nullable; only the relevant variant is set).
    # Single-table design chosen for simplicity and fast full-table scans.
    # See ADR-0004 for the trade-off analysis.
    # -----------------------------------------------------------------------

    # usage variant
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    tokens_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cost_estimate_cents: Mapped[float | None] = mapped_column(
        Numeric(precision=20, scale=6), nullable=True
    )

    # pii_blocked variant
    # Column name matches contracts/events.schema.json: PiiBlockedEvent.severity
    pattern_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # action_taken: shared across pii_blocked, injection_detected, secret_leaked,
    # policy_violated. Per-variant validation enforced in the repository.
    action_taken: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # injection_detected variant
    classifier_score: Mapped[float | None] = mapped_column(
        Numeric(precision=5, scale=4), nullable=True
    )
    rule_matched: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # secret_leaked variant
    secret_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    direction: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # policy_violated variant
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    violation_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # compliance_checked variant
    # Column name matches contracts/events.schema.json: ComplianceCheckedEvent.status
    framework: Mapped[str | None] = mapped_column(String(32), nullable=True)
    control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # shadow_ai_detected variant
    detected_endpoint: Mapped[str | None] = mapped_column(String(256), nullable=True)
    traffic_volume: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_seen_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # routing_decision variant (F-006, ADR-0008 §5.6). action_taken (above) reused.
    selected_provider: Mapped[str | None] = mapped_column(String(16), nullable=True)
    routing_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempt_index: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    requested_model: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # F-007 (ADR-0010 §8): ML classifier + judge-billing + classifier-status
    # variant columns. judge_provider reuses selected_provider; prompt/completion
    # tokens reuse tokens_in/tokens_out; cost/latency reuse the usage columns.
    judge_score: Mapped[float | None] = mapped_column(Numeric(precision=4, scale=3), nullable=True)
    judge_confidence: Mapped[float | None] = mapped_column(
        Numeric(precision=4, scale=3), nullable=True
    )
    final_score: Mapped[float | None] = mapped_column(Numeric(precision=4, scale=3), nullable=True)
    judge_model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    judge_preset: Mapped[str | None] = mapped_column(String(64), nullable=True)
    judge_outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    audit_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    classifier_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # F-014 (ADR-0017 §10 D9) — per-operator attribution column.
    # Holds the internal admin_users.id UUID (opaque, NOT PII, NOT the raw IdP
    # subject/email). Nullable: pre-binding denials and break-glass events have
    # no resolved operator. Folded into the hash canonical form ONLY WHEN NOT
    # NULL — see hash_chain.canonical_json() for the backward-compat rule.
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Hash-chain columns
    # -----------------------------------------------------------------------
    # SHA-256 hex of the previous row's row_hash. GENESIS_HASH for the first row.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 hex of canonical JSON of this row's content (including prev_hash
    # and event_timestamp — preventing reordering attacks).
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # -----------------------------------------------------------------------
    # Constraints
    # -----------------------------------------------------------------------
    __table_args__ = (
        CheckConstraint(
            "event_type IN ("
            "'usage','pii_blocked','injection_detected',"
            "'secret_leaked','policy_violated','compliance_checked',"
            "'shadow_ai_detected','routing_decision',"
            # F-008 (ADR-0009 §7) — kept in sync with migration 0008.
            "'policy_intake_accepted','policy_intake_rejected_signature',"
            "'policy_intake_rejected_scope_mismatch','policy_intake_rejected_replay',"
            "'policy_intake_rejected_schema','policy_decision_allow','policy_decision_deny',"
            # F-007 (ADR-0010 §8) — kept in sync with migration 0010.
            "'prompt_injection_detected_ml','classifier_unconfigured','classifier_degraded',"
            "'classifier_invocation_failed','shadow_ai_detected_outbound',"
            "'recursive_injection_attempt','judge_billing_event',"
            # F-009 (ADR-0011 §7) — kept in sync with migration 0011.
            "'rate_limit_degraded','rate_limit_recovered','rate_limit_redis_error',"
            # F-011/F-012 — kept in sync with migrations 0012/0013.
            "'compliance_evidence_generated','compliance_pack_exported',"
            "'admin_tenant_created','admin_tenant_deactivated',"
            "'admin_key_minted','admin_key_revoked',"
            "'admin_config_updated','admin_audit_accessed',"
            # F-014 (ADR-0017 §10 D9) — kept in sync with migration 0015.
            "'operator_sso_login','operator_sso_denied',"
            "'admin_breakglass_used','idp_config_changed')",
            name="ck_eal_event_type",
        ),
        CheckConstraint(
            "tokens_in IS NULL OR (tokens_in >= 0 AND tokens_in <= 10000000)",
            name="ck_eal_tokens_in",
        ),
        CheckConstraint(
            "tokens_out IS NULL OR (tokens_out >= 0 AND tokens_out <= 10000000)",
            name="ck_eal_tokens_out",
        ),
        CheckConstraint(
            "latency_ms IS NULL OR (latency_ms >= 0 AND latency_ms <= 3600000)",
            name="ck_eal_latency_ms",
        ),
        CheckConstraint(
            "classifier_score IS NULL OR " "(classifier_score >= 0 AND classifier_score <= 1)",
            name="ck_eal_classifier_score",
        ),
        CheckConstraint(
            "traffic_volume IS NULL OR " "(traffic_volume >= 0 AND traffic_volume <= 1000000000)",
            name="ck_eal_traffic_volume",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('low','medium','high','critical')",
            name="ck_eal_severity",
        ),
        CheckConstraint(
            "secret_type IS NULL OR "
            "secret_type IN ('api_key','token','private_key','credential')",
            name="ck_eal_secret_type",
        ),
        CheckConstraint(
            "direction IS NULL OR direction IN ('inbound','outbound')",
            name="ck_eal_direction",
        ),
        CheckConstraint(
            "framework IS NULL OR " "framework IN ('SOC2','GDPR','HIPAA','EU_AI_ACT')",
            name="ck_eal_framework",
        ),
        CheckConstraint(
            "status IS NULL OR " "status IN ('passed','failed','not_applicable')",
            name="ck_eal_status",
        ),
        # action_taken: union of valid values across all event variants.
        # F-006 adds 'routed','failed_over' (routing_decision); 'blocked' already present.
        CheckConstraint(
            "action_taken IS NULL OR action_taken IN ("
            "'masked','tokenized','blocked','logged','throttled','warned',"
            "'routed','failed_over')",
            name="ck_eal_action_taken",
        ),
        # routing_decision variant bounds (F-006, ADR-0008 §5.6).
        CheckConstraint(
            "selected_provider IS NULL OR " "selected_provider IN ('openai','anthropic','bedrock')",
            name="ck_eal_selected_provider",
        ),
        CheckConstraint(
            "outcome IS NULL OR outcome IN ("
            "'selected','allowlist_denied','cost_blocked','fallback_attempted','exhausted')",
            name="ck_eal_outcome",
        ),
        CheckConstraint(
            "attempt_index IS NULL OR (attempt_index >= 0 AND attempt_index <= 16)",
            name="ck_eal_attempt_index",
        ),
        # F-007 (ADR-0010 §8) — ML classifier variant bounds (kept in sync with 0010).
        CheckConstraint(
            "judge_score IS NULL OR (judge_score >= 0 AND judge_score <= 1)",
            name="ck_eal_judge_score",
        ),
        CheckConstraint(
            "judge_confidence IS NULL OR (judge_confidence >= 0 AND judge_confidence <= 1)",
            name="ck_eal_judge_confidence",
        ),
        CheckConstraint(
            "final_score IS NULL OR (final_score >= 0 AND final_score <= 1)",
            name="ck_eal_final_score",
        ),
        CheckConstraint(
            "audit_mode IS NULL OR audit_mode IN ('full','redacted')",
            name="ck_eal_audit_mode",
        ),
        CheckConstraint(
            "judge_outcome IS NULL OR "
            "judge_outcome IN ('verdict','degraded','failed','policy_denied')",
            name="ck_eal_judge_outcome",
        ),
        # row_hash and prev_hash must be 64-char hex strings.
        CheckConstraint("length(row_hash) = 64", name="ck_eal_row_hash_len"),
        CheckConstraint("length(prev_hash) = 64", name="ck_eal_prev_hash_len"),
        Index("ix_eal_tenant_id", "tenant_id"),
        Index("ix_eal_event_type", "event_type"),
        Index("ix_eal_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_eal_sequence_number", "sequence_number"),
        # BRIN index on sequence_number for range scans on large tables.
        Index(
            "ix_eal_seq_brin",
            "sequence_number",
            postgresql_using="brin",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<EventsAuditLog seq={self.sequence_number} "
            f"type={self.event_type!r} tenant={self.tenant_id!r}>"
        )
