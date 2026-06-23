"""DataLockDetector — 6th PostResponseHook (F-017, ADR-0020).

Conditionally withholds locked fields in the assistant's JSON output.  Runs in a
DEDICATED registry slot (like F-016 code-scan), NOT the per-chunk streaming chain,
because withholding requires the COMPLETE response body.

Non-streamed path (registry.run_data_lock):
  1. Load per-tenant config — FAIL CLOSED: a load/parse error raises
     DataLockConfigError → this detector returns action="block" (whole-response
     fail-closed, ADR-0020 §4 tier-2).
  2. Not armed (no opt-in) → action="pass" (cheap).
  3. Armed → parse the response envelope; for each assistant message.content that
     is itself JSON, evaluate every rule's SERVER-AUTHORITATIVE condition and
     withhold the value of each field whose condition is unmet.  Non-JSON / prose
     content is out of scope (Fork 2) and passes through untouched.
  4. action="mask" with the re-serialized envelope when ≥1 field was withheld,
     else "pass".

Streamed path (registry.run_data_lock_stream_preflight):
  A field cannot be withheld from bytes already on the wire, so an armed tenant's
  streamed request is BLOCKED before the first byte (ADR-0020 §5).  A load error
  is likewise fail-closed blocked.

Audit (never the field value — CLAUDE.md rule 6): field_locked / field_unlocked /
lock_condition_denied / data_lock_error carry only metadata (path → pattern_name,
condition kind → violation_type, action_taken).
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from data_lock.conditions import PermissionCondition, evaluate
from data_lock.config import DataLockConfigError, load_data_lock_config
from data_lock.rules import DataLockRule
from data_lock.selector import (
    MAX_CONTENT_BYTES,
    SelectorBudgetError,
    apply_withhold,
    new_budget,
)
from orchestration.hooks.base import DetectorResult, PostResponseHook

log = structlog.get_logger(__name__)

_SLUG = "data-lock"


class DataLockDetector(PostResponseHook):
    """Post-response hook: conditionally withhold locked fields (fail-closed)."""

    @property
    def detector_slug(self) -> str:
        return _SLUG

    # ------------------------------------------------------------------
    # Non-streamed enforcement
    # ------------------------------------------------------------------

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Withhold locked fields in *content* (the response envelope JSON string).

        Returns action "pass" | "mask" | "block".  Never "release on error".
        """
        tenant_id = self._tenant_id(context)

        try:
            config = await load_data_lock_config(tenant_id)
        except DataLockConfigError:
            # Tier-2 fail-closed: the ruleset is unknowable → block the whole body.
            return await self._block_error(context, "config_error")

        if not config.armed:
            return DetectorResult(action="pass")

        ids = self._principal(context)

        try:
            envelope = json.loads(content)
        except (ValueError, TypeError):
            # We are armed but cannot parse the body → cannot guarantee no leak.
            return await self._block_error(context, "envelope_unparseable")

        choices = envelope.get("choices") if isinstance(envelope, dict) else None
        if not isinstance(choices, list):
            return DetectorResult(action="pass")

        events: list[dict[str, Any]] = []
        any_withheld = False
        # Immutable rebuild: never mutate the parsed envelope/choice/message in
        # place (CLAUDE.md immutability + reader-safety). Replace only the choices
        # whose content was actually withheld.
        new_choices = list(choices)
        try:
            for idx, choice in enumerate(choices):
                msg = choice.get("message") if isinstance(choice, dict) else None
                if not isinstance(msg, dict):
                    continue
                cstr = msg.get("content")
                if not isinstance(cstr, str) or not cstr:
                    continue
                if len(cstr.encode("utf-8")) > MAX_CONTENT_BYTES:
                    # Too large to traverse safely while armed → fail closed.
                    return await self._block_error(context, "content_too_large")
                try:
                    parsed = json.loads(cstr)
                except (ValueError, TypeError):
                    continue  # prose / non-JSON content → out of scope (Fork 2)
                new_parsed, withheld = self._apply_rules(parsed, config.rules, ids, events)
                if withheld:
                    new_msg = {**msg, "content": json.dumps(new_parsed)}
                    new_choices[idx] = {**choice, "message": new_msg}
                    any_withheld = True
        except SelectorBudgetError:
            # Pathological payload exceeded the traversal budget → fail closed.
            return await self._block_error(context, "traversal_budget")

        # Emit the collected per-field events (best-effort; never raise).
        for ev in events:
            await self._safe_emit(context, ev)

        if any_withheld:
            new_envelope = {**envelope, "choices": new_choices}
            return DetectorResult(action="mask", modified_payload=json.dumps(new_envelope))
        return DetectorResult(action="pass")

    # ------------------------------------------------------------------
    # Streamed pre-flight
    # ------------------------------------------------------------------

    async def evaluate_stream_preflight(self, context: Any) -> DetectorResult:
        """Streaming: armed → block (ADR-0020 §5); load error → block; else pass."""
        tenant_id = self._tenant_id(context)
        try:
            config = await load_data_lock_config(tenant_id)
        except DataLockConfigError:
            return await self._block_error(context, "config_error")

        if config.armed:
            # Whole-request block (not a single field), and the streamed response
            # has no field path → use data_lock_error (FieldLockedEvent requires a
            # pattern_name; this is a policy-level block, not a per-field lock).
            ev = {
                "event_type": "data_lock_error",
                "action_taken": "blocked",
                "violation_type": "streaming_blocked_by_policy",
            }
            await self._safe_emit(context, ev)
            return DetectorResult(action="block", event=ev)
        return DetectorResult(action="pass")

    # ------------------------------------------------------------------
    # Rule application
    # ------------------------------------------------------------------

    def _apply_rules(
        self,
        parsed: Any,
        rules: tuple[DataLockRule, ...],
        ids: dict[str, str],
        events: list[dict[str, Any]],
    ) -> tuple[Any, bool]:
        """Apply every rule to *parsed*, withholding unmet+present fields.

        Returns (new_parsed, any_withheld).  A shared traversal budget bounds the
        TOTAL work across all rules in this response.  UNMET rules do the real
        withholding first — a budget breach there propagates (caller fail-closes
        the whole response, R1).  MET rules are then probed only for an
        ``field_unlocked`` audit signal; a budget breach during release-probing is
        caught and never blocks (H-1: a fully-released response must not 403).
        """
        budget = new_budget()
        current = parsed
        any_withheld = False
        met_rules: list[DataLockRule] = []

        # Pass 1 — UNMET rules withhold (priority on the shared budget).
        for rule in rules:
            if evaluate(rule.condition, **ids):
                met_rules.append(rule)
                continue
            candidate, count = apply_withhold(current, [rule.tokens], budget)
            if count == 0:
                continue  # field absent in this payload → nothing to withhold
            current = candidate
            any_withheld = True
            kind = "permission" if isinstance(rule.condition, PermissionCondition) else "time"
            events.append(
                {
                    "event_type": (
                        "lock_condition_denied" if kind == "permission" else "field_locked"
                    ),
                    "action_taken": "blocked",
                    "pattern_name": rule.raw_path,
                    "violation_type": kind,
                }
            )

        # Pass 2 — MET rules: emit field_unlocked only for fields actually present
        # (a genuine release).  Probing must NEVER block, so a budget breach here
        # just stops further unlock auditing.
        for rule in met_rules:
            try:
                _, count = apply_withhold(current, [rule.tokens], budget)
            except SelectorBudgetError:
                break
            if count > 0:
                kind = "permission" if isinstance(rule.condition, PermissionCondition) else "time"
                events.append(
                    {
                        "event_type": "field_unlocked",
                        "action_taken": "logged",
                        "pattern_name": rule.raw_path,
                        "violation_type": kind,
                    }
                )
        return current, any_withheld

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tenant_id(context: Any) -> str:
        try:
            return context.tenant_context.tenant_id or ""
        except Exception:
            # An unresolvable tenant context is anomalous (production always
            # resolves it upstream). Return "" → load raises → fail-closed block.
            log.warning("data_lock.tenant_context_unresolvable")
            return ""

    @staticmethod
    def _principal(context: Any) -> dict[str, str]:
        tc = context.tenant_context
        return {
            "team_id": getattr(tc, "team_id", "") or "",
            "project_id": getattr(tc, "project_id", "") or "",
            "agent_id": getattr(tc, "agent_id", "") or "",
        }

    async def _block_error(self, context: Any, reason: str) -> DetectorResult:
        """Emit data_lock_error and return a whole-response fail-closed block."""
        ev = {
            "event_type": "data_lock_error",
            "action_taken": "blocked",
            "violation_type": reason,  # e.g. config_error / traversal_budget — never a value
        }
        await self._safe_emit(context, ev)
        log.warning("data_lock.fail_closed_block", reason=reason)
        return DetectorResult(action="block", event=ev)

    @staticmethod
    async def _safe_emit(context: Any, event: dict[str, Any]) -> None:
        """Emit an event; a failed emit must never convert a lock into a leak."""
        try:
            await context.emit(event, detector_slug=_SLUG)
        except Exception:
            pass
