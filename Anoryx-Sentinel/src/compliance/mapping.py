"""Compliance framework mapping loader (F-011, ADR-0013 §4 D3).

Loads and validates framework YAML control-mappings, returning immutable
frozen dataclasses.  Fails closed on ANY malformed or unknown input —
raises MappingValidationError rather than silently skipping bad data.

Honest-language rule: "audit-ready" throughout; never "compliant".
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from compliance.constants import FRAMEWORKS, VALID_STATUSES
from compliance.errors import MappingNotFoundError, MappingValidationError
from persistence.models.events_audit_log import VALID_EVENT_TYPES

# ── Paths ────────────────────────────────────────────────────────────────────

_FRAMEWORKS_DIR: Path = Path(__file__).parent / "frameworks"
_SCHEMA_PATH: Path = _FRAMEWORKS_DIR / "mapping.schema.json"

# ── Immutable data structures ─────────────────────────────────────────────────


@dataclass(frozen=True)
class ControlEntry:
    """Immutable representation of a single framework control mapping.

    Fields
    ------
    control_id:
        Framework-specific identifier (e.g. "CC7.2", "A.8.15").
    title:
        Human-readable control title.
    sentinel_controls:
        Tuple of Sentinel capability identifiers that map to this control.
        Empty tuple indicates no Sentinel coverage — reported as not_covered.
    evidence_event_types:
        Tuple of VALID_EVENT_TYPES members that constitute evidence for this
        control.  All values are validated against VALID_EVENT_TYPES at load
        time; unknown values raise MappingValidationError (fail-closed).
    rationale:
        Optional explanation of the control mapping.
    status_override:
        When set, forces the control status to "not_applicable" or
        "not_covered" regardless of evidence.  Always explicit, never silent.
    """

    control_id: str
    title: str
    sentinel_controls: tuple[str, ...]
    evidence_event_types: tuple[str, ...]
    rationale: str | None
    status_override: str | None


@dataclass(frozen=True)
class FrameworkMap:
    """Immutable mapping for an entire compliance framework.

    Fields
    ------
    framework:
        Framework identifier — one of FRAMEWORKS.
    framework_version:
        Pinned framework revision string copied verbatim into every artifact.
    controls:
        Tuple of ControlEntry objects in YAML-file order.  No post-load
        sorting is applied so the human-authored ordering is preserved.
    """

    framework: str
    framework_version: str
    controls: tuple[ControlEntry, ...]


# ── Schema cache (loaded once per process) ───────────────────────────────────

_schema_cache: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    """Return the parsed JSON Schema, loading from disk at most once."""
    global _schema_cache  # noqa: PLW0603 — intentional module-level cache
    if _schema_cache is None:
        if not _SCHEMA_PATH.exists():
            raise MappingNotFoundError(f"JSON Schema not found: {_SCHEMA_PATH}")
        with _SCHEMA_PATH.open(encoding="utf-8") as fh:
            _schema_cache = json.load(fh)
    return _schema_cache


# ── YAML loading helper ───────────────────────────────────────────────────────


def _yaml_path(framework: str) -> Path:
    """Return the expected YAML path for *framework*."""
    return _FRAMEWORKS_DIR / f"{framework.lower()}.yaml"


def _load_raw_yaml(framework: str) -> dict[str, Any]:
    """Read and parse the YAML file; raise MappingNotFoundError if absent."""
    path = _yaml_path(framework)
    if not path.exists():
        raise MappingNotFoundError(f"Framework mapping file not found for '{framework}': {path}")
    with path.open(encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise MappingValidationError(f"YAML parse error in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise MappingValidationError(
            f"Framework mapping '{path}' must be a YAML mapping at the top level."
        )
    return data


# ── JSON Schema validation ────────────────────────────────────────────────────


def _validate_schema(data: dict[str, Any], framework: str) -> None:
    """Validate *data* against mapping.schema.json; raise MappingValidationError on failure."""
    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        messages = "; ".join(
            f"[{'.'.join(str(p) for p in err.path)}] {err.message}" for err in errors[:5]
        )
        raise MappingValidationError(
            f"Framework mapping for '{framework}' failed JSON Schema validation: {messages}"
        )


# ── Structural validation ─────────────────────────────────────────────────────


def _validate_framework_field(data: dict[str, Any], requested: str) -> None:
    """Ensure the 'framework' field in the YAML matches what was requested."""
    if data.get("framework") != requested:
        raise MappingValidationError(
            f"Framework mismatch: file declares '{data.get('framework')}' but "
            f"'{requested}' was requested."
        )


def _validate_controls(controls_raw: list[Any], framework: str) -> list[dict[str, Any]]:
    """Validate the controls list; raise MappingValidationError on any violation.

    Checks enforced:
    - Each item is a dict (schema covers this, but belt-and-suspenders).
    - No duplicate control_id values.
    - No unknown top-level or control-level keys beyond those in the schema.
    - All evidence_event_types values are members of VALID_EVENT_TYPES.
    - status_override (if present) is a known status literal.
    """
    seen_ids: set[str] = set()
    allowed_control_keys: frozenset[str] = frozenset(
        {
            "control_id",
            "title",
            "sentinel_controls",
            "evidence_event_types",
            "rationale",
            "status_override",
        }
    )

    validated: list[dict[str, Any]] = []

    for idx, raw in enumerate(controls_raw):
        if not isinstance(raw, dict):
            raise MappingValidationError(f"[{framework}] control at index {idx} is not a mapping.")

        unknown_keys = set(raw.keys()) - allowed_control_keys
        if unknown_keys:
            raise MappingValidationError(
                f"[{framework}] control at index {idx} has unknown key(s): "
                f"{sorted(unknown_keys)}.  Allowed: {sorted(allowed_control_keys)}."
            )

        control_id = raw.get("control_id")
        if not control_id:
            raise MappingValidationError(
                f"[{framework}] control at index {idx} is missing 'control_id'."
            )
        if not isinstance(control_id, str) or not control_id.strip():
            raise MappingValidationError(
                f"[{framework}] control at index {idx}: 'control_id' must be a "
                f"non-empty string."
            )

        if control_id in seen_ids:
            raise MappingValidationError(
                f"[{framework}] duplicate control_id '{control_id}' at index {idx}."
            )
        seen_ids.add(control_id)

        event_types: list[Any] = raw.get("evidence_event_types") or []
        unknown_events = [e for e in event_types if e not in VALID_EVENT_TYPES]
        if unknown_events:
            raise MappingValidationError(
                f"[{framework}] control '{control_id}' references unknown "
                f"evidence_event_types: {unknown_events}.  "
                f"All values must be members of VALID_EVENT_TYPES."
            )

        status_override = raw.get("status_override")
        if status_override is not None and status_override not in VALID_STATUSES:
            raise MappingValidationError(
                f"[{framework}] control '{control_id}' has unknown status_override "
                f"'{status_override}'.  Valid values: {sorted(VALID_STATUSES)}."
            )

        validated.append(raw)

    return validated


# ── Entry-point coercions ─────────────────────────────────────────────────────


def _to_control_entry(raw: dict[str, Any]) -> ControlEntry:
    """Convert a validated raw dict to an immutable ControlEntry.

    Normalises absent optional fields to safe defaults; never mutates the
    input dict (immutability rule).
    """
    sentinel_controls = tuple(raw.get("sentinel_controls") or [])
    evidence_event_types = tuple(raw.get("evidence_event_types") or [])
    rationale_raw = raw.get("rationale")
    rationale = rationale_raw if rationale_raw else None
    status_override = raw.get("status_override") or None

    # Coerce explicit empty-sentinel_controls with no status_override to not_covered.
    # (Actual status resolution is gap_analysis.py's responsibility; here we just
    # surface what the YAML says — we do NOT silently set status_override.)

    return ControlEntry(
        control_id=raw["control_id"],
        title=raw["title"],
        sentinel_controls=sentinel_controls,
        evidence_event_types=evidence_event_types,
        rationale=rationale,
        status_override=status_override,
    )


# ── Public API ────────────────────────────────────────────────────────────────


def load_framework(name: str) -> FrameworkMap:
    """Load, validate, and return the FrameworkMap for *name*.

    Parameters
    ----------
    name:
        One of FRAMEWORKS ("SOC2", "ISO27001").

    Returns
    -------
    FrameworkMap
        Immutable frozen dataclass.  All nested structures are tuples.

    Raises
    ------
    MappingNotFoundError
        If the YAML file for *name* does not exist.
    MappingValidationError
        If the YAML is structurally or semantically invalid (unknown keys,
        duplicate control_id, unknown event type, JSON Schema violation, etc.).
    """
    if name not in FRAMEWORKS:
        raise MappingValidationError(
            f"Unknown framework '{name}'.  Supported frameworks: {FRAMEWORKS}."
        )

    data = _load_raw_yaml(name)
    _validate_schema(data, name)
    _validate_framework_field(data, name)

    controls_raw: list[Any] = data.get("controls") or []
    validated_controls = _validate_controls(controls_raw, name)

    entries = tuple(_to_control_entry(c) for c in validated_controls)

    return FrameworkMap(
        framework=data["framework"],
        framework_version=data["framework_version"],
        controls=entries,
    )


def load_all() -> dict[str, FrameworkMap]:
    """Load and validate all supported framework mappings.

    Returns
    -------
    dict[str, FrameworkMap]
        Keys are framework names (members of FRAMEWORKS).

    Raises
    ------
    MappingNotFoundError
        If any framework YAML file is missing.
    MappingValidationError
        If any framework mapping is invalid.
    """
    return {name: load_framework(name) for name in FRAMEWORKS}
