"""Tests for compliance.mapping — framework YAML loader (F-011, ADR-0013 §4 D3).

Coverage target: ≥85% of mapping.py.
AAA pattern throughout; descriptive names.
"""

from __future__ import annotations

import dataclasses
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from compliance.constants import (
    FRAMEWORKS,
    STATUS_NOT_APPLICABLE,
)
from compliance.errors import MappingNotFoundError, MappingValidationError
from compliance.mapping import ControlEntry, FrameworkMap, load_all, load_framework

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh)


def _minimal_control(
    control_id: str = "CC1.1",
    sentinel_controls: list[str] | None = None,
    evidence_event_types: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "control_id": control_id,
        "title": f"Test control {control_id}",
    }
    if sentinel_controls is not None:
        entry["sentinel_controls"] = sentinel_controls
    if evidence_event_types is not None:
        entry["evidence_event_types"] = evidence_event_types
    entry.update(extra)
    return entry


def _minimal_soc2_doc(controls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "framework": "SOC2",
        "framework_version": "2017-TSC-rev2022",
        "controls": controls
        or [_minimal_control("CC1.1", sentinel_controls=[], evidence_event_types=[])],
    }


# ── Happy-path: load_all() succeeds ──────────────────────────────────────────


class TestLoadAll:
    def test_load_all_returns_both_frameworks(self) -> None:
        # Arrange — nothing (uses real YAML files)
        # Act
        result = load_all()
        # Assert
        assert set(result.keys()) == set(FRAMEWORKS)

    def test_load_all_values_are_framework_maps(self) -> None:
        # Arrange / Act
        result = load_all()
        # Assert
        for fm in result.values():
            assert isinstance(fm, FrameworkMap)

    def test_load_all_controls_are_tuples(self) -> None:
        # Arrange / Act
        result = load_all()
        # Assert
        for fm in result.values():
            assert isinstance(fm.controls, tuple)
            for entry in fm.controls:
                assert isinstance(entry, ControlEntry)

    def test_load_all_soc2_has_expected_minimum_controls(self) -> None:
        # Arrange / Act
        result = load_all()
        soc2 = result["SOC2"]
        # Assert — at least 8 controls per spec; starter set is 11
        assert len(soc2.controls) >= 8

    def test_load_all_iso27001_has_expected_minimum_controls(self) -> None:
        # Arrange / Act
        result = load_all()
        iso = result["ISO27001"]
        # Assert — at least 6 controls per spec; starter set is 8
        assert len(iso.controls) >= 6


# ── Happy-path: individual framework loading ──────────────────────────────────


class TestLoadFramework:
    def test_load_soc2_returns_correct_framework_name(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        # Assert
        assert fm.framework == "SOC2"

    def test_load_iso27001_returns_correct_framework_name(self) -> None:
        # Arrange / Act
        fm = load_framework("ISO27001")
        # Assert
        assert fm.framework == "ISO27001"

    def test_load_soc2_framework_version_is_non_empty(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        # Assert
        assert fm.framework_version
        assert isinstance(fm.framework_version, str)

    def test_load_iso27001_framework_version_is_non_empty(self) -> None:
        # Arrange / Act
        fm = load_framework("ISO27001")
        # Assert
        assert fm.framework_version
        assert isinstance(fm.framework_version, str)

    def test_control_entry_fields_have_correct_types(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        entry = fm.controls[0]
        # Assert
        assert isinstance(entry.control_id, str)
        assert isinstance(entry.title, str)
        assert isinstance(entry.sentinel_controls, tuple)
        assert isinstance(entry.evidence_event_types, tuple)
        assert entry.rationale is None or isinstance(entry.rationale, str)
        assert entry.status_override is None or isinstance(entry.status_override, str)


# ── Immutability: frozen dataclasses ─────────────────────────────────────────


class TestImmutability:
    def test_framework_map_rejects_attribute_assignment(self) -> None:
        # Arrange
        fm = load_framework("SOC2")
        # Act / Assert
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            fm.framework = "MUTATED"  # type: ignore[misc]

    def test_control_entry_rejects_attribute_assignment(self) -> None:
        # Arrange
        fm = load_framework("SOC2")
        entry = fm.controls[0]
        # Act / Assert
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            entry.control_id = "MUTATED"  # type: ignore[misc]

    def test_controls_tuple_is_not_a_list(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        # Assert — immutability: tuples, not lists
        assert not isinstance(fm.controls, list)

    def test_sentinel_controls_is_tuple_not_list(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        for entry in fm.controls:
            assert isinstance(entry.sentinel_controls, tuple)

    def test_evidence_event_types_is_tuple_not_list(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        for entry in fm.controls:
            assert isinstance(entry.evidence_event_types, tuple)


# ── not_covered parsing ───────────────────────────────────────────────────────


class TestNotCoveredParsing:
    def test_soc2_contains_at_least_one_not_covered_entry(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        not_covered = [
            e for e in fm.controls if len(e.sentinel_controls) == 0 and e.status_override is None
        ]
        # Assert — e.g. CC6.7, A1.2
        assert len(not_covered) >= 1

    def test_iso27001_contains_at_least_one_not_covered_entry(self) -> None:
        # Arrange / Act
        fm = load_framework("ISO27001")
        not_covered = [
            e for e in fm.controls if len(e.sentinel_controls) == 0 and e.status_override is None
        ]
        # Assert — e.g. A.5.30
        assert len(not_covered) >= 1

    def test_not_covered_entry_has_empty_sentinel_controls(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        not_covered = [
            e for e in fm.controls if len(e.sentinel_controls) == 0 and e.status_override is None
        ]
        for entry in not_covered:
            # Assert — sentinel_controls is empty tuple, not faked
            assert entry.sentinel_controls == ()


# ── not_applicable parsing ────────────────────────────────────────────────────


class TestNotApplicableParsing:
    def test_soc2_contains_at_least_one_not_applicable_entry(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        na = [e for e in fm.controls if e.status_override == STATUS_NOT_APPLICABLE]
        # Assert — CC9.2
        assert len(na) >= 1

    def test_iso27001_contains_at_least_one_not_applicable_entry(self) -> None:
        # Arrange / Act
        fm = load_framework("ISO27001")
        na = [e for e in fm.controls if e.status_override == STATUS_NOT_APPLICABLE]
        # Assert — A.8.28
        assert len(na) >= 1

    def test_not_applicable_entry_status_override_value(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        na = [e for e in fm.controls if e.status_override == STATUS_NOT_APPLICABLE]
        for entry in na:
            # Assert — exact string value
            assert entry.status_override == STATUS_NOT_APPLICABLE


# ── Fail-closed: unknown framework name ───────────────────────────────────────


class TestFailClosedUnknownFramework:
    def test_unknown_framework_raises_mapping_validation_error(self) -> None:
        # Arrange — a framework NOT in FRAMEWORKS (HIPAA is now shipped, F-029;
        # PCI_DSS remains unregistered).
        bad_name = "PCI_DSS"
        # Act / Assert
        with pytest.raises(MappingValidationError, match="Unknown framework"):
            load_framework(bad_name)

    def test_empty_framework_name_raises_mapping_validation_error(self) -> None:
        # Arrange / Act / Assert
        with pytest.raises(MappingValidationError):
            load_framework("")


# ── Fail-closed: missing file ─────────────────────────────────────────────────


class TestFailClosedMissingFile:
    def test_missing_yaml_file_raises_mapping_not_found_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange — point the loader at an empty tmp directory
        import compliance.mapping as mapping_module

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", tmp_path)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)
        # Act / Assert
        with pytest.raises(MappingNotFoundError):
            load_framework("SOC2")


# ── Fail-closed: unknown event type ──────────────────────────────────────────


class TestFailClosedUnknownEventType:
    def test_unknown_event_type_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        bad_doc = _minimal_soc2_doc(
            controls=[
                _minimal_control(
                    "CC1.1",
                    sentinel_controls=["some_control"],
                    evidence_event_types=["TOTALLY_UNKNOWN_EVENT_TYPE_XYZ"],
                )
            ]
        )
        _write_yaml(frameworks_dir / "soc2.yaml", bad_doc)

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert
        with pytest.raises(MappingValidationError, match="unknown"):
            load_framework("SOC2")


# ── Fail-closed: duplicate control_id ────────────────────────────────────────


class TestFailClosedDuplicateControlId:
    def test_duplicate_control_id_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        doc = _minimal_soc2_doc(
            controls=[
                _minimal_control("CC1.1"),
                _minimal_control("CC1.1"),  # duplicate
            ]
        )
        _write_yaml(frameworks_dir / "soc2.yaml", doc)

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert
        with pytest.raises(MappingValidationError, match="duplicate"):
            load_framework("SOC2")


# ── Fail-closed: unknown key in control ──────────────────────────────────────


class TestFailClosedUnknownKey:
    def test_unknown_control_key_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        # JSON Schema has additionalProperties:false — unknown key "invented_field"
        # should fail schema validation before even reaching structural checks.
        doc = _minimal_soc2_doc(
            controls=[
                {
                    "control_id": "CC1.1",
                    "title": "Test",
                    "invented_field": "should_fail",
                }
            ]
        )
        _write_yaml(frameworks_dir / "soc2.yaml", doc)

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert — JSON Schema additionalProperties:false catches this
        with pytest.raises(MappingValidationError):
            load_framework("SOC2")


# ── Fail-closed: missing control_id ──────────────────────────────────────────


class TestFailClosedMissingControlId:
    def test_missing_control_id_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        # JSON Schema requires control_id
        doc = _minimal_soc2_doc(
            controls=[{"title": "No control_id here"}]  # missing required field
        )
        _write_yaml(frameworks_dir / "soc2.yaml", doc)

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert — JSON Schema "required" catches missing control_id
        with pytest.raises(MappingValidationError):
            load_framework("SOC2")


# ── Fail-closed: framework mismatch ──────────────────────────────────────────


class TestFailClosedFrameworkMismatch:
    def test_framework_field_mismatch_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange — file declares ISO27001 but loader asked for SOC2
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        doc = {
            "framework": "ISO27001",  # wrong framework in the SOC2 file slot
            "framework_version": "ISO-IEC-27001-2022-AnnexA",
            "controls": [_minimal_control("A.8.15")],
        }
        _write_yaml(frameworks_dir / "soc2.yaml", doc)

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert
        with pytest.raises(MappingValidationError, match="mismatch"):
            load_framework("SOC2")


# ── Fail-closed: bad YAML syntax ─────────────────────────────────────────────


class TestFailClosedBadYaml:
    def test_invalid_yaml_syntax_raises_mapping_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import shutil

        import compliance.mapping as mapping_module

        frameworks_dir = tmp_path / "frameworks"
        frameworks_dir.mkdir()
        shutil.copy(mapping_module._SCHEMA_PATH, frameworks_dir / "mapping.schema.json")

        bad_yaml = textwrap.dedent(
            """\
            framework: SOC2
            framework_version: [unclosed bracket
            controls:
              - control_id: CC1.1
                title: bad
            """
        )
        (frameworks_dir / "soc2.yaml").write_text(bad_yaml, encoding="utf-8")

        monkeypatch.setattr(mapping_module, "_FRAMEWORKS_DIR", frameworks_dir)
        monkeypatch.setattr(mapping_module, "_schema_cache", None)

        # Act / Assert
        with pytest.raises(MappingValidationError, match="YAML parse error"):
            load_framework("SOC2")


# ── Control-id uniqueness across real YAMLs ───────────────────────────────────


class TestRealYamlControlIdUniqueness:
    def test_soc2_control_ids_are_unique(self) -> None:
        # Arrange / Act
        fm = load_framework("SOC2")
        ids = [e.control_id for e in fm.controls]
        # Assert
        assert len(ids) == len(set(ids))

    def test_iso27001_control_ids_are_unique(self) -> None:
        # Arrange / Act
        fm = load_framework("ISO27001")
        ids = [e.control_id for e in fm.controls]
        # Assert
        assert len(ids) == len(set(ids))


# ── All evidence_event_types are valid ───────────────────────────────────────


class TestRealYamlEventTypesValid:
    def test_soc2_all_event_types_are_valid(self) -> None:
        # Arrange
        from persistence.models.events_audit_log import VALID_EVENT_TYPES

        # Act
        fm = load_framework("SOC2")

        # Assert
        for entry in fm.controls:
            for et in entry.evidence_event_types:
                assert (
                    et in VALID_EVENT_TYPES
                ), f"SOC2 control {entry.control_id} references unknown event type '{et}'"

    def test_iso27001_all_event_types_are_valid(self) -> None:
        # Arrange
        from persistence.models.events_audit_log import VALID_EVENT_TYPES

        # Act
        fm = load_framework("ISO27001")

        # Assert
        for entry in fm.controls:
            for et in entry.evidence_event_types:
                assert (
                    et in VALID_EVENT_TYPES
                ), f"ISO27001 control {entry.control_id} references unknown event type '{et}'"
