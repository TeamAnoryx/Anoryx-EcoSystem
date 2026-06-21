"""F-014 SSO event variants + actor_id persistence (ADR-0017 §10/§11 D9/D10).

Three test groups:

1. Backward-compatibility of hash_chain (pure-Python, no DB):
   - canonical_json() for a row WITHOUT actor_id does NOT contain b'"actor_id"'.
   - compute_row_hash() for a pre-F-014 row equals what it would have been
     before this change (i.e. building the dict from CANONICAL_FIELDS only
     produces the same bytes — no actor_id key injected).
   - A mixed chain (old-style rows then an operator_sso_login row WITH actor_id)
     validates cleanly in a simulated walk.

2. actor_id tamper detection (pure-Python, no DB):
   - A row WITH actor_id: changing actor_id changes compute_row_hash.
   - Nulling a previously-present actor_id breaks verification.

3. DB round-trip (integration, skip-not-fail when no DB):
   - Append one of each of the 4 new event types via AuditLogRepository.
   - operator_sso_login WITH actor_id set (UUID string).
   - admin_breakglass_used with tenant_id=WILDCARD_UUID (system event, D9 table).
   - validate_chain() returns is_valid=True over the appended rows.
   - 4-site registration check: all 4 new types in VALID_EVENT_TYPES +
     ACTION_TAKEN_BY_EVENT_TYPE.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.hash_chain import (
    CANONICAL_FIELDS,
    GENESIS_HASH,
    canonical_json,
    compute_row_hash,
    verify_row_hash,
)
from persistence.models.events_audit_log import ACTION_TAKEN_BY_EVENT_TYPE, VALID_EVENT_TYPES

# Reserved system-ID per contracts/ids.md (fourth documented use: admin_breakglass_used).
WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"

# The four F-014 event types (ADR-0017 §10 D9).
_F014_VARIANTS = (
    "operator_sso_login",
    "operator_sso_denied",
    "admin_breakglass_used",
    "idp_config_changed",
)


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# 4-site registration checks (pure-Python, no DB required)
# ---------------------------------------------------------------------------


def test_f014_variants_in_valid_event_types() -> None:
    """All four F-014 variants are registered in VALID_EVENT_TYPES."""
    for variant in _F014_VARIANTS:
        assert (
            variant in VALID_EVENT_TYPES
        ), f"{variant!r} missing from VALID_EVENT_TYPES — 4-site consistency broken"


def test_f014_action_taken_mapping() -> None:
    """All four F-014 variants are in ACTION_TAKEN_BY_EVENT_TYPE with correct values."""
    expected = {
        "operator_sso_login": frozenset({"logged"}),
        "operator_sso_denied": frozenset({"blocked"}),
        "admin_breakglass_used": frozenset({"logged"}),
        "idp_config_changed": frozenset({"logged"}),
    }
    for variant, allowed in expected.items():
        assert (
            variant in ACTION_TAKEN_BY_EVENT_TYPE
        ), f"{variant!r} missing from ACTION_TAKEN_BY_EVENT_TYPE"
        assert (
            ACTION_TAKEN_BY_EVENT_TYPE[variant] == allowed
        ), f"{variant!r}: expected {allowed!r}, got {ACTION_TAKEN_BY_EVENT_TYPE[variant]!r}"


def test_actor_id_not_in_canonical_fields() -> None:
    """actor_id must NOT be in CANONICAL_FIELDS (opt-in-when-present rule, ADR-0017 §10 D9)."""
    assert "actor_id" not in CANONICAL_FIELDS, (
        "actor_id must NOT be in CANONICAL_FIELDS — adding it would inject "
        '"actor_id":null into every pre-F-014 row\'s recomputed hash and break '
        "validate_chain() over all historical data."
    )


# ---------------------------------------------------------------------------
# Backward-compatibility tests (pure-Python, no DB required)
# ---------------------------------------------------------------------------


def _minimal_row_data(event_type: str = "usage", **extra) -> dict:
    """Build a minimal valid row data dict (no actor_id unless passed in extra)."""
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_timestamp": _now_z(),
        "request_id": "req-" + uuid.uuid4().hex[:24],
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
        "prev_hash": GENESIS_HASH,
        **extra,
    }


def test_canonical_json_without_actor_id_has_no_actor_id_key() -> None:
    """A row dict without actor_id produces canonical JSON with no 'actor_id' key.

    This is the critical backward-compat assertion: pre-F-014 rows that lack
    actor_id must canonicalize EXACTLY as before — no "actor_id":null injected.
    """
    data = _minimal_row_data("usage")
    # Confirm actor_id is not even in the dict (simulates a pre-F-014 row).
    assert "actor_id" not in data

    canon = canonical_json(data)
    assert b'"actor_id"' not in canon, (
        "canonical_json() must NOT include 'actor_id' when the field is absent. "
        "This would change every pre-F-014 row's recomputed hash and break validate_chain."
    )


def test_canonical_json_with_actor_id_none_has_no_actor_id_key() -> None:
    """A row dict with actor_id=None also produces canonical JSON with no 'actor_id' key.

    Simulates a new non-operator event (e.g. admin_breakglass_used) where
    actor_id is explicitly None.
    """
    data = _minimal_row_data("admin_breakglass_used", actor_id=None)
    canon = canonical_json(data)
    assert (
        b'"actor_id"' not in canon
    ), "canonical_json() must NOT include 'actor_id' when actor_id is None."


def test_canonical_json_with_actor_id_includes_it() -> None:
    """A row WITH a non-None actor_id includes it in canonical JSON (tamper-evident)."""
    actor = str(uuid.uuid4())
    data = _minimal_row_data("operator_sso_login", actor_id=actor)
    canon = canonical_json(data)
    assert b'"actor_id"' in canon
    parsed = json.loads(canon)
    assert parsed["actor_id"] == actor


def test_row_hash_without_actor_id_matches_canonical_fields_only() -> None:
    """Hashes for rows without actor_id equal hashes built from CANONICAL_FIELDS alone.

    Proves no regression: the hash_chain change does not alter any existing row's
    recomputed hash. We build the reference canonical bytes from CANONICAL_FIELDS
    only (the pre-F-014 implementation) and assert equality with the new impl.
    """
    data = _minimal_row_data("pii_blocked")
    # Pre-F-014 reference: only CANONICAL_FIELDS keys, None for missing.
    reference_dict = {k: data.get(k) for k in CANONICAL_FIELDS}
    reference_bytes = json.dumps(
        reference_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    actual_bytes = canonical_json(data)
    assert actual_bytes == reference_bytes, (
        "canonical_json() changed the output for a row without actor_id. "
        "This would invalidate all pre-F-014 stored hashes."
    )


def test_mixed_chain_validates_correctly() -> None:
    """Simulated chain: old-style rows then an operator_sso_login row with actor_id.

    Proves validate_chain() logic over a mixed dataset stays intact:
    - Pre-F-014 rows (no actor_id) link correctly.
    - The new SSO row (with actor_id) hashes to a different but valid value.
    - The chain walk succeeds end-to-end.
    """
    chain: list[dict] = []
    prev = GENESIS_HASH

    # Two pre-F-014 rows (no actor_id).
    for etype in ("usage", "pii_blocked"):
        row = _minimal_row_data(etype)
        row["prev_hash"] = prev
        row_hash = compute_row_hash(row)
        chain.append({"data": row, "row_hash": row_hash})
        prev = row_hash

    # One new F-014 row with actor_id.
    actor = str(uuid.uuid4())
    sso_row = _minimal_row_data("operator_sso_login", actor_id=actor)
    sso_row["agent_id"] = "operator-sso"
    sso_row["prev_hash"] = prev
    sso_hash = compute_row_hash(sso_row)
    chain.append({"data": sso_row, "row_hash": sso_hash})

    # Walk chain: simulate what validate_chain() does.
    expected_prev = GENESIS_HASH
    for entry in chain:
        data = entry["data"]
        stored_hash = entry["row_hash"]
        assert data["prev_hash"] == expected_prev, "prev_hash mismatch in chain walk"
        assert verify_row_hash(data, stored_hash), "row_hash verification failed"
        expected_prev = stored_hash

    # Verify the SSO row's canonical form includes actor_id.
    sso_canon = canonical_json(sso_row)
    assert b'"actor_id"' in sso_canon
    # And the first old-style row's canonical form does not.
    old_canon = canonical_json(chain[0]["data"])
    assert b'"actor_id"' not in old_canon


# ---------------------------------------------------------------------------
# actor_id tamper detection tests (pure-Python, no DB required)
# ---------------------------------------------------------------------------


def test_changing_actor_id_changes_hash() -> None:
    """Altering actor_id on a row that had it set changes compute_row_hash.

    This proves the tamper-evident property: an attacker changing actor_id
    breaks the stored hash match.
    """
    actor = str(uuid.uuid4())
    data = _minimal_row_data("operator_sso_login", actor_id=actor)
    original_hash = compute_row_hash(data)

    tampered = dict(data)
    tampered["actor_id"] = str(uuid.uuid4())  # different UUID
    tampered_hash = compute_row_hash(tampered)

    assert original_hash != tampered_hash, "Changing actor_id must change compute_row_hash."
    assert not verify_row_hash(
        tampered, original_hash
    ), "verify_row_hash must return False when actor_id was changed."


def test_nulling_present_actor_id_breaks_verification() -> None:
    """Nulling a previously-present actor_id breaks verification.

    The stored hash was computed WITH actor_id in the canonical form. If actor_id
    is later set to None (or removed), the recomputed hash omits it — mismatch.
    This is the omission-detection property described in the module docstring.
    """
    actor = str(uuid.uuid4())
    data = _minimal_row_data("operator_sso_login", actor_id=actor)
    stored_hash = compute_row_hash(data)

    # Null out actor_id (simulating an attacker stripping the field).
    stripped = dict(data)
    stripped["actor_id"] = None
    assert not verify_row_hash(stripped, stored_hash), (
        "verify_row_hash must return False when actor_id is nulled after "
        "a hash was computed with it present."
    )

    # Also verify the inverse: a row without actor_id that someone tries to
    # add actor_id to also fails verification.
    no_actor = _minimal_row_data("usage")
    hash_without = compute_row_hash(no_actor)
    with_actor = dict(no_actor)
    with_actor["actor_id"] = str(uuid.uuid4())
    assert not verify_row_hash(with_actor, hash_without), (
        "verify_row_hash must return False when actor_id is injected into a row "
        "whose hash was computed without it."
    )


# ---------------------------------------------------------------------------
# DB round-trip tests (integration — skip-not-fail when no DB)
# ---------------------------------------------------------------------------


def _skip_if_no_db() -> None:
    """Skip (not fail) when DATABASE_URL is not available."""
    import os

    from dotenv import load_dotenv

    _env = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
    load_dotenv(dotenv_path=_env)
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB integration test")


def _make_async_url(raw: str) -> str:
    import re

    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


def _sso_envelope(
    event_type: str,
    *,
    action_taken: str,
    tenant_id: str | None = None,
    actor_id: str | None = None,
) -> dict:
    """Build a minimal valid envelope for an F-014 SSO event."""
    return {
        "event_type": event_type,
        "tenant_id": tenant_id or str(uuid.uuid4()),
        "team_id": WILDCARD_UUID,
        "project_id": WILDCARD_UUID,
        "agent_id": "operator-sso",
        "event_id": str(uuid.uuid4()),
        "event_timestamp": _now_z(),
        "request_id": "req-" + uuid.uuid4().hex[:24],
        "action_taken": action_taken,
        **({"actor_id": actor_id} if actor_id is not None else {}),
    }


@pytest.mark.asyncio
async def test_operator_sso_login_with_actor_id_db(session: AsyncSession) -> None:
    """operator_sso_login WITH actor_id persists correctly and chain validates."""
    _skip_if_no_db()
    from persistence.repositories.audit_log_repository import AuditLogRepository

    repo = AuditLogRepository(session)
    actor = str(uuid.uuid4())
    envelope = _sso_envelope("operator_sso_login", action_taken="logged", actor_id=actor)

    row = await repo.append(envelope)
    assert row.event_type == "operator_sso_login"
    assert row.actor_id == actor
    assert row.action_taken == "logged"
    assert len(row.row_hash) == 64
    assert len(row.prev_hash) == 64

    # Verify the hash covers actor_id (the canonical form must include it).
    from persistence.hash_chain import canonical_json as cj
    from persistence.repositories.audit_log_repository import _row_to_hash_data

    hash_data = _row_to_hash_data(row)
    canon = cj(hash_data)
    assert b'"actor_id"' in canon, "actor_id must appear in canonical JSON for this row"

    result = await repo.validate_chain()
    assert result.is_valid, f"Chain invalid after operator_sso_login: {result.error_detail}"


@pytest.mark.asyncio
async def test_admin_breakglass_used_wildcard_tenant_db(session: AsyncSession) -> None:
    """admin_breakglass_used with tenant_id=WILDCARD_UUID persists correctly."""
    _skip_if_no_db()
    from persistence.repositories.audit_log_repository import AuditLogRepository

    repo = AuditLogRepository(session)
    envelope = _sso_envelope(
        "admin_breakglass_used",
        action_taken="logged",
        tenant_id=WILDCARD_UUID,
        # No actor_id — break-glass has no resolved operator (D9 table).
    )
    envelope["agent_id"] = "admin-console"

    row = await repo.append(envelope)
    assert row.event_type == "admin_breakglass_used"
    assert row.tenant_id == WILDCARD_UUID
    assert row.actor_id is None
    assert row.action_taken == "logged"

    # Verify canonical JSON does NOT include actor_id (backward-compat rule).
    from persistence.hash_chain import canonical_json as cj
    from persistence.repositories.audit_log_repository import _row_to_hash_data

    hash_data = _row_to_hash_data(row)
    canon = cj(hash_data)
    assert (
        b'"actor_id"' not in canon
    ), "actor_id must be absent from canonical JSON when it is None."

    result = await repo.validate_chain()
    assert result.is_valid, f"Chain invalid after admin_breakglass_used: {result.error_detail}"


@pytest.mark.asyncio
async def test_operator_sso_denied_db(session: AsyncSession) -> None:
    """operator_sso_denied with action_taken='blocked' persists correctly."""
    _skip_if_no_db()
    from persistence.repositories.audit_log_repository import AuditLogRepository

    repo = AuditLogRepository(session)
    envelope = _sso_envelope("operator_sso_denied", action_taken="blocked")

    row = await repo.append(envelope)
    assert row.event_type == "operator_sso_denied"
    assert row.action_taken == "blocked"
    assert row.actor_id is None

    result = await repo.validate_chain()
    assert result.is_valid, f"Chain invalid after operator_sso_denied: {result.error_detail}"


@pytest.mark.asyncio
async def test_idp_config_changed_db(session: AsyncSession) -> None:
    """idp_config_changed with actor_id persists correctly."""
    _skip_if_no_db()
    from persistence.repositories.audit_log_repository import AuditLogRepository

    repo = AuditLogRepository(session)
    actor = str(uuid.uuid4())
    envelope = _sso_envelope("idp_config_changed", action_taken="logged", actor_id=actor)

    row = await repo.append(envelope)
    assert row.event_type == "idp_config_changed"
    assert row.actor_id == actor
    assert row.action_taken == "logged"

    result = await repo.validate_chain()
    assert result.is_valid, f"Chain invalid after idp_config_changed: {result.error_detail}"


@pytest.mark.asyncio
async def test_mixed_chain_old_and_new_events_db(session: AsyncSession) -> None:
    """Mixed chain: pre-F-014 events then F-014 SSO events — validate_chain passes.

    This is the critical regression proof: adding actor_id support must not
    alter the hash of any pre-existing (actor_id=None) row.
    """
    _skip_if_no_db()
    from persistence.repositories.audit_log_repository import AuditLogRepository

    repo = AuditLogRepository(session)

    # Append two 'old-style' events (no actor_id in the dict).
    for etype in ("usage", "pii_blocked"):
        env: dict = {
            "event_type": etype,
            "tenant_id": str(uuid.uuid4()),
            "team_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "agent_id": "gateway-core",
            "event_id": str(uuid.uuid4()),
            "event_timestamp": _now_z(),
            "request_id": "req-" + uuid.uuid4().hex[:24],
        }
        if etype == "pii_blocked":
            env["action_taken"] = "masked"
        await repo.append(env)

    # Append one new SSO event with actor_id.
    actor = str(uuid.uuid4())
    await repo.append(_sso_envelope("operator_sso_login", action_taken="logged", actor_id=actor))

    result = await repo.validate_chain()
    assert result.is_valid, (
        f"Mixed-chain validation failed: {result.error_detail}. "
        "This indicates the actor_id hash_chain change broke an existing row's hash."
    )
    assert result.rows_checked >= 3
