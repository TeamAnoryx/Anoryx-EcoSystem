"""Agent-messaging hash chain (O-012, ADR-0012): canonicalization + tamper-evidence.

Pure tests over the messaging chain functions in persistence.hash_chain. Unlike the
identity/automation chains, MESSAGING_CANONICAL_FIELDS has NO opt-in-when-present fields
— every field (including disposition: 'sent' | 'deduped') is always present on both a
fresh send and a deduped resend (ADR-0012's "every attempt" semantics).
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.MESSAGING_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.AUTOMATION_GENESIS_HASH
    assert hc.MESSAGING_GENESIS_HASH != hc.STATE_GENESIS_HASH
    assert len(hc.MESSAGING_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_messaging_row_hash({"tenant_id": "t-a", "disposition": "sent"})


def _base_row(**overrides):
    row = {
        "tenant_id": "t-a",
        "sender_agent_id": "agent-a",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "idempotency_key": "msg-1",
        "disposition": "sent",
        "prev_hash": hc.MESSAGING_GENESIS_HASH,
    }
    row.update(overrides)
    return row


def test_sent_and_deduped_both_hash_and_differ() -> None:
    sent = _base_row()
    deduped = _base_row(disposition="deduped")
    h_sent = hc.compute_messaging_row_hash(sent)
    h_deduped = hc.compute_messaging_row_hash(deduped)
    assert h_sent != h_deduped
    assert hc.verify_messaging_row_hash(sent, h_sent)
    assert hc.verify_messaging_row_hash(deduped, h_deduped)


def test_tamper_breaks_verification() -> None:
    row = _base_row()
    stored = hc.compute_messaging_row_hash(row)
    tampered = {**row, "disposition": "deduped"}
    assert not hc.verify_messaging_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = _base_row()
    h1 = hc.compute_messaging_row_hash(first)
    second = _base_row(idempotency_key="msg-2", disposition="deduped", prev_hash=h1)
    h2 = hc.compute_messaging_row_hash(second)
    assert h1 != h2
    assert hc.verify_messaging_row_hash(second, h2)


def test_missing_optional_fields_absent_from_canonical_fields() -> None:
    """Unlike identity/automation, the messaging chain has NO opt-in-when-present field —
    every CANONICAL_FIELDS member is always present, so an extra unrelated key in the input
    dict never changes the hash (only MESSAGING_CANONICAL_FIELDS members are folded in)."""
    base = _base_row()
    with_extra = {**base, "some_unrelated_key": "should be ignored"}
    assert hc.compute_messaging_row_hash(base) == hc.compute_messaging_row_hash(with_extra)
