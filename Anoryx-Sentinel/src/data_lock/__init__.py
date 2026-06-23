"""F-017 JSON Data-Lock Engine (ADR-0020).

A 6th post-response enforcement action: conditional, field-level withholding of
locked fields in the assistant's JSON output, governed by an F-008 ``data_lock``
policy.  Fail-closed by design (an error never releases a field).
"""
