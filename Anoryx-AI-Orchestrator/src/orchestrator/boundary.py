"""Persistence-boundary guards shared by the Orchestrator request seams.

A single home for the small structural checks every persistence boundary applies before
durably recording an inbound record. Postgres `text` and JSONB both categorically reject a
NUL (\\x00), so a NUL anywhere in a record would crash the persist / DLQ insert (a
non-IntegrityError → 503), leaving the record neither stored nor recorded — an
un-storable-poison + retry-storm class (O-003 audit M-2). Rejecting it at the boundary as
malformed (422) is a deterministic terminal disposition that does not loop. Reused by BOTH
the ingest (O-003) and policy-distribution (O-004) routers at every persistence boundary.
"""

from __future__ import annotations


def contains_nul(obj: object) -> bool:
    """Recursively detect a NUL (\\x00) in any string within *obj*.

    Returns True iff a \\x00 appears in any string key or value (dicts and lists are
    traversed recursively), else False. Postgres text/JSONB cannot store \\x00, so a positive
    result means the record must be rejected at the boundary (422) rather than 503'ing on the
    insert.
    """
    if isinstance(obj, str):
        return "\x00" in obj
    if isinstance(obj, dict):
        return any(contains_nul(k) or contains_nul(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(contains_nul(item) for item in obj)
    return False
