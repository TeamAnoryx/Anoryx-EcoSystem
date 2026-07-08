"""Stream key epochs — an encrypted-live-streaming key-management seam (R-014).

HONESTY BOUNDARY (verbatim, non-removable): the roadmap names R-014 "Encrypted
live-streaming infrastructure... high-fidelity encrypted live-streaming for
confidential investor updates + global all-hands" (Heavy, 28h+, 🏦
POST-INVESTMENT, depends on R-007 + R-013). "High-fidelity" and "global
all-hands" describe the funded-future vision: a media-server (SFU) fan-out to
an effectively unbounded viewer audience. That delivery is structurally
impossible within this codebase's LOCKED architecture — ``contracts/
openapi.yaml`` states, verbatim, "Media is ALWAYS full-mesh P2P — there is no
SFU/media-relay tier, regardless of participant count. Rendly never sees or
forwards huddle media" (R-001 D4). ADR-0011's own Alternatives section already
named building an SFU as "a fundamental architecture reversal... this task
does not have license for" when R-011 first touched this boundary, and
ADR-0013 (R-013) reaffirmed it when deferring "large-scale" delivery to this
very task. Nothing in this module lifts or narrows that lock: a genuine
one-to-many broadcast tier remains a separate, dedicated architecture/security
decision this task does not make.

What ships here, in the same deliberate scope-down spirit as O-009/O-010/
O-011/R-012/R-013 (see ADR-0014 §Decision), is the cryptographic key-management
seam a real encrypted-streaming feature needs regardless of transport
topology: minting a random per-session master key ("epoch"), rotating it
(fresh randomness, no derivation from the retired epoch — full forward
secrecy on rotation), and deriving a distinct per-participant sub-key from an
epoch via HKDF-SHA256. This is the same "insertable streams" per-sender-key
pattern real E2EE video-conferencing products layer on top of WebRTC's own
mandatory DTLS-SRTP transport encryption — it is additive application-layer
protection, not a replacement for it. Every derived key is scoped to the
EXISTING R-013 ``EventSession`` (itself capacity-bounded to R-011's 2-8
participant P2P huddle), so this module never claims a participant count the
signaling layer cannot honor.

Explicitly NOT built here (named, not silently skipped — see ADR-0014):
- No SFU / media relay / broadcast fan-out. See the honesty boundary above.
- No actual media-frame encryption/decryption. Applying a derived key to real
  RTP frames is client-side (WebRTC Insertable Streams / a media pipeline),
  entirely out of a Python backend seam's reach.
- No wiring into ``realtime/pipeline.py`` or ``realtime/ws.py``. Distributing
  an epoch's per-participant keys to live peers needs a new signaling message
  (e.g. a ``stream_key.rotate`` frame) — a follow-up task owns that wire
  surface, mirroring how R-013 deferred its own live-huddle binding.
- No persistence. Epochs are minted and rotated in memory by the caller,
  exactly as R-013's ``schedule_session`` holds no state of its own — a
  follow-up task owns a ``rendly.stream_key_epochs`` audit table (rotation
  history, never the key material itself) mirroring R-009's archive pattern.
- No REST/wire surface, no ``policy.schema.json``/``contracts/openapi.yaml``
  change.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .common import require_aware_utc
from .event import MAX_SESSION_CAPACITY, EventSession

# A stream key epoch's master key is 256 bits — matches this codebase's existing symmetric
# key size discipline (nothing smaller ships elsewhere in Rendly).
_MASTER_KEY_BYTES = 32
_DERIVED_KEY_BYTES = 32

# Deliberately reuses R-013's `EventSession` capacity bound rather than defining a third
# sibling constant: unlike `event.py`'s own realtime -> domain layering concern (ADR-0013
# Fork B), `stream_crypto.py` and `event.py` are BOTH domain-layer modules, so importing
# across them inverts nothing — it is the same intra-domain sharing `event.py` already does
# with `profile.py`. A roster this module is asked to derive keys for can never legitimately
# exceed the session's own capacity bound, because a session is, mechanically, still an R-011
# group huddle (see the module honesty boundary above).
MAX_STREAM_PARTICIPANTS = MAX_SESSION_CAPACITY

_EPOCH_SALT_PREFIX = b"rendly:stream-key:v1"
_PARTICIPANT_INFO_PREFIX = b"rendly:stream-participant:v1"


@dataclass(frozen=True, kw_only=True)
class StreamKeyEpoch:
    """One generation of a live-stream session's master encryption key.

    Immutable. ``master_key`` is genuinely secret material — excluded from the
    dataclass's generated ``repr`` (``field(repr=False)``) so it can never end up
    in a log line or an uncaught-exception traceback by accident, mirroring how
    ``auth/keys.py``'s ``KeyMaterial`` never exposes raw private-key bytes either.
    """

    session_id: str
    tenant_id: str
    epoch: int
    created_at: datetime
    master_key: bytes = field(repr=False)


def mint_key_epoch(session: EventSession, *, now: datetime) -> StreamKeyEpoch:
    """Mint the first key epoch (epoch 0) for a real, already-validated ``EventSession``.

    ``session_id``/``tenant_id`` are read FROM the session, mirroring
    :func:`rendly.event.bind_event`/:func:`rendly.culture.bind_culture_opt_in` — an
    epoch's identity is derived from a validated session, never hand-supplied. The
    master key is fresh cryptographic randomness (``os.urandom``), never derived
    from anything the caller supplies.
    """
    created_at = require_aware_utc(now, "created_at")
    return StreamKeyEpoch(
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        epoch=0,
        created_at=created_at,
        master_key=os.urandom(_MASTER_KEY_BYTES),
    )


def rotate_key_epoch(previous: StreamKeyEpoch, *, now: datetime) -> StreamKeyEpoch:
    """Rotate to the next key epoch for the SAME session.

    A rotation should be triggered by the caller whenever a participant leaves a
    live session (mirrors ADR-0011 Fork D's leave semantics one layer up): once
    rotated, every FUTURE :func:`derive_participant_key` call for this session
    uses the new epoch's fresh, independently-random master key, so a departed
    participant's previously-derived key material grants no access to anything
    encrypted under a later epoch (forward secrecy on rotation) — the new key is
    NOT derived from ``previous.master_key`` in any way.

    Raises ``ValueError`` if ``now`` does not strictly follow the previous
    epoch's ``created_at`` (epochs for one session are strictly ordered in time,
    the same monotonic discipline ``rendly.event.schedule_session`` applies to a
    single host's agenda).
    """
    created_at = require_aware_utc(now, "created_at")
    if created_at <= previous.created_at:
        raise ValueError("a rotated epoch's created_at must strictly follow the previous epoch")
    return StreamKeyEpoch(
        session_id=previous.session_id,
        tenant_id=previous.tenant_id,
        epoch=previous.epoch + 1,
        created_at=created_at,
        master_key=os.urandom(_MASTER_KEY_BYTES),
    )


def derive_participant_key(epoch: StreamKeyEpoch, participant_id: str) -> bytes:
    """Derive a distinct 256-bit sub-key for one participant from an epoch's master key.

    HKDF-SHA256 (RFC 5869): ``salt`` binds the derivation to this exact
    ``(session_id, epoch)`` pair so the same participant id derives a DIFFERENT
    key under a different session or a later epoch; ``info`` binds it to the
    participant so two different participants under the SAME epoch derive
    DIFFERENT keys from the same master secret. Deterministic — the same
    ``(epoch, participant_id)`` pair always derives the same key, so peers who
    already hold an epoch's master key (distributed out-of-band by a future
    signaling follow-up, see the module honesty boundary) can each derive
    every other live participant's key locally without a second round-trip.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_DERIVED_KEY_BYTES,
        salt=_EPOCH_SALT_PREFIX + f"{epoch.session_id}:{epoch.epoch}".encode("utf-8"),
        info=_PARTICIPANT_INFO_PREFIX + participant_id.encode("utf-8"),
    )
    return hkdf.derive(epoch.master_key)


def derive_roster_keys(epoch: StreamKeyEpoch, roster: Sequence[str]) -> dict[str, bytes]:
    """Derive one sub-key per participant for the whole live roster of an epoch's session.

    Validates, in order: ``roster`` is non-empty (a stream with nobody in it has
    no key to derive), ``len(roster) <= MAX_STREAM_PARTICIPANTS`` (bounded-list
    discipline mirroring ``culture.py``'s ``MAX_CANDIDATES``/``event.py``'s
    ``MAX_SESSIONS_PER_EVENT``), and every entry is unique (a duplicate id would
    silently overwrite its own derived key in the returned mapping). Raises
    ``ValueError`` on any violation; never silently drops or truncates.
    """
    if not roster:
        raise ValueError("roster must not be empty")
    if len(roster) > MAX_STREAM_PARTICIPANTS:
        raise ValueError(f"roster must not exceed {MAX_STREAM_PARTICIPANTS} participants")
    if len(set(roster)) != len(roster):
        raise ValueError("roster must not contain duplicate participant ids")
    return {
        participant_id: derive_participant_key(epoch, participant_id) for participant_id in roster
    }
