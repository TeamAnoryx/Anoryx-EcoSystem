"""In-process connection registry + the live Connection (R-005 FORK B = single-instance).

Tracks which live WebSocket connections belong to which (tenant, channel) so a ``chat.message``
fans out only to the right sockets. SINGLE-INSTANCE (stated limitation): the registry is in this
process only — a second app instance would not see these connections. Cross-instance fan-out
(Redis pub/sub or Postgres LISTEN/NOTIFY) is a DOCUMENTED SEAM (ADR-0005 Fork B), NOT built here.

CROSS-TENANT ISOLATION (structural): buckets are keyed by ``(tenant_id, channel_id)`` and a
connection only ever registers under ITS OWN tenant's channels (its membership set was loaded
under its own tenant session, so RLS already scoped it). A fan-out for ``(tenantB, channel)``
therefore can only reach connections registered under ``(tenantB, channel)`` — a tenant-A socket
is never in a tenant-B bucket. This is the live-delivery half of the tenant isolation spine; the
storage half is RLS on the chat tables.

Everything runs on the app's single asyncio event loop (cooperative, no threads), so the dict
mutations need no lock; the only care is to SNAPSHOT a bucket to a list before awaiting sends,
since a send that fails may trigger a disconnect that mutates the bucket.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from starlette.websockets import WebSocket


# eq=False keeps object-identity __eq__ + __hash__: each live socket is a distinct connection,
# and the registry stores connections in sets/dicts keyed by identity (two connections are never
# "equal" by field value — the same user may hold several).
@dataclass(eq=False)
class Connection:
    """One authenticated live WebSocket. Identity is OFF THE TOKEN (never client-supplied)."""

    websocket: WebSocket
    tenant_id: str
    user_id: str
    scopes: frozenset[str]
    # The channels this connection delivers — a SNAPSHOT of the user's memberships at connect
    # (FORK B stated boundary: a member added mid-session receives after reconnect; send-authz
    # always re-checks live DB membership regardless).
    channels: set[str] = field(default_factory=set)
    # Ephemeral live presence (FORK E): online at connect, mutated by presence.set, never
    # persisted. Lost on disconnect / restart.
    presence: str = "online"

    async def send(self, frame: dict) -> bool:
        """Send a frame; return False if the socket was already closed (best-effort fan-out)."""
        try:
            await self.websocket.send_json(frame)
            return True
        except Exception:  # noqa: BLE001 - a dead socket must not break fan-out to the others
            return False


class ConnectionRegistry:
    """Single-process registry: (tenant, channel) -> connections, and (tenant, user) -> conns."""

    def __init__(self) -> None:
        self._by_channel: dict[tuple[str, str], set[Connection]] = {}
        self._by_user: dict[tuple[str, str], set[Connection]] = {}

    def add(self, conn: Connection) -> None:
        for channel_id in conn.channels:
            self._by_channel.setdefault((conn.tenant_id, channel_id), set()).add(conn)
        self._by_user.setdefault((conn.tenant_id, conn.user_id), set()).add(conn)

    def discard(self, conn: Connection) -> None:
        for channel_id in conn.channels:
            bucket = self._by_channel.get((conn.tenant_id, channel_id))
            if bucket is not None:
                bucket.discard(conn)
                if not bucket:
                    del self._by_channel[(conn.tenant_id, channel_id)]
        user_key = (conn.tenant_id, conn.user_id)
        users = self._by_user.get(user_key)
        if users is not None:
            users.discard(conn)
            if not users:
                del self._by_user[user_key]

    def remove_user_from_channel(self, *, tenant_id: str, channel_id: str, user_id: str) -> None:
        """Evict a user's live connections from a channel (called when membership is REVOKED).

        Single-instance: a DELETE-member only removes the DB row, so without this the removed
        user's open socket would keep receiving the channel's fan-out until they reconnect. This
        drops the channel from each of the user's connections' delivered set AND from the
        (tenant, channel) bucket, so a subsequent chat.message/typing/presence for that channel is
        never delivered to them. Their socket stays up for their other channels. (Cross-instance
        eviction is the documented Redis/LISTEN-NOTIFY seam — not built here.)
        """
        bucket_key = (tenant_id, channel_id)
        bucket = self._by_channel.get(bucket_key)
        for conn in list(self._by_user.get((tenant_id, user_id), ())):
            conn.channels.discard(channel_id)
            if bucket is not None:
                bucket.discard(conn)
        if bucket is not None and not bucket:
            del self._by_channel[bucket_key]

    def channel_connections(self, tenant_id: str, channel_id: str) -> list[Connection]:
        """A SNAPSHOT list of the connections in a (tenant, channel) bucket."""
        return list(self._by_channel.get((tenant_id, channel_id), ()))

    def user_connections(self, tenant_id: str, user_id: str) -> list[Connection]:
        """A SNAPSHOT list of a user's live connections (R-007 huddle signaling target lookup).

        Structurally tenant-scoped like every other lookup here: a connection only ever registers
        under its OWN tenant (``add`` above), so this can never return a connection from another
        tenant — the R-007 huddle authz spine (peer must have a live connection in the SAME
        tenant) rests on this, not on a separate DB check.
        """
        return list(self._by_user.get((tenant_id, user_id), ()))

    def sharing_connections(self, conn: Connection) -> list[Connection]:
        """Connections that share at least one channel with ``conn`` (presence audience)."""
        seen: set[Connection] = set()
        for channel_id in conn.channels:
            for other in self._by_channel.get((conn.tenant_id, channel_id), ()):
                seen.add(other)
        return list(seen)

    async def broadcast_channel(
        self, *, tenant_id: str, channel_id: str, frame: dict, exclude: Connection | None = None
    ) -> None:
        """Fan a frame out to every live connection in a (tenant, channel) bucket."""
        for conn in self.channel_connections(tenant_id, channel_id):
            if conn is exclude:
                continue
            await conn.send(frame)
