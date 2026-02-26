"""
GE_Phantom — Multiclient Router

Routes packets from multiple GE clients to separate RadarState instances.
Each client is identified by its unique local endpoint (ip:port).

Architecture:
  GESniffer → ClientRouter → per-client RadarState
                           → global RadarState (aggregated)
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Callable

from src.sniffer.capture import GEPacket
from src.data.state import RadarState


@dataclass
class ClientSession:
    """One game client's session, identified by local endpoint."""
    client_key: str          # "192.168.1.100:54321"
    label: str               # "Client 1" → upgrades to char name
    state: RadarState
    first_seen: float
    last_seen: float = 0.0
    reconnect_count: int = 0  # times this char reconnected on a new port

    def is_stale(self, timeout: float, now: float | None = None) -> bool:
        """Check if client hasn't been seen within timeout seconds."""
        now = now or time.time()
        return (now - self.last_seen) > timeout


ClientCallback = Callable[[ClientSession], None]


class ClientRouter:
    """Routes packets to per-client RadarState instances.

    Client identity = local endpoint (ip:port):
      - C2S packets: src_ip:src_port is the client
      - S2C packets: dst_ip:dst_port is the client

    Features:
      - Stale pruning: remove clients not seen within a timeout
      - Reconnect detection: same character name on a new port
    """

    # Default stale timeout: 5 minutes of no packets
    DEFAULT_STALE_TIMEOUT: float = 300.0

    def __init__(self, my_chars: list[str] | None = None):
        self._my_chars = my_chars
        self.clients: dict[str, ClientSession] = {}
        self.global_state: RadarState = RadarState(my_chars=my_chars)
        self._next_label: int = 1
        self._callbacks: list[ClientCallback] = []
        self._lock = threading.Lock()
        # Map character name (lowercase) → client_key for reconnect detection
        self._char_to_key: dict[str, str] = {}

    def process_packet(self, pkt: GEPacket) -> tuple[str, dict | None]:
        """Route packet to correct client. Returns (client_key, decoded)."""
        key = self._identify(pkt)

        with self._lock:
            session = self.clients.get(key)
            if session is None:
                session = self._create_session(key, pkt.timestamp)

        session.last_seen = pkt.timestamp

        # Feed to per-client state
        decoded = session.state.process_packet(pkt)
        # Feed to global state
        self.global_state.process_packet(pkt)

        # Try to upgrade label from decoded data
        if decoded:
            self._maybe_upgrade_label(session, decoded)

        return key, decoded

    def _identify(self, pkt: GEPacket) -> str:
        """Extract client key from packet."""
        if pkt.direction == "C2S":
            return f"{pkt.src_ip}:{pkt.src_port}"
        else:  # S2C
            return f"{pkt.dst_ip}:{pkt.dst_port}"

    def _create_session(self, key: str, timestamp: float) -> ClientSession:
        """Create a new ClientSession. Must be called under _lock."""
        label = f"Client {self._next_label}"
        self._next_label += 1
        session = ClientSession(
            client_key=key,
            label=label,
            state=RadarState(my_chars=self._my_chars),
            first_seen=timestamp,
            last_seen=timestamp,
        )
        self.clients[key] = session

        # Notify subscribers (outside lock would be ideal but keeping simple)
        for cb in self._callbacks:
            try:
                cb(session)
            except Exception:
                pass

        return session

    def _maybe_upgrade_label(self, session: ClientSession, decoded: dict) -> None:
        """If ITEM_DROP has owner_name, upgrade label from 'Client N' to char name.

        Also handles reconnect detection: if another session already has this
        character name, the old session is stale — transfer identity.
        """
        if decoded.get("name") != "ITEM_DROP":
            return
        owner = decoded.get("owner_name", "").strip()
        if not owner:
            return
        # Only upgrade if still using default label
        if not session.label.startswith("Client "):
            return

        owner_lower = owner.lower()

        with self._lock:
            old_key = self._char_to_key.get(owner_lower)
            if old_key and old_key != session.client_key:
                # Reconnect: same char, new port
                old_session = self.clients.get(old_key)
                if old_session:
                    session.reconnect_count = old_session.reconnect_count + 1
                    # Remove old stale session
                    del self.clients[old_key]

            session.label = owner
            self._char_to_key[owner_lower] = session.client_key

    def get_active_clients(self) -> list[ClientSession]:
        """List clients sorted by last_seen (most recent first)."""
        with self._lock:
            sessions = list(self.clients.values())
        return sorted(sessions, key=lambda s: s.last_seen, reverse=True)

    def get_client_by_index(self, index: int) -> ClientSession | None:
        """Get client by 1-based index (for keybind switching)."""
        sessions = self.get_active_clients()
        if 1 <= index <= len(sessions):
            return sessions[index - 1]
        return None

    def on_client_discovered(self, callback: ClientCallback) -> None:
        """Subscribe to new client events."""
        self._callbacks.append(callback)

    def prune_stale(self, timeout: float | None = None, now: float | None = None) -> list[ClientSession]:
        """Remove clients not seen within timeout seconds.

        Returns list of pruned sessions (for logging/notification).
        """
        timeout = timeout if timeout is not None else self.DEFAULT_STALE_TIMEOUT
        now = now or time.time()
        pruned: list[ClientSession] = []

        with self._lock:
            stale_keys = [
                key for key, session in self.clients.items()
                if session.is_stale(timeout, now)
            ]
            for key in stale_keys:
                session = self.clients.pop(key)
                pruned.append(session)
                # Clean up char→key mapping
                label_lower = session.label.lower()
                if self._char_to_key.get(label_lower) == key:
                    del self._char_to_key[label_lower]

        return pruned

    def find_client_by_char(self, char_name: str) -> ClientSession | None:
        """Find a client session by character name (case-insensitive)."""
        with self._lock:
            key = self._char_to_key.get(char_name.lower())
            if key:
                return self.clients.get(key)
        return None
