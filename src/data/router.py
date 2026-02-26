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


ClientCallback = Callable[[ClientSession], None]


class ClientRouter:
    """Routes packets to per-client RadarState instances.

    Client identity = local endpoint (ip:port):
      - C2S packets: src_ip:src_port is the client
      - S2C packets: dst_ip:dst_port is the client
    """

    def __init__(self, my_chars: list[str] | None = None):
        self._my_chars = my_chars
        self.clients: dict[str, ClientSession] = {}
        self.global_state: RadarState = RadarState(my_chars=my_chars)
        self._next_label: int = 1
        self._callbacks: list[ClientCallback] = []
        self._lock = threading.Lock()

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
        """If ITEM_DROP has owner_name, upgrade label from 'Client N' to char name."""
        if decoded.get("name") != "ITEM_DROP":
            return
        owner = decoded.get("owner_name", "").strip()
        if not owner:
            return
        # Only upgrade if still using default label
        if session.label.startswith("Client "):
            session.label = owner

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
