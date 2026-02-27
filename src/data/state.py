"""
GE_Phantom — Shared Game State

Extracted from tools/item_radar.py and extended with:
- CharacterInfo: tracks attack range, speed, state, zone from decoded packets
- PacketStats: rate counter (packets/sec by type)
- on_update callback: lets the dashboard subscribe to state changes
"""

from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable

from src.sniffer.capture import GEPacket
from src.protocol.packet_types import decode_packet


# ---- Data classes ----

@dataclass
class Entity:
    """Tracked entity in the game world."""
    entity_id: int
    x: int = 0
    y: int = 0
    last_seen: float = 0.0
    entity_type: str = "unknown"  # "monster", "player", "item", "npc", "object"
    name: str = ""


@dataclass
class ItemDrop:
    """A detected item drop."""
    timestamp: float
    entity_id: int
    item_id: int
    count: int
    x: int
    y: int
    owner_name: str
    owner_eid: int
    picked_up: bool = False


@dataclass
class CharacterInfo:
    """Extended character details built from multiple packet types."""
    entity_id: int
    attack_range: float = 0.0
    speed: float = 0.0
    state_flags: int = 0
    zone: int = 0
    stance_guess: str = ""  # inferred from speed + range patterns


class PacketStats:
    """Rate counter for packets per second, by type and total."""

    def __init__(self, window: float = 5.0):
        self._window = window
        self._timestamps: deque[float] = deque()
        self._type_timestamps: dict[str, deque[float]] = defaultdict(deque)

    def record(self, packet_name: str, ts: float | None = None) -> None:
        ts = ts or time.time()
        self._timestamps.append(ts)
        self._type_timestamps[packet_name].append(ts)

    def _prune(self, q: deque[float], now: float) -> None:
        while q and q[0] < now - self._window:
            q.popleft()

    def rate(self) -> float:
        """Overall packets/sec over the window."""
        now = time.time()
        self._prune(self._timestamps, now)
        if not self._timestamps:
            return 0.0
        return len(self._timestamps) / self._window

    def rate_by_type(self, name: str) -> float:
        """Packets/sec for a specific type."""
        now = time.time()
        q = self._type_timestamps.get(name)
        if not q:
            return 0.0
        self._prune(q, now)
        return len(q) / self._window


# ---- State tracker ----

# Callback type: called with (event_type, data_dict)
# event_type: "packet", "drop", "despawn", "spawn", "position", "combat"
UpdateCallback = Callable[[str, dict], None]


@dataclass
class ZoneTransition:
    """Records a zone change."""
    timestamp: float
    from_zone: int
    to_zone: int


class RadarState:
    """Tracks all game state from decoded packets."""

    def __init__(self, my_chars: list[str] | None = None):
        self.my_chars = set(c.lower() for c in (my_chars or []))
        self.entities: dict[int, Entity] = {}
        self.item_drops: list[ItemDrop] = []
        self.active_drops: dict[int, ItemDrop] = {}  # entity_id -> drop
        self.combat_targets: dict[int, int] = {}  # attacker -> target
        self.characters: dict[int, CharacterInfo] = {}  # entity_id -> info
        self.packet_counts: defaultdict[str, int] = defaultdict(int)
        self.total_packets: int = 0
        self.start_time: float = time.time()
        self.stats: PacketStats = PacketStats()
        self._lock = threading.Lock()
        self._callbacks: list[UpdateCallback] = []
        # Zone tracking
        self.current_zone: int = 0
        self.zone_transitions: list[ZoneTransition] = []
        # Player tracking for distance calculation
        self.player_entity_id: int = 0
        self.player_x: int = 0
        self.player_y: int = 0

    def on_update(self, callback: UpdateCallback) -> None:
        """Subscribe to state changes."""
        self._callbacks.append(callback)

    def _notify(self, event_type: str, data: dict) -> None:
        for cb in self._callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def is_mine(self, owner_name: str) -> bool:
        """Check if an item belongs to one of our characters."""
        if not self.my_chars:
            return True  # No filter = show everything
        return owner_name.lower() in self.my_chars

    def distance_to_player(self, entity_id: int) -> float | None:
        """Calculate distance from player to an entity. Returns None if player position unknown."""
        if not self.player_entity_id or entity_id == self.player_entity_id:
            return None
        ent = self.entities.get(entity_id)
        if not ent or (ent.x == 0 and ent.y == 0):
            return None
        dx = ent.x - self.player_x
        dy = ent.y - self.player_y
        return (dx * dx + dy * dy) ** 0.5

    def process_packet(self, pkt: GEPacket) -> dict | None:
        """Process a captured packet and update state. Returns decoded dict or None."""
        self.total_packets += 1

        if not pkt.payload or len(pkt.payload) < 2:
            return None

        decoded = decode_packet(pkt.payload)
        if not decoded:
            return None

        name = decoded["name"]
        self.packet_counts[name] += 1
        self.stats.record(name, pkt.timestamp)

        with self._lock:
            match name:
                case "ENTITY_POSITION":
                    self._handle_position(decoded, pkt.timestamp)
                case "PLAYER_POSITION":
                    self._handle_player_position(decoded, pkt.timestamp)
                case "ITEM_DROP":
                    self._handle_item_drop(decoded, pkt.timestamp)
                case "ENTITY_DESPAWN":
                    self._handle_despawn(decoded)
                case "TARGET_LINK":
                    self._handle_target(decoded)
                case "MONSTER_SPAWN" | "ENTITY_SPAWN_B" | "OBJECT_SPAWN":
                    self._handle_spawn(decoded, name, pkt.timestamp)
                case "ENTITY_SPAWN_EX":
                    self._handle_spawn(decoded, name, pkt.timestamp)
                case "COMBAT_UPDATE":
                    self._handle_combat(decoded, pkt.timestamp)

        self._notify("packet", decoded)
        return decoded

    def _handle_position(self, d: dict, ts: float) -> None:
        eid = d.get("entity_id", 0)
        if not eid:
            return
        ent = self.entities.get(eid)
        if not ent:
            ent = Entity(entity_id=eid, entity_type="unknown")
            self.entities[eid] = ent
        ent.x = d.get("x", ent.x)
        ent.y = d.get("y", ent.y)
        ent.last_seen = ts

        # Update character speed/state/zone if we have a CharacterInfo
        speed = d.get("speed")
        state = d.get("state")
        zone = d.get("zone")
        if eid in self.characters:
            ci = self.characters[eid]
            if speed is not None:
                ci.speed = speed
            if state is not None:
                ci.state_flags = state
            if zone is not None:
                ci.zone = zone
        elif speed is not None:
            # Create a CharacterInfo entry from position data
            self.characters[eid] = CharacterInfo(
                entity_id=eid,
                speed=speed if speed else 0.0,
                state_flags=state if state else 0,
                zone=zone if zone else 0,
            )

        # Track zone transitions
        if zone is not None and zone > 0 and zone != self.current_zone:
            old_zone = self.current_zone
            self.current_zone = zone
            if old_zone > 0:
                self.zone_transitions.append(
                    ZoneTransition(timestamp=ts, from_zone=old_zone, to_zone=zone)
                )
                self._notify("zone_change", {
                    "from_zone": old_zone, "to_zone": zone, "timestamp": ts,
                })

        self._notify("position", d)

    def _handle_player_position(self, d: dict, ts: float) -> None:
        """Handle PLAYER_POSITION — uses f64 coordinates."""
        eid = d.get("entity_id", 0)
        if not eid:
            return
        ent = self.entities.get(eid)
        if not ent:
            ent = Entity(entity_id=eid, entity_type="player")
            self.entities[eid] = ent
        # PLAYER_POSITION uses f64, convert to int for consistency
        x = d.get("x")
        y = d.get("y")
        if x is not None:
            ent.x = int(x)
        if y is not None:
            ent.y = int(y)
        ent.entity_type = "player"
        ent.last_seen = ts
        # Track player position for distance calculations
        self.player_entity_id = eid
        self.player_x = ent.x
        self.player_y = ent.y
        self._notify("position", d)

    def _handle_item_drop(self, d: dict, ts: float) -> None:
        drop = ItemDrop(
            timestamp=ts,
            entity_id=d.get("entity_id", 0),
            item_id=d.get("item_id", 0),
            count=d.get("count", 1),
            x=d.get("x", 0),
            y=d.get("y", 0),
            owner_name=d.get("owner_name", ""),
            owner_eid=d.get("owner_eid", 0),
        )
        self.item_drops.append(drop)
        self.active_drops[drop.entity_id] = drop
        self._notify("drop", d)

    def _handle_despawn(self, d: dict) -> None:
        eid = d.get("entity_id", 0)
        if eid in self.active_drops:
            self.active_drops[eid].picked_up = True
            del self.active_drops[eid]
        self.entities.pop(eid, None)
        self._notify("despawn", d)

    def _handle_target(self, d: dict) -> None:
        attacker = d.get("attacker_id", 0)
        target = d.get("target_id", 0)
        if attacker and target:
            self.combat_targets[attacker] = target

    def _handle_spawn(self, d: dict, spawn_type: str, ts: float) -> None:
        eid = d.get("entity_id", 0)
        if not eid:
            return
        etype = {
            "MONSTER_SPAWN": "monster",
            "ENTITY_SPAWN_B": "monster",  # same 371b structure — not NPC-specific
            "ENTITY_SPAWN_EX": "monster",
            "OBJECT_SPAWN": "object",
        }.get(spawn_type, "unknown")
        self.entities[eid] = Entity(entity_id=eid, entity_type=etype, last_seen=ts)
        self._notify("spawn", d)

    def _handle_combat(self, d: dict, ts: float) -> None:
        eid = d.get("entity_id", 0)
        if not eid:
            return
        attack_range = d.get("attack_range")

        if eid not in self.characters:
            self.characters[eid] = CharacterInfo(entity_id=eid)
        ci = self.characters[eid]
        if attack_range is not None:
            ci.attack_range = attack_range

        # Also ensure entity exists
        if eid not in self.entities:
            self.entities[eid] = Entity(entity_id=eid, last_seen=ts)
        self.entities[eid].last_seen = ts

        self._notify("combat", d)
