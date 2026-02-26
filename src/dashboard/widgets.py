"""
GE_Phantom Dashboard — Panel Widgets

Four panels for the TUI dashboard:
1. TrafficPanel  — live decoded packet log
2. EntityPanel   — tracked entities table + character detail
3. DropPanel     — item drops table with summary
4. SessionPanel  — session stats overview
"""

from __future__ import annotations

import time

from rich.text import Text
from textual.message import Message
from textual.widgets import Static, RichLog, DataTable
from textual.containers import Vertical

from src.data.state import RadarState, Entity, ItemDrop, CharacterInfo
from src.data.router import ClientRouter, ClientSession
from src.data.items import item_name, item_name_short


def _fmt_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _fmt_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    return f"{m}m{s:02d}s"


# ---- Color map for packet types ----

_PACKET_COLORS: dict[str, str] = {
    "ITEM_DROP": "yellow",
    "ITEM_EVENT": "yellow",
    "COMBAT_UPDATE": "red",
    "COMBAT_DATA": "red",
    "TARGET_LINK": "red",
    "MONSTER_SPAWN": "bright_red",
    "NPC_SPAWN": "blue",
    "OBJECT_SPAWN": "dim",
    "ENTITY_DESPAWN": "dim",
    "ENTITY_POSITION": "bright_black",
    "PLAYER_POSITION": "green",
    "BATCH_ENTITY_UPDATE": "bright_black",
    "ENTITY_EVENT": "cyan",
    "EFFECT": "magenta",
    "HEARTBEAT": "bright_black",
    "ACK": "bright_black",
    "KEEPALIVE": "bright_black",
    "PLAYER_ACTION": "green",
}

_ENTITY_COLORS: dict[str, str] = {
    "monster": "red",
    "npc": "blue",
    "player": "green",
    "item": "yellow",
    "object": "dim",
    "unknown": "white",
}


# ---- 1. Traffic Panel ----

class TrafficPanel(Vertical):
    """Live decoded packet log with rate display."""

    def compose(self):
        yield Static("", id="traffic-rate")
        yield RichLog(highlight=True, markup=True, max_lines=500, id="traffic-log")

    def log_packet(self, decoded: dict, state: RadarState) -> None:
        """Add a decoded packet to the log."""
        log: RichLog = self.query_one("#traffic-log", RichLog)
        rate_label: Static = self.query_one("#traffic-rate", Static)

        name = decoded["name"]
        size = decoded.get("size", 0)
        color = _PACKET_COLORS.get(name, "white")

        # Build summary of key fields
        fields = []
        for key in ("entity_id", "x", "y", "item_id", "count", "owner_name",
                     "attacker_id", "target_id", "attack_range", "speed", "zone"):
            if key in decoded:
                val = decoded[key]
                if key == "item_id" and isinstance(val, int):
                    fields.append(f"item={item_name(val)}")
                elif isinstance(val, float):
                    fields.append(f"{key}={val:.0f}")
                else:
                    fields.append(f"{key}={val}")
        field_str = " ".join(fields)

        ts = _fmt_time(time.time())
        text = Text()
        text.append(f"[{ts}] ", style="bright_black")
        text.append(f"{name}", style=f"bold {color}")
        text.append(f" ({size}b)", style="bright_black")
        if field_str:
            text.append(f" {field_str}", style=color)

        log.write(text)

        # Update rate display
        rate = state.stats.rate()
        rate_label.update(f" {rate:.1f} pkt/s | {state.total_packets} total")

    def clear_log(self) -> None:
        log: RichLog = self.query_one("#traffic-log", RichLog)
        log.clear()


# ---- 2. Entity Panel ----

class EntityPanel(Vertical):
    """Tracked entities table with character detail view."""

    def compose(self):
        table = DataTable(id="entity-table")
        table.cursor_type = "row"
        yield table
        yield Static("Select an entity to see details", id="char-detail")

    def on_mount(self) -> None:
        table: DataTable = self.query_one("#entity-table", DataTable)
        table.add_columns("ID", "Type", "Position", "Speed", "Range", "Zone", "Last Seen")

    def refresh_entities(self, state: RadarState) -> None:
        """Rebuild the entity table from current state."""
        table: DataTable = self.query_one("#entity-table", DataTable)
        table.clear()

        with state._lock:
            # Sort by last_seen descending
            entities = sorted(
                state.entities.values(),
                key=lambda e: e.last_seen,
                reverse=True,
            )

        now = time.time()
        for ent in entities[:200]:  # cap display at 200
            ci = state.characters.get(ent.entity_id)
            color = _ENTITY_COLORS.get(ent.entity_type, "white")

            eid_text = Text(str(ent.entity_id), style=color)
            type_text = Text(ent.entity_type, style=f"bold {color}")
            pos_text = Text(f"({ent.x}, {ent.y})")

            speed_text = Text(f"{ci.speed:.0f}" if ci and ci.speed else "-")
            range_text = Text(f"{ci.attack_range:.0f}" if ci and ci.attack_range else "-")
            zone_text = Text(str(ci.zone) if ci and ci.zone else "-")

            ago = now - ent.last_seen if ent.last_seen else 0
            if ago < 2:
                seen_text = Text("now", style="green")
            elif ago < 10:
                seen_text = Text(f"{ago:.0f}s ago", style="yellow")
            else:
                seen_text = Text(f"{ago:.0f}s ago", style="dim")

            table.add_row(eid_text, type_text, pos_text, speed_text, range_text, zone_text, seen_text,
                          key=str(ent.entity_id))

    def show_detail(self, entity_id: int, state: RadarState) -> None:
        """Show character detail for a selected entity."""
        detail: Static = self.query_one("#char-detail", Static)
        ent = state.entities.get(entity_id)
        ci = state.characters.get(entity_id)

        if not ent:
            detail.update("Entity not found")
            return

        lines = [f"Entity #{ent.entity_id} ({ent.entity_type})  pos=({ent.x}, {ent.y})"]
        if ci:
            lines.append(
                f"  range={ci.attack_range:.0f}  speed={ci.speed:.0f}  "
                f"zone={ci.zone}  state=0x{ci.state_flags:08x}  "
                f"stance={ci.stance_guess or '?'}"
            )
        target = state.combat_targets.get(entity_id)
        if target:
            lines.append(f"  targeting -> #{target}")
        detail.update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """When user highlights a row, show detail."""
        if event.row_key and event.row_key.value:
            try:
                eid = int(event.row_key.value)
                # The app will call show_detail with the state
                self.post_message(EntitySelected(eid))
            except (ValueError, TypeError):
                pass


class EntitySelected(Message):
    """Custom message when an entity row is selected."""

    def __init__(self, entity_id: int) -> None:
        self.entity_id = entity_id
        super().__init__()


# ---- 3. Drop Panel ----

class DropPanel(Vertical):
    """Item drops table with summary stats."""

    def compose(self):
        yield Static("", id="drop-summary")
        table = DataTable(id="drop-table")
        table.cursor_type = "row"
        yield table

    def on_mount(self) -> None:
        table: DataTable = self.query_one("#drop-table", DataTable)
        table.add_columns("Time", "Item", "Count", "Position", "Owner", "Status")

    def refresh_drops(self, state: RadarState) -> None:
        """Rebuild drops table."""
        table: DataTable = self.query_one("#drop-table", DataTable)
        summary: Static = self.query_one("#drop-summary", Static)
        table.clear()

        with state._lock:
            drops = list(state.item_drops)
            n_active = len(state.active_drops)

        n_mine = sum(1 for d in drops if state.is_mine(d.owner_name))

        summary.update(
            f" Drops: {len(drops)} total | {n_active} on ground | {n_mine} mine"
        )

        # Show most recent first, cap at 200
        for drop in reversed(drops[-200:]):
            is_mine = state.is_mine(drop.owner_name)
            mine_style = "bold yellow" if is_mine else ""

            ts_text = Text(_fmt_time(drop.timestamp))
            item_text = Text(item_name(drop.item_id), style=mine_style or "white")
            count_text = Text(str(drop.count))
            pos_text = Text(f"({drop.x}, {drop.y})")
            owner_text = Text(drop.owner_name, style=mine_style or "white")

            if drop.picked_up:
                status_text = Text("picked up", style="dim")
            else:
                status_text = Text("ON GROUND", style="bold green")

            table.add_row(ts_text, item_text, count_text, pos_text, owner_text, status_text)


# ---- 4. Session Panel ----

class SessionPanel(Vertical):
    """Session overview with stats."""

    def compose(self):
        yield Static("Waiting for data...", id="session-stats")

    def refresh_session(self, state: RadarState) -> None:
        """Update session overview."""
        stats: Static = self.query_one("#session-stats", Static)

        elapsed = time.time() - state.start_time
        rate = state.stats.rate()

        with state._lock:
            n_entities = len(state.entities)
            n_active = len(state.active_drops)
            n_drops = len(state.item_drops)
            n_mine = sum(1 for d in state.item_drops if state.is_mine(d.owner_name))
            n_chars = len(state.characters)

        zone_str = str(state.current_zone) if state.current_zone else "-"
        n_transitions = len(state.zone_transitions)

        lines = [
            f"GE_Phantom Dashboard",
            f"{'=' * 40}",
            f"",
            f"Session Duration:  {_fmt_elapsed(elapsed)}",
            f"Packet Rate:       {rate:.1f} pkt/s",
            f"Total Packets:     {state.total_packets}",
            f"Current Zone:      {zone_str}" + (f"  ({n_transitions} transitions)" if n_transitions else ""),
            f"",
            f"Entities Tracked:  {n_entities}",
            f"Characters:        {n_chars}",
            f"",
            f"Item Drops:        {n_drops} total",
            f"  On Ground:       {n_active}",
            f"  Mine:            {n_mine}",
            f"",
            f"Packet Types:",
        ]

        if state.packet_counts:
            top = sorted(state.packet_counts.items(), key=lambda x: -x[1])[:12]
            for name, count in top:
                r = state.stats.rate_by_type(name)
                lines.append(f"  {name:<25s} {count:>6d}  ({r:.1f}/s)")

        stats.update("\n".join(lines))


# ---- 5. Client Panel ----

class ClientPanel(Vertical):
    """Connected clients list with session details."""

    def compose(self):
        yield Static("", id="client-summary")
        table = DataTable(id="client-table")
        table.cursor_type = "row"
        yield table

    def on_mount(self) -> None:
        table: DataTable = self.query_one("#client-table", DataTable)
        table.add_columns("#", "Label", "Endpoint", "Packets", "Entities", "Drops", "Reconnects", "Last Seen")

    def refresh_clients(self, router: ClientRouter, stale_timeout: float = 300.0) -> None:
        """Rebuild client table from router state."""
        table: DataTable = self.query_one("#client-table", DataTable)
        summary: Static = self.query_one("#client-summary", Static)
        table.clear()

        clients = router.get_active_clients()
        now = time.time()

        n_stale = sum(1 for c in clients if c.is_stale(stale_timeout, now))
        summary.update(
            f" Clients: {len(clients)} connected"
            + (f" | {n_stale} stale" if n_stale else "")
        )

        for i, session in enumerate(clients, 1):
            is_stale = session.is_stale(stale_timeout, now)
            style = "dim" if is_stale else ""

            idx_text = Text(str(i), style=style)
            label_text = Text(session.label, style=f"bold {style}" if not is_stale else style)
            key_text = Text(session.client_key, style="bright_black")
            pkts_text = Text(str(session.state.total_packets), style=style)

            with session.state._lock:
                n_ents = len(session.state.entities)
                n_drops = len(session.state.item_drops)
            ents_text = Text(str(n_ents), style=style)
            drops_text = Text(str(n_drops), style=style)

            reconn_text = Text(
                str(session.reconnect_count) if session.reconnect_count else "-",
                style="yellow" if session.reconnect_count else style,
            )

            ago = now - session.last_seen if session.last_seen else 0
            if ago < 2:
                seen_text = Text("now", style="green")
            elif ago < 10:
                seen_text = Text(f"{ago:.0f}s ago", style="yellow")
            elif is_stale:
                seen_text = Text(f"{_fmt_elapsed(ago)} ago", style="red")
            else:
                seen_text = Text(f"{ago:.0f}s ago", style=style)

            table.add_row(
                idx_text, label_text, key_text, pkts_text,
                ents_text, drops_text, reconn_text, seen_text,
                key=session.client_key,
            )
