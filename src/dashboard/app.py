"""
GE_Phantom Dashboard — Textual TUI App

Real-time terminal dashboard for packet monitoring, entity tracking,
item drop alerts, and session analytics.

Modes:
  - Live: runs GESniffer in a worker thread, feeds packets to RadarState
  - Replay: loads a saved session JSON file and replays packets

Multiclient: ClientRouter auto-detects multiple GE clients by local endpoint.
  0   — global view (all clients combined)
  1-9 — switch to per-client view

Replay speed controls:
  [ / ] — decrease / increase speed (1x, 2x, 5x, 10x, MAX)
  x     — export session stats to JSON
"""

from __future__ import annotations

import json
import time
import threading
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Static, TabbedContent, TabPane
from textual.timer import Timer

from src.data.state import RadarState
from src.data.router import ClientRouter
from src.sniffer.capture import GESniffer, GEPacket
from src.dashboard.widgets import (
    TrafficPanel,
    EntityPanel,
    DropPanel,
    SessionPanel,
    EntitySelected,
)

# Replay speed presets: (label, multiplier)
# multiplier=0 means unbounded (no sleep)
SPEED_PRESETS = [
    ("1x", 1.0),
    ("2x", 2.0),
    ("5x", 5.0),
    ("10x", 10.0),
    ("MAX", 0.0),
]


class GEDashboard(App):
    """GE_Phantom real-time packet dashboard."""

    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("t", "switch_tab('traffic')", "Traffic", show=True),
        Binding("e", "switch_tab('entities')", "Entities", show=True),
        Binding("d", "switch_tab('drops')", "Drops", show=True),
        Binding("s", "switch_tab('session')", "Session", show=True),
        Binding("p", "toggle_pause", "Pause"),
        Binding("c", "clear_log", "Clear"),
        Binding("left_square_bracket", "speed_down", "Slower"),
        Binding("right_square_bracket", "speed_up", "Faster"),
        Binding("x", "export_stats", "Export"),
        # Client switching: 0 = global, 1-9 = per-client
        Binding("0", "switch_client(0)", "Global", show=False),
        Binding("1", "switch_client(1)", "", show=False),
        Binding("2", "switch_client(2)", "", show=False),
        Binding("3", "switch_client(3)", "", show=False),
        Binding("4", "switch_client(4)", "", show=False),
        Binding("5", "switch_client(5)", "", show=False),
        Binding("6", "switch_client(6)", "", show=False),
        Binding("7", "switch_client(7)", "", show=False),
        Binding("8", "switch_client(8)", "", show=False),
        Binding("9", "switch_client(9)", "", show=False),
    ]

    def __init__(
        self,
        iface: str | None = None,
        my_chars: list[str] | None = None,
        replay_path: str | None = None,
    ):
        super().__init__()
        self._iface = iface
        self._replay_path = replay_path
        self.router = ClientRouter(my_chars=my_chars)
        # Active client view: None = global, str = client_key
        self._active_client: str | None = None
        self._paused = False
        self._connected = False
        self._refresh_timer: Timer | None = None
        # Replay speed
        self._speed_index = 0  # index into SPEED_PRESETS
        self._replay_done = False

    @property
    def _active_state(self) -> RadarState:
        """Return the RadarState for the current view."""
        if self._active_client is None:
            return self.router.global_state
        session = self.router.clients.get(self._active_client)
        if session:
            return session.state
        return self.router.global_state

    @property
    def _speed_label(self) -> str:
        return SPEED_PRESETS[self._speed_index][0]

    @property
    def _speed_mult(self) -> float:
        return SPEED_PRESETS[self._speed_index][1]

    def compose(self) -> ComposeResult:
        with Horizontal(id="header-bar"):
            yield Static("GE_Phantom", id="status-label")
            yield Static("0.0 pkt/s", id="rate-label")
        with TabbedContent(id="tabs"):
            with TabPane("Traffic", id="traffic"):
                yield TrafficPanel()
            with TabPane("Entities", id="entities"):
                yield EntityPanel()
            with TabPane("Drops", id="drops"):
                yield DropPanel()
            with TabPane("Session", id="session"):
                yield SessionPanel()
        yield Footer()

    def on_mount(self) -> None:
        self._update_header()

        # Start periodic UI refresh (entity/drop tables + session stats)
        self._refresh_timer = self.set_interval(1.0, self._periodic_refresh)

        # Start capture or replay in a background thread
        if self._replay_path:
            thread = threading.Thread(target=self._run_replay, daemon=True)
        else:
            thread = threading.Thread(target=self._run_sniffer, daemon=True)
        thread.start()

    def _update_header(self) -> None:
        status: Static = self.query_one("#status-label", Static)
        rate_label: Static = self.query_one("#rate-label", Static)

        if self._replay_path:
            speed_tag = f" [{self._speed_label}]"
            done_tag = " DONE" if self._replay_done else ""
            mode = f"REPLAY{speed_tag}{done_tag}"
        else:
            mode = "LIVE" if self._connected else "CONNECTING"

        paused = " [PAUSED]" if self._paused else ""

        # Client info
        clients = self.router.get_active_clients()
        n_clients = len(clients)

        if self._active_client is None:
            view_tag = "Global"
        else:
            session = self.router.clients.get(self._active_client)
            view_tag = session.label if session else "?"

        if n_clients > 1:
            client_tag = f" [{view_tag}] [{n_clients} clients]"
        elif n_clients == 1:
            client_tag = f" [{clients[0].label}]"
        else:
            client_tag = ""

        status.update(f"GE_Phantom | {mode}{paused}{client_tag}")

        state = self._active_state
        rate = state.stats.rate()
        rate_label.update(f"{rate:.1f} pkt/s | {state.total_packets} pkts")

    # ---- Sniffer (live mode) ----

    def _run_sniffer(self) -> None:
        sniffer = GESniffer(iface=self._iface)
        sniffer.on_packet(self._on_packet)
        self._connected = True
        self.call_from_thread(self._update_header)
        # start() blocks until stopped
        sniffer.start()

    def _on_packet(self, pkt: GEPacket) -> None:
        if self._paused:
            return
        _key, decoded = self.router.process_packet(pkt)
        if decoded:
            # Schedule UI update on the main thread
            self.call_from_thread(self._log_packet, decoded)

    # ---- Replay mode ----

    def _run_replay(self) -> None:
        path = Path(self._replay_path)
        if not path.exists():
            self.call_from_thread(self.notify, f"File not found: {path}", severity="error")
            return

        data = json.loads(path.read_text())
        packets = data.get("packets", [])
        if not packets:
            self.call_from_thread(self.notify, "No packets in file", severity="error")
            return

        self._connected = True
        self.call_from_thread(self._update_header)
        self.call_from_thread(
            self.notify,
            f"Replaying {len(packets)} packets from {path.name}",
        )

        # Replay with timing
        for i, pkt_data in enumerate(packets):
            if self._paused:
                # Spin-wait while paused
                while self._paused:
                    time.sleep(0.1)

            payload_hex = pkt_data.get("payload_hex", "")
            if not payload_hex:
                continue

            payload = bytes.fromhex(payload_hex)
            pkt = GEPacket(
                timestamp=pkt_data.get("timestamp", time.time()),
                direction=pkt_data.get("direction", "S2C"),
                src_ip=pkt_data.get("src", "").rsplit(":", 1)[0] if "src" in pkt_data else "0.0.0.0",
                dst_ip=pkt_data.get("dst", "").rsplit(":", 1)[0] if "dst" in pkt_data else "0.0.0.0",
                src_port=int(pkt_data["src"].rsplit(":", 1)[1]) if "src" in pkt_data else 0,
                dst_port=int(pkt_data["dst"].rsplit(":", 1)[1]) if "dst" in pkt_data else 0,
                payload=payload,
                seq=pkt_data.get("seq", 0),
                ack=pkt_data.get("ack", 0),
                flags=pkt_data.get("flags", ""),
            )

            _key, decoded = self.router.process_packet(pkt)
            if decoded:
                self.call_from_thread(self._log_packet, decoded)

            # Simulate timing gap, adjusted by speed multiplier
            if i + 1 < len(packets):
                next_ts = packets[i + 1].get("timestamp", 0)
                gap = next_ts - pkt_data.get("timestamp", 0)
                mult = self._speed_mult

                if mult == 0.0:
                    # MAX speed — no sleep at all
                    pass
                elif gap > 0:
                    # Scale the gap by speed, cap at 0.5s real-time
                    scaled = gap / mult
                    if scaled > 0.5:
                        scaled = 0.05
                    if scaled > 0.001:
                        time.sleep(scaled)

        self._replay_done = True
        self.call_from_thread(self._update_header)
        self.call_from_thread(self.notify, "Replay complete")

    # ---- UI updates ----

    def _log_packet(self, decoded: dict) -> None:
        """Log a packet to the traffic panel (called on main thread)."""
        try:
            panel: TrafficPanel = self.query_one(TrafficPanel)
            panel.log_packet(decoded, self._active_state)
        except Exception:
            pass

    def _periodic_refresh(self) -> None:
        """Refresh tables and stats periodically."""
        self._update_header()

        state = self._active_state

        # Only refresh the active tab's content
        tabs: TabbedContent = self.query_one("#tabs", TabbedContent)
        active = tabs.active

        if active == "entities":
            try:
                panel: EntityPanel = self.query_one(EntityPanel)
                panel.refresh_entities(state)
            except Exception:
                pass
        elif active == "drops":
            try:
                panel: DropPanel = self.query_one(DropPanel)
                panel.refresh_drops(state)
            except Exception:
                pass
        elif active == "session":
            try:
                panel: SessionPanel = self.query_one(SessionPanel)
                panel.refresh_session(state)
            except Exception:
                pass

    # ---- Actions ----

    def action_switch_tab(self, tab_id: str) -> None:
        tabs: TabbedContent = self.query_one("#tabs", TabbedContent)
        tabs.active = tab_id

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self._update_header()
        self.notify(f"{'Paused' if self._paused else 'Resumed'}")

    def action_clear_log(self) -> None:
        try:
            panel: TrafficPanel = self.query_one(TrafficPanel)
            panel.clear_log()
        except Exception:
            pass

    def action_switch_client(self, index: int) -> None:
        """Switch active client view. 0 = global, 1-9 = per-client."""
        if index == 0:
            self._active_client = None
            self._update_header()
            self.notify("View: Global (all clients)")
            return

        session = self.router.get_client_by_index(index)
        if session:
            self._active_client = session.client_key
            self._update_header()
            self.notify(f"View: {session.label}")
        else:
            self.notify(f"No client #{index}")

    def action_speed_up(self) -> None:
        """Increase replay speed."""
        if not self._replay_path:
            return
        if self._speed_index < len(SPEED_PRESETS) - 1:
            self._speed_index += 1
            self._update_header()
            self.notify(f"Speed: {self._speed_label}")

    def action_speed_down(self) -> None:
        """Decrease replay speed."""
        if not self._replay_path:
            return
        if self._speed_index > 0:
            self._speed_index -= 1
            self._update_header()
            self.notify(f"Speed: {self._speed_label}")

    def action_export_stats(self) -> None:
        """Export session stats to a JSON file."""
        export = self._build_export()
        out_dir = Path("data")
        out_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"export_{ts}.json"
        out_path.write_text(json.dumps(export, indent=2, default=str))
        self.notify(f"Exported to {out_path}")

    def _build_export(self) -> dict:
        """Build a session stats dict for export."""
        state = self._active_state
        elapsed = time.time() - state.start_time
        with state._lock:
            entities = [
                {
                    "entity_id": e.entity_id,
                    "type": e.entity_type,
                    "x": e.x,
                    "y": e.y,
                    "name": e.name,
                }
                for e in state.entities.values()
            ]
            drops = [
                {
                    "timestamp": d.timestamp,
                    "entity_id": d.entity_id,
                    "item_id": d.item_id,
                    "count": d.count,
                    "x": d.x,
                    "y": d.y,
                    "owner_name": d.owner_name,
                    "picked_up": d.picked_up,
                }
                for d in state.item_drops
            ]
        return {
            "exported_at": datetime.now().isoformat(),
            "active_view": self._active_client or "global",
            "session": {
                "duration_seconds": round(elapsed, 1),
                "total_packets": state.total_packets,
                "packet_rate": round(state.stats.rate(), 1),
            },
            "packet_counts": dict(state.packet_counts),
            "entities": entities,
            "item_drops": drops,
        }

    def on_entity_selected(self, event: EntitySelected) -> None:
        """Handle entity row selection from EntityPanel."""
        try:
            panel: EntityPanel = self.query_one(EntityPanel)
            panel.show_detail(event.entity_id, self._active_state)
        except Exception:
            pass
