"""
GE_Phantom Dashboard — Textual TUI App

Real-time terminal dashboard for packet monitoring, entity tracking,
item drop alerts, and session analytics.

Modes:
  - Live: runs GESniffer in a worker thread, feeds packets to RadarState
  - Replay: loads a saved session JSON file and replays packets
"""

from __future__ import annotations

import json
import time
import threading
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Static, TabbedContent, TabPane
from textual.timer import Timer

from src.data.state import RadarState
from src.sniffer.capture import GESniffer, GEPacket
from src.dashboard.widgets import (
    TrafficPanel,
    EntityPanel,
    DropPanel,
    SessionPanel,
    EntitySelected,
)


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
        self.state = RadarState(my_chars=my_chars)
        self._paused = False
        self._connected = False
        self._refresh_timer: Timer | None = None

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

        mode = "REPLAY" if self._replay_path else ("LIVE" if self._connected else "CONNECTING")
        paused = " [PAUSED]" if self._paused else ""
        status.update(f"GE_Phantom | {mode}{paused}")

        rate = self.state.stats.rate()
        rate_label.update(f"{rate:.1f} pkt/s | {self.state.total_packets} pkts")

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
        decoded = self.state.process_packet(pkt)
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
        first_ts = packets[0].get("timestamp", 0)
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

            decoded = self.state.process_packet(pkt)
            if decoded:
                self.call_from_thread(self._log_packet, decoded)

            # Simulate timing gap (capped at 0.5s to avoid long waits)
            if i + 1 < len(packets):
                next_ts = packets[i + 1].get("timestamp", 0)
                gap = next_ts - pkt_data.get("timestamp", 0)
                if 0 < gap < 0.5:
                    time.sleep(gap)
                elif gap >= 0.5:
                    time.sleep(0.05)  # fast-forward large gaps

        self.call_from_thread(self.notify, "Replay complete")

    # ---- UI updates ----

    def _log_packet(self, decoded: dict) -> None:
        """Log a packet to the traffic panel (called on main thread)."""
        try:
            panel: TrafficPanel = self.query_one(TrafficPanel)
            panel.log_packet(decoded, self.state)
        except Exception:
            pass

    def _periodic_refresh(self) -> None:
        """Refresh tables and stats periodically."""
        self._update_header()

        # Only refresh the active tab's content
        tabs: TabbedContent = self.query_one("#tabs", TabbedContent)
        active = tabs.active

        if active == "entities":
            try:
                panel: EntityPanel = self.query_one(EntityPanel)
                panel.refresh_entities(self.state)
            except Exception:
                pass
        elif active == "drops":
            try:
                panel: DropPanel = self.query_one(DropPanel)
                panel.refresh_drops(self.state)
            except Exception:
                pass
        elif active == "session":
            try:
                panel: SessionPanel = self.query_one(SessionPanel)
                panel.refresh_session(self.state)
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

    def on_entity_selected(self, event: EntitySelected) -> None:
        """Handle entity row selection from EntityPanel."""
        try:
            panel: EntityPanel = self.query_one(EntityPanel)
            panel.show_detail(event.entity_id, self.state)
        except Exception:
            pass
