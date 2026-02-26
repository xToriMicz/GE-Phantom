"""
Capture Session — tagged recording with markers.

Use markers to correlate game actions with packets:
  session.mark("picked up item")
  session.mark("killed mob")

This lets us find which packets correspond to which game events.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .capture import GEPacket, GESniffer


@dataclass
class Marker:
    """A user-placed marker during capture."""
    timestamp: float
    label: str
    packet_index: int  # index of next packet after this marker

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "label": self.label,
            "packet_index": self.packet_index,
        }


class CaptureSession:
    """A recording session with markers for correlating actions to packets."""

    def __init__(self, sniffer: GESniffer, name: str = ""):
        self.sniffer = sniffer
        self.name = name or time.strftime("%Y%m%d_%H%M%S")
        self.packets: list[GEPacket] = []
        self.markers: list[Marker] = []
        self._start_time: float = 0

    def mark(self, label: str) -> None:
        """Place a marker at the current point in capture."""
        marker = Marker(
            timestamp=time.time(),
            label=label,
            packet_index=len(self.packets),
        )
        self.markers.append(marker)
        elapsed = time.time() - self._start_time if self._start_time else 0
        print(f"  [MARK @ {elapsed:.1f}s] #{len(self.markers)}: {label} (after pkt #{marker.packet_index})")

    def _collect_packet(self, pkt: GEPacket) -> None:
        self.packets.append(pkt)

    def start(self, timeout: int | None = None) -> None:
        """Start recording. Use mark() from another thread or in callbacks."""
        self._start_time = time.time()
        self.sniffer.on_packet(self._collect_packet)
        print(f"[*] Session '{self.name}' recording...")
        print(f"[*] Use Ctrl+C to stop\n")
        self.sniffer.start(timeout=timeout)

    def packets_between_markers(self, marker_idx: int) -> list[GEPacket]:
        """Get packets between marker[idx] and marker[idx+1]."""
        if marker_idx >= len(self.markers):
            return []
        start = self.markers[marker_idx].packet_index
        end = (
            self.markers[marker_idx + 1].packet_index
            if marker_idx + 1 < len(self.markers)
            else len(self.packets)
        )
        return self.packets[start:end]

    def packets_near_marker(self, marker_idx: int, before: int = 5, after: int = 10) -> list[GEPacket]:
        """Get packets around a marker (best for finding the exact packet)."""
        if marker_idx >= len(self.markers):
            return []
        idx = self.markers[marker_idx].packet_index
        start = max(0, idx - before)
        end = min(len(self.packets), idx + after)
        return self.packets[start:end]

    def save(self, directory: str | Path = "captures") -> Path:
        """Save session to JSON."""
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{self.name}.json"

        data = {
            "name": self.name,
            "start_time": self._start_time,
            "duration": time.time() - self._start_time if self._start_time else 0,
            "packet_count": len(self.packets),
            "marker_count": len(self.markers),
            "markers": [m.to_dict() for m in self.markers],
            "packets": [p.to_dict() for p in self.packets],
        }

        out_path.write_text(json.dumps(data, indent=2))
        print(f"[*] Session saved: {out_path} ({len(self.packets)} packets, {len(self.markers)} markers)")
        return out_path

    @classmethod
    def load(cls, path: str | Path) -> CaptureSession:
        """Load a saved session for analysis."""
        data = json.loads(Path(path).read_text())

        session = cls(sniffer=GESniffer(), name=data["name"])
        session._start_time = data.get("start_time", 0)

        for m in data.get("markers", []):
            session.markers.append(Marker(**m))

        for p in data.get("packets", []):
            payload = bytes.fromhex(p["payload_hex"]) if p.get("payload_hex") else b""
            src_ip, src_port = p["src"].rsplit(":", 1)
            dst_ip, dst_port = p["dst"].rsplit(":", 1)
            session.packets.append(GEPacket(
                timestamp=p["timestamp"],
                direction=p["direction"],
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port),
                dst_port=int(dst_port),
                payload=payload,
                seq=p.get("seq", 0),
                ack=p.get("ack", 0),
                flags=p.get("flags", ""),
            ))

        return session

    def summary(self) -> str:
        """Print session summary."""
        c2s = [p for p in self.packets if p.direction == "C2S"]
        s2c = [p for p in self.packets if p.direction == "S2C"]
        lines = [
            f"Session: {self.name}",
            f"  Packets: {len(self.packets)} total ({len(c2s)} C2S, {len(s2c)} S2C)",
            f"  Markers: {len(self.markers)}",
        ]
        if self.markers:
            lines.append("  Marker list:")
            for i, m in enumerate(self.markers):
                count = len(self.packets_between_markers(i))
                lines.append(f"    [{i}] {m.label} — {count} packets after")
        return "\n".join(lines)
