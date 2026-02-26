"""
GE_Phantom — Packet Sniffer for Granado Espada

Captures TCP traffic to/from GE servers using scapy.
Requires Npcap installed + admin privileges.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from scapy.all import IP, TCP, sniff, conf

# Default GE server config
DEFAULT_SERVER_IPS = ["103.55.55.138"]
DEFAULT_PORTS = [7000, 7001]


@dataclass
class GEPacket:
    """A captured GE packet with metadata."""
    timestamp: float
    direction: str          # "C2S" (client→server) or "S2C" (server→client)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    seq: int
    ack: int
    flags: str

    @property
    def size(self) -> int:
        return len(self.payload)

    @property
    def hex_dump(self) -> str:
        return self.payload.hex()

    @property
    def pretty_hex(self) -> str:
        """16-byte wide hex dump with ASCII."""
        lines = []
        data = self.payload
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "size": self.size,
            "seq": self.seq,
            "ack": self.ack,
            "flags": self.flags,
            "payload_hex": self.hex_dump,
        }

    def __repr__(self) -> str:
        arrow = "→" if self.direction == "C2S" else "←"
        return (
            f"[{self.direction}] {self.src_ip}:{self.src_port} "
            f"{arrow} {self.dst_ip}:{self.dst_port} "
            f"({self.size} bytes)"
        )


class GESniffer:
    """Capture and filter Granado Espada network traffic."""

    def __init__(
        self,
        server_ips: list[str] | None = None,
        ports: list[int] | None = None,
        iface: str | None = None,
    ):
        self.server_ips = server_ips or DEFAULT_SERVER_IPS
        self.ports = ports or DEFAULT_PORTS
        self.iface = iface
        self.callbacks: list[Callable[[GEPacket], None]] = []
        self._running = False

    @property
    def bpf_filter(self) -> str:
        """Build BPF filter string for GE traffic."""
        ip_filters = " or ".join(f"host {ip}" for ip in self.server_ips)
        port_filters = " or ".join(f"port {p}" for p in self.ports)
        return f"tcp and ({ip_filters}) and ({port_filters})"

    def on_packet(self, callback: Callable[[GEPacket], None]) -> None:
        """Register a callback for each captured GE packet."""
        self.callbacks.append(callback)

    def _process_packet(self, raw_pkt) -> None:
        """Convert scapy packet to GEPacket and dispatch."""
        if not raw_pkt.haslayer(TCP) or not raw_pkt.haslayer(IP):
            return

        ip_layer = raw_pkt[IP]
        tcp_layer = raw_pkt[TCP]

        # Only care about packets with payload
        payload = bytes(tcp_layer.payload)
        if not payload:
            return

        # Determine direction
        if ip_layer.dst in self.server_ips:
            direction = "C2S"
        elif ip_layer.src in self.server_ips:
            direction = "S2C"
        else:
            return

        pkt = GEPacket(
            timestamp=time.time(),
            direction=direction,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            payload=payload,
            seq=tcp_layer.seq,
            ack=tcp_layer.ack,
            flags=str(tcp_layer.flags),
        )

        for cb in self.callbacks:
            try:
                cb(pkt)
            except Exception as e:
                print(f"[!] Callback error: {e}")

    def start(self, count: int = 0, timeout: int | None = None) -> None:
        """Start capturing. count=0 means infinite. Blocks until done."""
        print(f"[*] GE_Phantom Sniffer starting...")
        print(f"[*] Filter: {self.bpf_filter}")
        print(f"[*] Interface: {self.iface or 'auto'}")
        print(f"[*] Press Ctrl+C to stop\n")

        self._running = True
        try:
            sniff(
                filter=self.bpf_filter,
                prn=self._process_packet,
                iface=self.iface,
                count=count,
                timeout=timeout,
                store=False,
            )
        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
        finally:
            self._running = False

    def capture_packets(self, count: int = 0, timeout: int = 60) -> list[GEPacket]:
        """Capture and return packets as a list (for analysis)."""
        packets: list[GEPacket] = []
        self.on_packet(packets.append)
        self.start(count=count, timeout=timeout)
        self.callbacks.remove(packets.append)
        return packets


# --- CLI entry point ---

def _print_packet(pkt: GEPacket) -> None:
    """Default callback: print packet summary + hex."""
    ts = time.strftime("%H:%M:%S", time.localtime(pkt.timestamp))
    ms = int((pkt.timestamp % 1) * 1000)
    print(f"[{ts}.{ms:03d}] {pkt}")
    if pkt.size <= 256:
        print(pkt.pretty_hex)
    else:
        # Show first and last 64 bytes for large packets
        lines = pkt.pretty_hex.split("\n")
        for line in lines[:4]:
            print(line)
        print(f"  ... ({pkt.size} bytes total) ...")
        for line in lines[-4:]:
            print(line)
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Packet Sniffer")
    parser.add_argument("--iface", help="Network interface to sniff on")
    parser.add_argument("--timeout", type=int, default=0, help="Capture timeout in seconds (0=infinite)")
    parser.add_argument("--save", help="Save captured packets to JSON file")
    args = parser.parse_args()

    sniffer = GESniffer(iface=args.iface)
    sniffer.on_packet(_print_packet)

    captured: list[GEPacket] = []
    if args.save:
        sniffer.on_packet(captured.append)

    try:
        sniffer.start(timeout=args.timeout or None)
    finally:
        if args.save and captured:
            out_path = Path(args.save)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            data = [p.to_dict() for p in captured]
            out_path.write_text(json.dumps(data, indent=2))
            print(f"[*] Saved {len(captured)} packets to {out_path}")
