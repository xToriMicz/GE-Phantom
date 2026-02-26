"""
Protocol Analyzer — find patterns in captured GE packets.

Key techniques:
1. Header analysis: find common prefixes/structures
2. Frequency analysis: which byte values appear at which positions
3. Diff analysis: compare similar actions to isolate changing fields
4. Size grouping: same action often = same packet size
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from src.sniffer.capture import GEPacket


@dataclass
class PatternMatch:
    """A discovered pattern in packet data."""
    name: str
    offset: int
    length: int
    value: bytes
    confidence: float  # 0.0–1.0
    description: str = ""

    def __repr__(self) -> str:
        return f"Pattern({self.name}: offset={self.offset}, value={self.value.hex()}, conf={self.confidence:.0%})"


class PacketAnalyzer:
    """Analyze captured packets to find protocol patterns."""

    def __init__(self, packets: list[GEPacket]):
        self.packets = packets

    def by_direction(self, direction: str) -> list[GEPacket]:
        return [p for p in self.packets if p.direction == direction]

    def by_size(self, size: int, tolerance: int = 0) -> list[GEPacket]:
        return [p for p in self.packets if abs(p.size - size) <= tolerance]

    def size_distribution(self, direction: str | None = None) -> dict[int, int]:
        """Count packets by payload size."""
        pkts = self.by_direction(direction) if direction else self.packets
        counter = Counter(p.size for p in pkts)
        return dict(sorted(counter.items()))

    def find_common_header(self, packets: list[GEPacket] | None = None, min_length: int = 2) -> bytes:
        """Find common prefix across packets."""
        pkts = packets or self.packets
        if not pkts:
            return b""

        payloads = [p.payload for p in pkts if p.payload]
        if not payloads:
            return b""

        # Find common prefix
        ref = payloads[0]
        common_len = len(ref)
        for payload in payloads[1:]:
            for i in range(min(common_len, len(payload))):
                if ref[i] != payload[i]:
                    common_len = i
                    break
            else:
                common_len = min(common_len, len(payload))

        return ref[:common_len] if common_len >= min_length else b""

    def byte_frequency(self, offset: int, packets: list[GEPacket] | None = None) -> Counter:
        """Frequency of byte values at a specific offset across packets."""
        pkts = packets or self.packets
        counter = Counter()
        for p in pkts:
            if offset < len(p.payload):
                counter[p.payload[offset]] += 1
        return counter

    def find_constant_bytes(self, packets: list[GEPacket] | None = None) -> list[tuple[int, int]]:
        """Find byte positions that are constant across all packets."""
        pkts = packets or self.packets
        if not pkts:
            return []

        min_len = min(len(p.payload) for p in pkts)
        constants = []

        for offset in range(min_len):
            values = set(p.payload[offset] for p in pkts)
            if len(values) == 1:
                constants.append((offset, pkts[0].payload[offset]))

        return constants

    def find_varying_bytes(self, packets: list[GEPacket] | None = None) -> list[tuple[int, int]]:
        """Find byte positions that change between packets. Returns (offset, unique_count)."""
        pkts = packets or self.packets
        if not pkts:
            return []

        min_len = min(len(p.payload) for p in pkts)
        varying = []

        for offset in range(min_len):
            values = set(p.payload[offset] for p in pkts)
            if len(values) > 1:
                varying.append((offset, len(values)))

        return varying

    def diff_packets(self, pkt_a: GEPacket, pkt_b: GEPacket) -> list[tuple[int, int, int]]:
        """Byte-level diff between two packets. Returns [(offset, byte_a, byte_b), ...]."""
        min_len = min(len(pkt_a.payload), len(pkt_b.payload))
        diffs = []

        for i in range(min_len):
            if pkt_a.payload[i] != pkt_b.payload[i]:
                diffs.append((i, pkt_a.payload[i], pkt_b.payload[i]))

        # Length difference
        if len(pkt_a.payload) != len(pkt_b.payload):
            diffs.append((-1, len(pkt_a.payload), len(pkt_b.payload)))

        return diffs

    def find_packet_id(self, packets: list[GEPacket] | None = None) -> list[PatternMatch]:
        """Try to identify packet type/ID field (usually first 2-4 bytes)."""
        pkts = packets or self.packets
        if not pkts:
            return []

        patterns = []

        # Try 2-byte and 4-byte prefixes
        for width in (2, 4):
            prefixes = Counter()
            for p in pkts:
                if len(p.payload) >= width:
                    prefixes[p.payload[:width]] += 1

            for prefix, count in prefixes.most_common(20):
                # Group packets with this prefix
                group = [p for p in pkts if p.payload[:width] == prefix]
                sizes = Counter(p.size for p in group)

                # High confidence if same prefix → consistent size
                size_consistency = max(sizes.values()) / len(group) if group else 0

                patterns.append(PatternMatch(
                    name=f"pkt_id_{prefix.hex()}",
                    offset=0,
                    length=width,
                    value=prefix,
                    confidence=size_consistency,
                    description=f"seen {count}x, sizes: {dict(sizes)}",
                ))

        return sorted(patterns, key=lambda p: -p.confidence)

    def find_length_field(self, packets: list[GEPacket] | None = None) -> list[PatternMatch]:
        """Try to find where the packet length is encoded."""
        pkts = packets or self.packets
        if not pkts:
            return []

        patterns = []

        # Check first 8 bytes for length-like values (little-endian and big-endian)
        for offset in range(0, min(8, min(len(p.payload) for p in pkts) - 1)):
            le_match = 0
            be_match = 0

            for p in pkts:
                if offset + 2 > len(p.payload):
                    continue

                le_val = int.from_bytes(p.payload[offset:offset+2], "little")
                be_val = int.from_bytes(p.payload[offset:offset+2], "big")
                plen = len(p.payload)

                # Check if value matches payload length (with various offsets)
                for adj in (0, -2, -4, 2, 4):
                    if le_val == plen + adj:
                        le_match += 1
                    if be_val == plen + adj:
                        be_match += 1

            total = len(pkts)
            if le_match > total * 0.3:
                patterns.append(PatternMatch(
                    name=f"length_le_at_{offset}",
                    offset=offset,
                    length=2,
                    value=b"",
                    confidence=le_match / total,
                    description=f"Little-endian u16 at offset {offset} matches payload length",
                ))
            if be_match > total * 0.3:
                patterns.append(PatternMatch(
                    name=f"length_be_at_{offset}",
                    offset=offset,
                    length=2,
                    value=b"",
                    confidence=be_match / total,
                    description=f"Big-endian u16 at offset {offset} matches payload length",
                ))

        return sorted(patterns, key=lambda p: -p.confidence)

    def report(self, direction: str | None = None) -> str:
        """Generate a human-readable analysis report."""
        pkts = self.by_direction(direction) if direction else self.packets
        if not pkts:
            return "No packets to analyze."

        lines = []
        lines.append(f"=== Packet Analysis Report ===")
        lines.append(f"Packets: {len(pkts)} ({'all' if not direction else direction})")
        lines.append("")

        # Size distribution
        sizes = self.size_distribution(direction)
        lines.append("Size Distribution (top 15):")
        for size, count in sorted(sizes.items(), key=lambda x: -x[1])[:15]:
            bar = "#" * min(count, 40)
            lines.append(f"  {size:>5} bytes: {count:>4}x {bar}")
        lines.append("")

        # Packet IDs
        pkt_ids = self.find_packet_id(pkts)
        if pkt_ids:
            lines.append("Potential Packet IDs (first bytes):")
            for p in pkt_ids[:10]:
                lines.append(f"  0x{p.value.hex()} — {p.description} (conf: {p.confidence:.0%})")
            lines.append("")

        # Length field
        length_fields = self.find_length_field(pkts)
        if length_fields:
            lines.append("Potential Length Fields:")
            for p in length_fields[:5]:
                lines.append(f"  {p.description} (conf: {p.confidence:.0%})")
            lines.append("")

        # Common header
        header = self.find_common_header(pkts)
        if header:
            lines.append(f"Common Header: {header.hex()} ({len(header)} bytes)")
        else:
            lines.append("No common header found")

        return "\n".join(lines)
