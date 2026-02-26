"""
TCP Stream Reassembler — reconstruct application-level packets from TCP segments.

TCP can split or merge game packets across segments. This module:
1. Buffers incoming TCP data per direction
2. Splits into game-level packets using the configured framing strategy
3. Emits complete game packets

Framing strategies:
- None: pass through raw TCP segments as-is (no reassembly)
- "length_prefix": uniform length-prefix framing (all packets same format)
- "opcode_registry": per-opcode framing using KNOWN_PACKETS definitions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .capture import GEPacket


@dataclass
class StreamBuffer:
    """Buffer for one direction of a TCP stream."""
    direction: str
    buffer: bytearray = field(default_factory=bytearray)
    packet_count: int = 0
    game_packets_emitted: int = 0

    def append(self, data: bytes) -> None:
        self.buffer.extend(data)
        self.packet_count += 1

    def consume(self, n: int) -> bytes:
        """Consume n bytes from the front of the buffer."""
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def peek(self, n: int) -> bytes:
        return bytes(self.buffer[:n])

    @property
    def size(self) -> int:
        return len(self.buffer)


class TCPStreamReassembler:
    """
    Reassemble TCP streams into game-level packets.

    Framing strategies (set via set_framing):
    - None: pass through raw TCP segments as-is
    - "length_prefix": length field at custom offset/size
    - "opcode_registry": use packet_types.get_packet_size() per opcode
    """

    def __init__(self):
        self.streams: dict[str, StreamBuffer] = {
            "C2S": StreamBuffer("C2S"),
            "S2C": StreamBuffer("S2C"),
        }
        self._framing: str | None = None
        self._length_offset: int = 0
        self._length_size: int = 2
        self._length_endian: str = "little"
        self._length_includes_header: bool = False
        self._header_size: int = 4
        self.callbacks: list[Callable[[str, bytes], None]] = []

    def set_framing(
        self,
        framing: str,
        length_offset: int = 0,
        length_size: int = 2,
        endian: str = "little",
        includes_header: bool = False,
        header_size: int = 4,
    ) -> None:
        """Configure packet framing once discovered."""
        self._framing = framing
        self._length_offset = length_offset
        self._length_size = length_size
        self._length_endian = endian
        self._length_includes_header = includes_header
        self._header_size = header_size

    def on_game_packet(self, callback: Callable[[str, bytes], None]) -> None:
        """Register callback for complete game packets. Args: (direction, data)."""
        self.callbacks.append(callback)

    def feed(self, pkt: GEPacket) -> None:
        """Feed a captured TCP packet into the reassembler."""
        stream = self.streams[pkt.direction]
        stream.append(pkt.payload)
        self._try_extract(stream)

    def _try_extract(self, stream: StreamBuffer) -> None:
        """Try to extract complete game packets from the buffer."""
        if self._framing is None:
            # No framing known — pass through as-is
            if stream.size > 0:
                data = stream.consume(stream.size)
                self._emit(stream.direction, data)
            return

        if self._framing == "opcode_registry":
            self._extract_opcode_registry(stream)
            return

        # Length-prefix framing
        while stream.size >= self._header_size:
            header = stream.peek(self._header_size)
            raw_len = header[self._length_offset:self._length_offset + self._length_size]
            pkt_len = int.from_bytes(raw_len, self._length_endian)

            if self._length_includes_header:
                total_len = pkt_len
            else:
                total_len = pkt_len + self._header_size

            if total_len <= 0 or total_len > 65536:
                # Probably garbage — skip 1 byte and retry
                stream.consume(1)
                continue

            if stream.size < total_len:
                break  # Need more data

            data = stream.consume(total_len)
            self._emit(stream.direction, data)

    def _extract_opcode_registry(self, stream: StreamBuffer) -> None:
        """Extract packets using per-opcode size lookup from packet_types registry."""
        from src.protocol.packet_types import get_packet_size, HEADER_SIZE

        while stream.size >= HEADER_SIZE:
            # Peek enough to determine packet size
            header = stream.peek(min(stream.size, HEADER_SIZE))
            pkt_size = get_packet_size(header)

            if pkt_size is not None:
                # Known size — wait for full packet or consume
                if stream.size < pkt_size:
                    break  # Need more data (fragmented)
                data = stream.consume(pkt_size)
                self._emit(stream.direction, data)
                continue

            # Unknown size — need to peek more for length field
            # Try with more data (some packets have length field past HEADER_SIZE)
            if stream.size > HEADER_SIZE:
                peek_data = stream.peek(min(stream.size, 8))
                pkt_size = get_packet_size(peek_data)
                if pkt_size is not None:
                    if stream.size < pkt_size:
                        break  # Need more data
                    data = stream.consume(pkt_size)
                    self._emit(stream.direction, data)
                    continue

            # Truly unknown: scan forward for next known opcode boundary
            found = self._scan_for_next_opcode(stream)
            if found:
                # Emit everything up to the next opcode as one chunk
                data = stream.consume(found)
                self._emit(stream.direction, data)
                continue  # Process remaining buffer (starts with known opcode)
            else:
                # No next opcode found — emit all remaining as one packet
                data = stream.consume(stream.size)
                self._emit(stream.direction, data)
                break

    # Opcodes too common in binary data to use as boundary markers
    _SCAN_EXCLUDE = frozenset({0x0000})  # HEARTBEAT: \x00\x00 matches any two zero bytes

    def _scan_for_next_opcode(self, stream: StreamBuffer) -> int | None:
        """Scan buffer for the next valid opcode after position 2.

        Returns offset of the next opcode, or None if not found.
        Excludes HEARTBEAT (0x0000) from candidates — too many false positives.
        Validates candidates by checking if they lead to valid packet chains.
        """
        from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size

        buf = stream.buffer
        # Start scanning from offset 4 (skip current opcode + at least 2 payload bytes)
        for offset in range(4, len(buf) - 1):
            candidate = int.from_bytes(buf[offset:offset + 2], "big")
            if candidate in self._SCAN_EXCLUDE:
                continue
            if candidate not in KNOWN_PACKETS:
                continue

            # Validate: the candidate should be parseable (known size)
            remaining = bytes(buf[offset:])
            pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])
            if pkt_size is not None:
                # Strong candidate: we know the next packet's size
                if pkt_size <= len(remaining):
                    return offset
                # Packet is fragmented but opcode is valid — still accept
                return offset

            # Variable-size packet with unknown framing — weaker candidate
            # Accept only if this opcode is confirmed
            pdef = KNOWN_PACKETS[candidate]
            if pdef.confirmed:
                return offset

        return None

    def _emit(self, direction: str, data: bytes) -> None:
        stream = self.streams[direction]
        stream.game_packets_emitted += 1
        for cb in self.callbacks:
            try:
                cb(direction, data)
            except Exception as e:
                print(f"[!] Stream callback error: {e}")

    def stats(self) -> dict:
        return {
            d: {
                "buffered": s.size,
                "tcp_segments": s.packet_count,
                "game_packets": s.game_packets_emitted,
            }
            for d, s in self.streams.items()
        }
