"""
TCP Stream Reassembler — reconstruct application-level packets from TCP segments.

TCP can split or merge game packets across segments. This module:
1. Buffers incoming TCP data per direction
2. Splits into game-level packets once we know the framing (length prefix)
3. Emits complete game packets

Until we discover the framing format, this just accumulates raw data.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from .capture import GEPacket


@dataclass
class StreamBuffer:
    """Buffer for one direction of a TCP stream."""
    direction: str
    buffer: bytearray = field(default_factory=bytearray)
    packet_count: int = 0

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
    - "length_prefix_le16": first 2 bytes = u16 little-endian payload length
    - "length_prefix_be16": first 2 bytes = u16 big-endian payload length
    - "length_at_offset": length field at custom offset/size
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

        # Length-prefix framing
        while stream.size >= self._header_size:
            # Read length field
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

    def _emit(self, direction: str, data: bytes) -> None:
        for cb in self.callbacks:
            try:
                cb(direction, data)
            except Exception as e:
                print(f"[!] Stream callback error: {e}")

    def stats(self) -> dict:
        return {
            d: {"buffered": s.size, "tcp_segments": s.packet_count}
            for d, s in self.streams.items()
        }
