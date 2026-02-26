"""Tests for capture session with markers."""

import json
import tempfile
from pathlib import Path

from src.sniffer.capture import GEPacket, GESniffer
from src.sniffer.session import CaptureSession, Marker


def test_session_mark():
    session = CaptureSession(GESniffer(), name="test")
    session._start_time = 1000.0

    # Simulate some packets
    for i in range(5):
        session.packets.append(GEPacket(
            timestamp=1000.0 + i,
            direction="S2C",
            src_ip="103.55.55.138",
            dst_ip="192.168.1.100",
            src_port=7000,
            dst_port=54321,
            payload=b"\x00" * 10,
            seq=i * 10,
            ack=0,
            flags="PA",
        ))

    session.mark("picked item")
    assert len(session.markers) == 1
    assert session.markers[0].label == "picked item"
    assert session.markers[0].packet_index == 5


def test_packets_between_markers():
    session = CaptureSession(GESniffer(), name="test")

    for i in range(20):
        session.packets.append(GEPacket(
            timestamp=1000.0 + i,
            direction="S2C",
            src_ip="103.55.55.138",
            dst_ip="192.168.1.100",
            src_port=7000,
            dst_port=54321,
            payload=bytes([i]) * 4,
            seq=i * 4,
            ack=0,
            flags="PA",
        ))
        if i == 5:
            session.markers.append(Marker(1005.0, "action1", len(session.packets)))
        if i == 12:
            session.markers.append(Marker(1012.0, "action2", len(session.packets)))

    between = session.packets_between_markers(0)
    assert len(between) == 7  # packets 6-12


def test_packets_near_marker():
    session = CaptureSession(GESniffer(), name="test")

    for i in range(20):
        session.packets.append(GEPacket(
            timestamp=1000.0 + i,
            direction="S2C",
            src_ip="103.55.55.138",
            dst_ip="192.168.1.100",
            src_port=7000,
            dst_port=54321,
            payload=bytes([i]) * 4,
            seq=i * 4,
            ack=0,
            flags="PA",
        ))

    session.markers.append(Marker(1010.0, "action", 10))
    near = session.packets_near_marker(0, before=3, after=3)
    assert len(near) == 6  # packets 7-12


def test_session_save_load(tmp_path):
    session = CaptureSession(GESniffer(), name="test_save")
    session._start_time = 1000.0

    for i in range(3):
        session.packets.append(GEPacket(
            timestamp=1000.0 + i,
            direction="C2S" if i % 2 == 0 else "S2C",
            src_ip="192.168.1.100" if i % 2 == 0 else "103.55.55.138",
            dst_ip="103.55.55.138" if i % 2 == 0 else "192.168.1.100",
            src_port=54321 if i % 2 == 0 else 7000,
            dst_port=7000 if i % 2 == 0 else 54321,
            payload=bytes([i, i + 1, i + 2, i + 3]),
            seq=i * 100,
            ack=i * 50,
            flags="PA",
        ))

    session.markers.append(Marker(1001.5, "test mark", 2))

    path = session.save(tmp_path)
    assert path.exists()

    loaded = CaptureSession.load(path)
    assert loaded.name == "test_save"
    assert len(loaded.packets) == 3
    assert len(loaded.markers) == 1
    assert loaded.markers[0].label == "test mark"
    assert loaded.packets[0].payload == b"\x00\x01\x02\x03"
    assert loaded.packets[1].direction == "S2C"


def test_session_summary():
    session = CaptureSession(GESniffer(), name="test")
    for i in range(10):
        session.packets.append(GEPacket(
            timestamp=1000.0 + i,
            direction="S2C",
            src_ip="103.55.55.138",
            dst_ip="192.168.1.100",
            src_port=7000,
            dst_port=54321,
            payload=b"\x00" * 8,
            seq=0,
            ack=0,
            flags="PA",
        ))

    session.markers.append(Marker(1003.0, "picked item", 3))
    summary = session.summary()
    assert "10 total" in summary
    assert "picked item" in summary
