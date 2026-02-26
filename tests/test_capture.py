"""Tests for the packet capture module."""

from src.sniffer.capture import GEPacket, GESniffer


def test_ge_packet_direction(sample_c2s_packet, sample_s2c_packet):
    assert sample_c2s_packet.direction == "C2S"
    assert sample_s2c_packet.direction == "S2C"


def test_ge_packet_size(sample_c2s_packet):
    assert sample_c2s_packet.size == 12


def test_ge_packet_hex_dump(sample_c2s_packet):
    assert sample_c2s_packet.hex_dump == "01000c0048656c6c6f000000"


def test_ge_packet_pretty_hex(sample_c2s_packet):
    pretty = sample_c2s_packet.pretty_hex
    assert "0000" in pretty
    assert "Hello" in pretty  # ASCII representation


def test_ge_packet_to_dict(sample_c2s_packet):
    d = sample_c2s_packet.to_dict()
    assert d["direction"] == "C2S"
    assert d["src"] == "192.168.1.100:54321"
    assert d["dst"] == "103.55.55.138:7000"
    assert d["size"] == 12


def test_ge_packet_repr(sample_c2s_packet):
    r = repr(sample_c2s_packet)
    assert "C2S" in r
    assert "12 bytes" in r


def test_sniffer_bpf_filter():
    sniffer = GESniffer()
    f = sniffer.bpf_filter
    assert "103.55.55.138" in f
    assert "7000" in f
    assert "7001" in f
    assert "tcp" in f


def test_sniffer_custom_servers():
    sniffer = GESniffer(server_ips=["1.2.3.4"], ports=[8000])
    assert "1.2.3.4" in sniffer.bpf_filter
    assert "8000" in sniffer.bpf_filter
