"""Tests for the protocol analyzer."""

from src.protocol.analyzer import PacketAnalyzer


def test_size_distribution(item_drop_packets, pick_item_packets):
    all_pkts = item_drop_packets + pick_item_packets
    analyzer = PacketAnalyzer(all_pkts)

    sizes = analyzer.size_distribution()
    assert 24 in sizes  # item_drop size
    assert 8 in sizes   # pick_item size


def test_size_distribution_by_direction(item_drop_packets, pick_item_packets):
    all_pkts = item_drop_packets + pick_item_packets
    analyzer = PacketAnalyzer(all_pkts)

    s2c_sizes = analyzer.size_distribution("S2C")
    assert 24 in s2c_sizes
    assert 8 not in s2c_sizes

    c2s_sizes = analyzer.size_distribution("C2S")
    assert 8 in c2s_sizes
    assert 24 not in c2s_sizes


def test_by_direction(item_drop_packets, pick_item_packets):
    analyzer = PacketAnalyzer(item_drop_packets + pick_item_packets)
    assert len(analyzer.by_direction("S2C")) == 5
    assert len(analyzer.by_direction("C2S")) == 5


def test_find_common_header(item_drop_packets):
    analyzer = PacketAnalyzer(item_drop_packets)
    header = analyzer.find_common_header(item_drop_packets)
    # First 4 bytes (opcode + length) should be common
    assert header == b"\x05\x00\x18\x00"


def test_find_constant_bytes(item_drop_packets):
    analyzer = PacketAnalyzer(item_drop_packets)
    constants = analyzer.find_constant_bytes(item_drop_packets)
    # Bytes 0-3 should be constant (opcode + length)
    constant_offsets = [offset for offset, _ in constants]
    assert 0 in constant_offsets
    assert 1 in constant_offsets
    assert 2 in constant_offsets
    assert 3 in constant_offsets


def test_find_varying_bytes(item_drop_packets):
    analyzer = PacketAnalyzer(item_drop_packets)
    varying = analyzer.find_varying_bytes(item_drop_packets)
    # Bytes after header should vary (item_id, coords, etc.)
    varying_offsets = [offset for offset, _ in varying]
    assert 4 in varying_offsets  # item_id first byte varies


def test_diff_packets(item_drop_packets):
    analyzer = PacketAnalyzer(item_drop_packets)
    diffs = analyzer.diff_packets(item_drop_packets[0], item_drop_packets[1])
    # Should find differences in item_id, coords, instance_id
    assert len(diffs) > 0
    diff_offsets = [offset for offset, _, _ in diffs]
    assert 4 in diff_offsets  # item_id


def test_find_packet_id(item_drop_packets, pick_item_packets):
    analyzer = PacketAnalyzer(item_drop_packets + pick_item_packets)
    ids = analyzer.find_packet_id()
    assert len(ids) > 0
    # The 2-byte prefix 0x0005 should appear for drops
    found_values = [p.value for p in ids]
    assert b"\x05\x00" in found_values


def test_find_length_field(item_drop_packets):
    """Test detecting length field — our synthetic data has it at offset 2."""
    analyzer = PacketAnalyzer(item_drop_packets)
    patterns = analyzer.find_length_field(item_drop_packets)
    # Should find the length field at offset 2 (value 0x18 = 24 = total size)
    assert len(patterns) > 0


def test_report(item_drop_packets, pick_item_packets):
    analyzer = PacketAnalyzer(item_drop_packets + pick_item_packets)
    report = analyzer.report()
    assert "Size Distribution" in report
    assert "Packet IDs" in report


def test_byte_frequency(item_drop_packets):
    analyzer = PacketAnalyzer(item_drop_packets)
    freq = analyzer.byte_frequency(0, item_drop_packets)
    # All packets have 0x05 at offset 0
    assert freq[0x05] == 5
