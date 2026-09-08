"""Guard against false passes in the packet acceptance checker."""
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest

from tos_capture import assert_capture, packets


class CaptureAssertions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.pcap'

    def pcap(self, frames, link=1):
        data = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
        for frame in frames:
            data += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame
        self.path.write_bytes(data)
        return self.path

    def ipv4_udp(self, tos, packet_id, fragment=0):
        body = struct.pack('!HHHH', 40000 + packet_id, 33494, 8, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 28, packet_id, fragment,
                         64, 17, 0, b'\x7f\0\0\1', b'\x7f\0\0\1')
        return b'\0' * 12 + b'\x08\0' + ip + body

    def ipv6_echo(self, tos, seq, reply=False):
        addr = ipaddress.IPv6Address('::1').packed
        body = struct.pack('!BBHHH', 129 if reply else 128, 0, 0, 1, seq)
        ip = struct.pack('!IHBB16s16s', (6 << 28) | (tos << 20), len(body), 58, 64, addr, addr)
        return struct.pack('<I', 30) + ip + body

    def ipv4_tcp(self, tos, source_port, sequence=0x01000000):
        body = struct.pack('!HHIIBBHHH', source_port, 33494, sequence, 0,
                           0x50, 0x02, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 40, 0, 0,
                         64, 6, 0, b'\x7f\0\0\1', b'\x7f\0\0\1')
        return b'\0' * 12 + b'\x08\0' + ip + body

    def test_repeated_tcp_rounds_in_distinct_port_sessions(self):
        self.pcap([self.ipv4_tcp(184, 47464)] * 2 +
                  [self.ipv4_tcp(184, 47465)] * 2)
        result = assert_capture(self.path, 4, 'tcp', 184, '127.0.0.1', '127.0.0.1',
                                source_ports=(47464, 47465))
        self.assertEqual(result['distinct_probes'], 2)
        self.assertEqual(result['packets'], 4)

    def test_each_report_session_must_be_captured(self):
        self.pcap([self.ipv4_tcp(184, 47464, 1), self.ipv4_tcp(184, 47464, 2)])
        with self.assertRaisesRegex(AssertionError, 'missing probe sessions'):
            assert_capture(self.path, 4, 'tcp', 184, '127.0.0.1', '127.0.0.1',
                           source_ports=(47464, 47465))

    def test_repeated_ipv6_udp_rounds_in_distinct_port_sessions(self):
        addr = ipaddress.IPv6Address('::1').packed
        frames = []
        for port in (47464, 47465):
            body = struct.pack('!HHHHH', port, 33494, 10, 0, 0)
            ip = struct.pack('!IHBB16s16s', (6 << 28) | (184 << 20),
                             len(body), 17, 64, addr, addr)
            frames.extend([struct.pack('<I', 30) + ip + body] * 2)
        self.pcap(frames, link=0)
        result = assert_capture(self.path, 6, 'udp', 184, '::1', '::1',
                                source_ports=(47464, 47465))
        self.assertEqual(result['distinct_probes'], 2)
        self.assertEqual(result['packets'], 4)

    def test_all_eight_bits_checked(self):
        self.pcap([self.ipv4_udp(184, 1), self.ipv4_udp(185, 2)])
        with self.assertRaisesRegex(AssertionError, 'wrong TOS'):
            assert_capture(self.path, 4, 'udp', 184, '127.0.0.1', '127.0.0.1')

    def test_loopback_duplicates_are_not_multiple_probes(self):
        self.pcap([self.ipv4_udp(255, 1)] * 2)
        with self.assertRaisesRegex(AssertionError, 'missing distinct probes'):
            assert_capture(self.path, 4, 'udp', 255, '127.0.0.1', '127.0.0.1')

    def test_ipv6_null_header_and_reply_exclusion(self):
        self.pcap([self.ipv6_echo(255, 1), self.ipv6_echo(255, 2),
                   self.ipv6_echo(0, 3, reply=True)], link=0)
        result = assert_capture(self.path, 6, 'icmp', 255, '::1', '::1')
        self.assertEqual(result['packets'], 2)

    def test_each_udp_fragment_is_checked(self):
        self.pcap([self.ipv4_udp(255, 1, 0x2000), self.ipv4_udp(255, 2, 0x2000),
                   self.ipv4_udp(0, 1, 1)])
        with self.assertRaisesRegex(AssertionError, 'wrong TOS'):
            assert_capture(self.path, 4, 'udp', 255, '127.0.0.1', '127.0.0.1', fragmented=True)
        self.pcap([self.ipv4_udp(255, 1, 0x2000), self.ipv4_udp(255, 2, 0x2000),
                   self.ipv4_udp(255, 1, 1)])
        self.assertEqual(assert_capture(self.path, 4, 'udp', 255, '127.0.0.1',
                                        '127.0.0.1', fragmented=True)['packets'], 3)

    def test_ipv6_udp_fixed_ports_have_distinct_payloads(self):
        frames = []
        addr = ipaddress.IPv6Address('::1').packed
        for sequence in (1, 2):
            body = struct.pack('!HHHHH', 40000, 33494, 10, sequence, sequence)
            ip = struct.pack('!IHBB16s16s', (6 << 28) | (184 << 20),
                             len(body), 17, 64, addr, addr)
            frames.append(struct.pack('<I', 30) + ip + body)
        self.pcap(frames, link=0)
        self.assertEqual(assert_capture(self.path, 6, 'udp', 184, '::1',
                                        '::1')['distinct_probes'], 2)

    def test_incomplete_capture_fails(self):
        self.pcap([self.ipv4_udp(0, 1)])
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaisesRegex(AssertionError, 'truncated captured frame'):
            list(packets(self.path))

    def test_empty_capture_fails(self):
        self.pcap([])
        with self.assertRaisesRegex(AssertionError, 'missing distinct probes'):
            assert_capture(self.path, 4, 'udp', 0, '127.0.0.1', '127.0.0.1')


if __name__ == '__main__':
    unittest.main()
