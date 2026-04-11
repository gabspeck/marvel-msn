"""Tests for transport packet building and parsing."""
import unittest

from server.transport import build_packet, build_ack_packet, parse_packet, build_transport_params


class TestBuildParseRoundtrip(unittest.TestCase):
    def test_simple_payload(self):
        pkt = build_packet(1, 0, b'\x01\x02\x03')
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.type, 'DATA')
        self.assertEqual(parsed.seq, 1)
        self.assertEqual(parsed.ack, 0)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, b'\x01\x02\x03')

    def test_payload_with_escape_bytes(self):
        data = bytes([0x0D, 0x1B, 0x10, 0x0B, 0x8D, 0x90, 0x8B])
        pkt = build_packet(5, 3, data)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, data)

    def test_empty_payload(self):
        pkt = build_packet(0, 0, b'')
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, b'')

    def test_seq_ack_high_values(self):
        pkt = build_packet(127, 127, b'\xAA')
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.seq, 127)
        self.assertEqual(parsed.ack, 127)

    def test_packet_ends_with_0x0d(self):
        pkt = build_packet(0, 0, b'test')
        self.assertEqual(pkt[-1], 0x0D)

    def test_no_bare_0x0d_before_terminator(self):
        pkt = build_packet(0, 0, bytes([0x0D, 0x0D, 0x0D]))
        self.assertNotIn(0x0D, pkt[:-1])


class TestAckPacket(unittest.TestCase):
    def test_ack_format(self):
        pkt = build_ack_packet(5)
        self.assertEqual(pkt[0], 0x41)
        self.assertEqual(pkt[-1], 0x0D)

    def test_ack_parse(self):
        pkt = build_ack_packet(5)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.type, 'ACK')
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.ack, 5)


class TestParsePacket(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_packet(b'\x00\x00'))

    def test_bad_crc(self):
        pkt = build_packet(0, 0, b'test')
        raw = bytearray(pkt[:-1])
        raw[-1] ^= 0xFF
        parsed = parse_packet(bytes(raw))
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed.crc_ok)

    def test_known_client_ctrl4(self):
        raw = bytes.fromhex('80 80 e0 03 00 ff ff 04 fc 03 18 a0')
        parsed = parse_packet(raw)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.type, 'DATA')
        self.assertEqual(parsed.seq, 0)
        self.assertEqual(parsed.ack, 0)


class TestTransportParams(unittest.TestCase):
    def test_known_wire_bytes(self):
        """build_transport_params() must produce the exact wire bytes from session captures."""
        pkt = build_transport_params()
        expected = bytes.fromhex(
            '80 80 e0 17 00 ff ff 03 00 01 00 00 00 01 00 00'
            ' 1b 32 00 00 00 01 00 00 00 58 02 00 00 31 c4 49'
            ' 2f 0d'
        )
        self.assertEqual(pkt, expected)

    def test_parseable(self):
        pkt = build_transport_params()
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.seq, 0)
        self.assertEqual(parsed.ack, 0)


if __name__ == '__main__':
    unittest.main()
