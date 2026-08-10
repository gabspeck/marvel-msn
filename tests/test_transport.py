"""Tests for transport packet building and parsing."""

import struct
import unittest

from server.connection import ConnectionState
from server.pipe import build_pipe_frame
from server.transport import build_ack_packet, build_packet, build_transport_params, parse_packet
from server.wire import byte_stuff, crc32, encode_header_byte, mask_crc


def _packet_from_stuffed_payload(seq, stuffed_payload):
    wire_data = bytes([encode_header_byte(seq | 0x80), encode_header_byte(0x80)])
    wire_data += stuffed_payload
    crc = mask_crc(struct.pack("<I", crc32(wire_data)))
    return wire_data + crc


class TestBuildParseRoundtrip(unittest.TestCase):
    def test_simple_payload(self):
        pkt = build_packet(1, 0, b"\x01\x02\x03")
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.type, "DATA")
        self.assertEqual(parsed.seq, 1)
        self.assertEqual(parsed.ack, 0)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, b"\x01\x02\x03")

    def test_payload_with_escape_bytes(self):
        data = bytes([0x0D, 0x1B, 0x10, 0x0B, 0x8D, 0x90, 0x8B])
        pkt = build_packet(5, 3, data)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, data)

    def test_empty_payload(self):
        pkt = build_packet(0, 0, b"")
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload, b"")

    def test_seq_ack_high_values(self):
        pkt = build_packet(127, 127, b"\xaa")
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.seq, 127)
        self.assertEqual(parsed.ack, 127)

    def test_packet_ends_with_0x0d(self):
        pkt = build_packet(0, 0, b"test")
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
        self.assertEqual(parsed.type, "ACK")
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.ack, 5)


class TestParsePacket(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_packet(b"\x00\x00"))

    def test_bad_crc(self):
        pkt = build_packet(0, 0, b"test")
        raw = bytearray(pkt[:-1])
        raw[-1] ^= 0xFF
        parsed = parse_packet(bytes(raw))
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed.crc_ok)

    def test_known_client_ctrl4(self):
        raw = bytes.fromhex("80 80 e0 03 00 ff ff 04 fc 03 18 a0")
        parsed = parse_packet(raw)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.type, "DATA")
        self.assertEqual(parsed.seq, 0)
        self.assertEqual(parsed.ack, 0)


class TestSplitEscapeReceive(unittest.TestCase):
    class _Socket:
        def __init__(self):
            self.sent = []

        def sendall(self, data):
            self.sent.append(data)

    def test_escape_split_across_crc_valid_packets_survives_reassembly(self):
        pipe_idx = 4
        content = b"SVC!" + b"A" * 233 + b"\x0b" + b"B" * 229
        first_content_len = 238

        first_payload = build_pipe_frame(pipe_idx, content, last=False)
        first_payload = first_payload[: 3 + first_content_len]
        second_header = build_pipe_frame(pipe_idx, b"", last=True)[:1]

        stuffed_first = byte_stuff(first_payload)
        self.assertTrue(stuffed_first.endswith(b"\x1b\x33"))
        first_packet = _packet_from_stuffed_payload(1, stuffed_first[:-1])
        self.assertEqual(len(first_packet[2:-4]), 241)
        second_packet = _packet_from_stuffed_payload(
            2, second_header + stuffed_first[-1:] + byte_stuff(content[first_content_len:])
        )

        state = ConnectionState(self._Socket())
        received = []
        state._handle_service_data = lambda idx, data: received.append((idx, data))

        state._handle_raw_packet(first_packet)
        self.assertEqual(received, [])
        self.assertTrue(state.rx_stuffed_pending)

        bad_second_packet = bytearray(second_packet)
        bad_second_packet[-1] ^= 0xFF
        state._handle_raw_packet(bytes(bad_second_packet))
        self.assertEqual(received, [])
        self.assertTrue(state.rx_stuffed_pending)

        state._handle_raw_packet(second_packet)
        self.assertEqual(received, [(pipe_idx, content)])
        self.assertEqual(state.rx_stuffed_pending, b"")


class TestTransportParams(unittest.TestCase):
    def test_known_wire_bytes(self):
        """build_transport_params() must produce stable wire bytes.

        Advertised packet/max_bytes = 1024 (0x400) so the server stays within
        the client's registry PacketSize default. The 0x10 WINDOW_SIZE byte
        is byte-stuffed to 1b 32.
        """
        pkt = build_transport_params()
        expected = bytes.fromhex(
            "80 80 e0 17 00 ff ff 03 00 04 00 00 00 04 00 00"
            " 1b 32 00 00 00 01 00 00 00 58 02 00 00 38 c9 9a"
            " 7e 0d"
        )
        self.assertEqual(pkt, expected)

    def test_parseable(self):
        pkt = build_transport_params()
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.seq, 0)
        self.assertEqual(parsed.ack, 0)


if __name__ == "__main__":
    unittest.main()
