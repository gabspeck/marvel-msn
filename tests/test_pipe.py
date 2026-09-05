"""Tests for pipe framing, control frames, and message routing."""

import struct
import unittest

from server.models import ControlMessage, PipeData, PipeOpenRequest
from server.mpc import build_control_type1_ack, build_pipe_open_result
from server.pipe import (
    build_control_frame,
    build_pipe_frame,
    build_pipe_frame_has_length,
    parse_connection_request,
    parse_pipe_frame,
    parse_pipe_frames,
    parse_pipe_message,
)
from server.transport import parse_packet


class TestPipeFrameContinuation(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello pipe"
        frame = build_pipe_frame(3, data)
        parsed, _ = parse_pipe_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.reassembly_index, 3)
        self.assertTrue(parsed.last_data)
        self.assertEqual(parsed.content, data)

    def test_pipe0(self):
        data = b"\xff\xff\x01test"
        frame = build_pipe_frame(0, data)
        parsed, _ = parse_pipe_frame(frame)
        self.assertEqual(parsed.reassembly_index, 0)
        self.assertEqual(parsed.content, data)

    def test_last_false(self):
        data = b"partial"
        frame = build_pipe_frame(5, data, last=False)
        parsed, _ = parse_pipe_frame(frame)
        self.assertFalse(parsed.last_data)

    def test_continuation_bit_set(self):
        frame = build_pipe_frame(1, b"x")
        hdr = frame[0]
        self.assertTrue(hdr & 0x20, "Continuation bit should be set")
        self.assertFalse(hdr & 0x10, "Has-length bit should NOT be set")


class TestPipeFrameHasLength(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello pipe"
        frame = build_pipe_frame_has_length(3, data)
        parsed, _ = parse_pipe_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.reassembly_index, 3)
        self.assertTrue(parsed.last_data)
        self.assertEqual(parsed.content, data)

    def test_has_length_bit_set(self):
        frame = build_pipe_frame_has_length(2, b"test")
        hdr = frame[0]
        self.assertTrue(hdr & 0x10, "Has-length bit should be set")
        self.assertFalse(hdr & 0x20, "Continuation bit should NOT be set")


class TestParseMultipleFrames(unittest.TestCase):
    def test_a_continuation_frame_leaves_the_rest_of_the_packet_alone(self):
        # A continuation frame owns its declared content, not the rest of the
        # packet. Consuming everything dropped whatever followed it — the tail
        # of a chunked post body lost 6 bytes that way and its compressed RTF
        # then failed its own CRC.
        f1 = build_pipe_frame(5, b"A" * 10)
        f2 = build_pipe_frame(5, b"B" * 6)
        frames = parse_pipe_frames(f1 + f2)
        self.assertEqual([f.content for f in frames], [b"A" * 10, b"B" * 6])

    def test_a_frame_split_across_packets_keeps_what_arrived(self):
        # The first fragment declares the whole content length but carries only
        # part of it; the connection layer joins the rest from the next packet.
        frame = build_pipe_frame(5, b"C" * 401)[:244]
        parsed, consumed = parse_pipe_frame(frame)
        self.assertEqual(parsed.content_length, 401)
        self.assertEqual(parsed.content, b"C" * 241)
        self.assertEqual(consumed, len(frame))

    def test_two_frames(self):
        f1 = build_pipe_frame_has_length(1, b"first")
        f2 = build_pipe_frame(2, b"second")
        frames = parse_pipe_frames(f1 + f2)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].reassembly_index, 1)
        self.assertEqual(frames[0].content, b"first")
        self.assertEqual(frames[1].reassembly_index, 2)
        self.assertEqual(frames[1].content, b"second")


class TestFrameCompletionBoundary(unittest.TestCase):
    """A pipe message ends on its declared length, not on `last_data`.

    Replays the four frames Blackbird's compound-file upload produced at the
    packet boundary that corrupted it (server log 2026-08-11 23:40:50): two
    467-byte messages, each split across two packets, where only the very last
    fragment carried `last_data`.
    """

    def _split(self, pipe_idx, body, first_len):
        frame = build_pipe_frame(pipe_idx, body, last=False)
        return frame[:first_len], bytes([frame[0]]) + frame[first_len:]

    def test_a_completed_frame_dispatches_without_last_data(self):
        pending = {}
        body_a = struct.pack("<H", 4) + b"\xe6\x02" + b"A" * 463
        head, tail = self._split(0, body_a, 238)

        first = parse_pipe_frames(head, pending)[0]
        self.assertFalse(first.last_data)
        self.assertEqual(pending[0], 467 - len(first.content))

        second = parse_pipe_frames(tail, pending)[0]
        self.assertFalse(second.last_data)
        self.assertEqual(pending[0], 0, "the message is complete though last_data is clear")
        self.assertEqual(len(first.content) + len(second.content), 467)

    def test_two_split_messages_do_not_merge(self):
        pending = {}
        assembled = []
        buffer = bytearray()
        bodies = [
            struct.pack("<H", 4) + b"\xe6\x02" + b"A" * 463,
            struct.pack("<H", 4) + b"\xe6\x02" + b"B" * 463,
        ]
        packets = []
        for body in bodies:
            head, tail = self._split(0, body, 238)
            packets += [head, tail]

        for packet in packets:
            for pf in parse_pipe_frames(packet, pending):
                buffer.extend(pf.content)
                if pending.get(pf.reassembly_index, 0) == 0:
                    assembled.append(bytes(buffer))
                    buffer.clear()

        self.assertEqual([len(m) for m in assembled], [467, 467])
        self.assertEqual(
            [parse_pipe_message(m).data[2:] for m in assembled], [b"A" * 463, b"B" * 463]
        )


class TestParsePipeMessage(unittest.TestCase):
    def test_control_frame(self):
        content = b"\xff\xff\x03" + b"\x00" * 20
        result = parse_pipe_message(content)
        self.assertIsInstance(result, ControlMessage)
        self.assertEqual(result.ctrl_type, 3)

    def test_pipe_open(self):
        payload = struct.pack("<HH H", 0, 0, 3)
        payload += b"LOGSRV\x00U\x00"
        payload += struct.pack("<I", 6)
        result = parse_pipe_message(payload)
        self.assertIsInstance(result, PipeOpenRequest)
        self.assertEqual(result.client_pipe_idx, 3)
        self.assertEqual(result.svc_name, "LOGSRV")
        self.assertEqual(result.version, 6)

    def test_pipe_data(self):
        content = struct.pack("<H", 3) + b"\x06\x00\x00"
        result = parse_pipe_message(content)
        self.assertIsInstance(result, PipeData)
        self.assertEqual(result.pipe_idx, 3)


class TestParseConnectionRequest(unittest.TestCase):
    # MOS-RPC-SPEC 5.1 capture: Straight client, US English, Windows 95 build
    # 4.00.1111, no failed connections and no modem.
    FIELD = bytes.fromhex(
        "06000000"  # FormatVer 6
        "00000000"  # LineRate 0: came in over Straight
        "7c7c7c7c7c7c7c7c30303030303430397c00"  # Locale "||||||||00000409|"
        "00"  # ConnLog, empty
        "00"  # LinkDesc, empty
        "0d000000"  # Elapsed 13 ms
        "09000000 01000000 01000000 04000000 00000000 57040004 01000000"  # OS block
    )

    def test_capture(self):
        req = parse_connection_request(self.FIELD)
        self.assertIsNotNone(req)
        self.assertEqual(req.format_ver, 6)
        self.assertEqual(req.line_rate, 0)
        self.assertEqual(req.locale, "||||||||00000409|")
        self.assertEqual(req.lcid, "00000409")
        self.assertEqual(req.conn_log, "")
        self.assertEqual(req.conn_log_records, [])
        self.assertEqual(req.link_desc, "")
        self.assertEqual(req.elapsed_ms, 13)
        self.assertEqual(req.language_id, 9)
        self.assertEqual(req.platform_name, "win9x")
        self.assertEqual((req.major_version, req.minor_version, req.build_number), (4, 0, 1111))

    def test_filled_strings(self):
        field = self.FIELD[:8]
        field += b"||||||||00000416|\x00"
        field += b"10.0.0.1!10060|3|0871234567\r!5|1|0871234599\x00"
        field += b"5551234\x03Unimodem\x04Generic 14400\x00"
        field += self.FIELD[-32:]
        req = parse_connection_request(field)
        self.assertEqual(req.lcid, "00000416")
        self.assertEqual(req.conn_log_records, ["10.0.0.1!10060|3|0871234567", "!5|1|0871234599"])
        self.assertEqual(req.link_desc, "5551234\x03Unimodem\x04Generic 14400")
        self.assertEqual(req.elapsed_ms, 13)

    def test_short_field_is_not_decoded(self):
        self.assertIsNone(parse_connection_request(self.FIELD[:42]))

    def test_missing_terminator_is_not_decoded(self):
        field = self.FIELD[:8] + b"|" * 60
        self.assertIsNone(parse_connection_request(field))


class TestControlFrame(unittest.TestCase):
    def test_format(self):
        payload = b"\x01\x02\x03"
        frame = build_control_frame(3, payload)
        self.assertEqual(frame[:2], b"\xff\xff")
        self.assertEqual(frame[2], 3)
        self.assertEqual(frame[3:], payload)


class TestPipeOpenResult(unittest.TestCase):
    def test_produces_parseable_packet(self):
        pkt = build_pipe_open_result(3, 1, 0)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)

    def test_known_wire_bytes(self):
        pkt = build_pipe_open_result(3, 2, 3)
        expected = bytes.fromhex("82 83 e3 08 00 03 00 01 00 03 00 00 00 b6 d3 09 2d 0d")
        self.assertEqual(pkt, expected)


class TestControlType1Ack(unittest.TestCase):
    def test_echoes_payload(self):
        payload = b"some control data"
        pkt = build_control_type1_ack(1, 1, payload)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)
        self.assertIn(payload, parsed.payload)


if __name__ == "__main__":
    unittest.main()
