"""Tests for pipe framing, control frames, and pipe0 routing."""

import struct
import unittest

from server.models import ControlMessage, PipeData, PipeOpenRequest
from server.mpc import build_control_type1_ack, build_pipe_open_result
from server.pipe import (
    build_control_frame,
    build_pipe_frame,
    build_pipe_frame_has_length,
    parse_pipe0_content,
    parse_pipe_frame,
    parse_pipe_frames,
)
from server.transport import parse_packet


class TestPipeFrameContinuation(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello pipe"
        frame = build_pipe_frame(3, data)
        parsed, _ = parse_pipe_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.pipe_idx, 3)
        self.assertTrue(parsed.last_data)
        self.assertEqual(parsed.content, data)

    def test_pipe0(self):
        data = b"\xff\xff\x01test"
        frame = build_pipe_frame(0, data)
        parsed, _ = parse_pipe_frame(frame)
        self.assertEqual(parsed.pipe_idx, 0)
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
        self.assertEqual(parsed.pipe_idx, 3)
        self.assertTrue(parsed.last_data)
        self.assertEqual(parsed.content, data)

    def test_has_length_bit_set(self):
        frame = build_pipe_frame_has_length(2, b"test")
        hdr = frame[0]
        self.assertTrue(hdr & 0x10, "Has-length bit should be set")
        self.assertFalse(hdr & 0x20, "Continuation bit should NOT be set")


class TestParseMultipleFrames(unittest.TestCase):
    def test_two_frames(self):
        f1 = build_pipe_frame_has_length(1, b"first")
        f2 = build_pipe_frame(2, b"second")
        frames = parse_pipe_frames(f1 + f2)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].pipe_idx, 1)
        self.assertEqual(frames[0].content, b"first")
        self.assertEqual(frames[1].pipe_idx, 2)
        self.assertEqual(frames[1].content, b"second")


class TestParsePipe0Content(unittest.TestCase):
    def test_control_frame(self):
        content = b"\xff\xff\x03" + b"\x00" * 20
        result = parse_pipe0_content(content)
        self.assertIsInstance(result, ControlMessage)
        self.assertEqual(result.ctrl_type, 3)

    def test_pipe_open(self):
        payload = struct.pack("<HH H", 0, 0, 3)
        payload += b"LOGSRV\x00U\x00"
        payload += struct.pack("<I", 6)
        result = parse_pipe0_content(payload)
        self.assertIsInstance(result, PipeOpenRequest)
        self.assertEqual(result.client_pipe_idx, 3)
        self.assertEqual(result.svc_name, "LOGSRV")
        self.assertEqual(result.version, 6)

    def test_pipe_data(self):
        content = struct.pack("<H", 3) + b"\x06\x00\x00"
        result = parse_pipe0_content(content)
        self.assertIsInstance(result, PipeData)
        self.assertEqual(result.pipe_idx, 3)


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
