"""Tests for host blocks, tagged parameter parsing, and reply encoding."""

import struct
import unittest

from server.models import ByteParam, DwordParam, UnknownParam, VarParam, WordParam
from server.mpc import (
    build_host_block,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    encode_reply_var_length,
    is_iterator_cancel,
    parse_host_block,
    parse_request_params,
)


class TestHostBlock(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        payload = b"\x83\x00\x00\x00\x00"
        hb = build_host_block(0x06, 0x00, 0, payload)
        parsed = parse_host_block(hb)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.msg_class, 0x06)
        self.assertEqual(parsed.selector, 0x00)
        self.assertEqual(parsed.request_id, 0)
        self.assertEqual(parsed.payload, payload)

    def test_with_2byte_request_id(self):
        hb = build_host_block(0x01, 0x02, 100, b"\x01\x02")
        parsed = parse_host_block(hb)
        self.assertEqual(parsed.request_id, 100)

    def test_parse_too_short(self):
        self.assertIsNone(parse_host_block(b"\x06"))

    def test_parse_empty(self):
        self.assertIsNone(parse_host_block(b""))

    def test_known_login_request(self):
        raw = bytes.fromhex(
            "06 00 00 03 43 16 00 00 04 d8 00 00 00 00 6d 69"
            "63 72 6f 73 6f 66 74 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 74 65 73 74"
            "00 00 00 01 00 00 00 c0 32 3b 82 00 00 00 00 83"
            "83 83 83 83 83 83 84"
        )
        parsed = parse_host_block(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.msg_class, 0x06)
        self.assertEqual(parsed.selector, 0x00)
        self.assertEqual(parsed.request_id, 0)
        self.assertGreater(len(parsed.payload), 90)
        self.assertIn(b"microsoft", parsed.payload)


class TestParseRequestParams(unittest.TestCase):
    def test_byte_param(self):
        data = bytes([0x01, 0x42])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 1)
        self.assertIsInstance(params[0], ByteParam)
        self.assertEqual(params[0].value, 0x42)

    def test_word_param(self):
        data = bytes([0x02]) + struct.pack("<H", 0x1234)
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], WordParam)
        self.assertEqual(params[0].value, 0x1234)

    def test_dword_param(self):
        data = bytes([0x03]) + struct.pack("<I", 0xDEADBEEF)
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], DwordParam)
        self.assertEqual(params[0].value, 0xDEADBEEF)

    def test_variable_param_inline_length(self):
        data = bytes([0x04, 0x85]) + b"hello"
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], VarParam)
        self.assertEqual(len(params[0].data), 5)
        self.assertEqual(params[0].data, b"hello")

    def test_recv_descriptors(self):
        data = bytes([0x83, 0x83, 0x85])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 0)
        self.assertEqual(descs, [0x83, 0x83, 0x85])

    def test_mixed_send_and_recv(self):
        data = bytes([0x01, 0x42, 0x83, 0x84])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].value, 0x42)
        self.assertEqual(descs, [0x83, 0x84])

    def test_known_password_change_payload(self):
        payload = bytes.fromhex(
            "04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19"
            "3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00"
            "00 54 2b 10 04 b8 83"
        )
        params, descs = parse_request_params(payload)
        self.assertEqual(len(params), 2)
        self.assertIsInstance(params[0], VarParam)
        self.assertEqual(len(params[0].data), 17)
        self.assertIsInstance(params[1], VarParam)
        self.assertEqual(len(params[1].data), 17)
        old_pw = params[0].data.split(b"\x00", 1)[0]
        new_pw = params[1].data.split(b"\x00", 1)[0]
        self.assertEqual(old_pw, b"teste")
        self.assertEqual(new_pw, b"avocados")
        self.assertEqual(descs, [0x83])

    def test_known_login_payload(self):
        payload = bytes.fromhex(
            "03 43 16 00 00 04 d8 00 00 00 00 6d 69 63 72 6f"
            "73 6f 66 74 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 74 65 73 74"
            "00 00 00 01 00 00 00 c0 32 3b 82 00 00 00 00 83"
            "83 83 83 83 83 83 84"
        )
        params, descs = parse_request_params(payload)
        self.assertIsInstance(params[0], DwordParam)
        self.assertIsInstance(params[1], VarParam)
        self.assertIn(b"microsoft", params[1].data)
        self.assertIn(b"test", params[1].data)
        self.assertEqual(len(descs), 8)
        self.assertEqual(descs[:7], [0x83] * 7)
        self.assertEqual(descs[7], 0x84)


class TestParseRequestParamsTruncation(unittest.TestCase):
    """Malformed/truncated send-side payloads must fail gracefully —
    parse_request_params is fed straight from the wire and cannot raise."""

    def test_empty_payload(self):
        params, descs = parse_request_params(b"")
        self.assertEqual(params, [])
        self.assertEqual(descs, [])

    def test_truncated_byte_param(self):
        # Tag 0x01 with no following byte.
        params, descs = parse_request_params(bytes([0x01]))
        self.assertEqual(params, [])
        self.assertEqual(descs, [])

    def test_truncated_word_param(self):
        # Tag 0x02 with only 1 of 2 expected bytes.
        params, descs = parse_request_params(bytes([0x02, 0xAA]))
        self.assertEqual(params, [])

    def test_truncated_dword_param(self):
        # Tag 0x03 with only 3 of 4 expected bytes.
        params, descs = parse_request_params(bytes([0x03, 0xAA, 0xBB, 0xCC]))
        self.assertEqual(params, [])

    def test_truncated_variable_length_byte(self):
        # Tag 0x04 with no following length byte at all.
        params, descs = parse_request_params(bytes([0x04]))
        self.assertEqual(params, [])

    def test_variable_length_promises_more_data_than_provided(self):
        # Tag 0x04, inline-length 5, but only 2 bytes follow.  Parser
        # currently returns whatever data is present without raising.
        data = bytes([0x04, 0x85, ord("h"), ord("i")])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 1)
        self.assertIsInstance(params[0], VarParam)
        self.assertLessEqual(len(params[0].data), 5)

    def test_unknown_send_tag_captured_as_unknown_param(self):
        # 0x42 isn't a known send tag (0x01-0x05) and bit 7 is clear so
        # it's not a recv descriptor either.  Captured as UnknownParam.
        data = bytes([0x42, 0xDE, 0xAD])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 1)
        self.assertIsInstance(params[0], UnknownParam)
        self.assertEqual(params[0].tag, 0x42)

    def test_many_recv_descriptors_only(self):
        # Eight recv descriptors, no send params — common in summary RPCs.
        data = bytes([0x83] * 7 + [0x84])
        params, descs = parse_request_params(data)
        self.assertEqual(params, [])
        self.assertEqual(len(descs), 8)
        self.assertEqual(descs, [0x83] * 7 + [0x84])

    def test_interleaved_send_and_recv(self):
        # Recv descriptors can appear anywhere in the stream.
        data = bytes([0x83, 0x01, 0x42, 0x83, 0x02, 0x12, 0x34, 0x84])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 2)
        self.assertEqual(params[0].value, 0x42)
        self.assertEqual(params[1].value, 0x3412)
        self.assertEqual(descs, [0x83, 0x83, 0x84])


class TestTaggedReply(unittest.TestCase):
    def test_dword_reply(self):
        result = build_tagged_reply_dword(0)
        self.assertEqual(result, b"\x83\x00\x00\x00\x00")

    def test_dword_reply_nonzero(self):
        result = build_tagged_reply_dword(0x12345678)
        self.assertEqual(result, b"\x83" + struct.pack("<I", 0x12345678))

    def test_var_reply_short(self):
        data = b"\x00" * 16
        result = build_tagged_reply_var(0x84, data)
        self.assertEqual(result[0], 0x84)
        self.assertEqual(result[1], 0x90)
        self.assertEqual(result[2:], data)

    def test_encode_reply_var_length_inline(self):
        encoded = encode_reply_var_length(16)
        self.assertEqual(encoded, bytes([0x80 | 16]))
        self.assertEqual(len(encoded), 1)

    def test_encode_reply_var_length_2byte(self):
        encoded = encode_reply_var_length(200)
        self.assertEqual(len(encoded), 2)
        reconstructed = (encoded[0] & 0x7F) << 8 | encoded[1]
        self.assertEqual(reconstructed, 200)


class TestIteratorCancel(unittest.TestCase):
    """MPCCL iterator-cancel control frame predicate (`docs/MEDVIEW.md` §6d.0).

    The frame is a single `0x0F` byte in the host-block payload, shipped on
    the same `(class, selector, req_id)` as the original stream-iterator
    subscribe.  The predicate must not false-positive on subscribe payloads
    or any other tagged-param shape.
    """

    def test_is_iterator_cancel_recognizes_single_0f(self):
        self.assertTrue(is_iterator_cancel(b"\x0F"))

    def test_is_iterator_cancel_rejects_empty(self):
        self.assertFalse(is_iterator_cancel(b""))

    def test_is_iterator_cancel_rejects_subscribe_shape(self):
        # `0x01 <type> 0x85` is the §6a subscribe payload.
        self.assertFalse(is_iterator_cancel(b"\x01\x00\x85"))

    def test_is_iterator_cancel_rejects_two_byte_0f(self):
        self.assertFalse(is_iterator_cancel(b"\x0F\x00"))

    def test_is_iterator_cancel_rejects_other_single_byte(self):
        for b in (b"\x01", b"\xFF", b"\x87", b"\x00", b"\x10"):
            self.assertFalse(is_iterator_cancel(b), msg=f"false-positive on {b!r}")


if __name__ == "__main__":
    unittest.main()
