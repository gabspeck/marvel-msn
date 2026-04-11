"""Tests for host blocks, tagged parameter parsing, and reply encoding."""
import unittest
import struct

from server.mpc import (
    build_host_block, parse_host_block,
    parse_request_params,
    build_tagged_reply_dword, build_tagged_reply_var,
    encode_reply_var_length,
)
from server.models import ByteParam, WordParam, DwordParam, VarParam


class TestHostBlock(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        payload = b'\x83\x00\x00\x00\x00'
        hb = build_host_block(0x06, 0x00, 0, payload)
        parsed = parse_host_block(hb)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.msg_class, 0x06)
        self.assertEqual(parsed.selector, 0x00)
        self.assertEqual(parsed.request_id, 0)
        self.assertEqual(parsed.payload, payload)

    def test_with_2byte_request_id(self):
        hb = build_host_block(0x01, 0x02, 100, b'\x01\x02')
        parsed = parse_host_block(hb)
        self.assertEqual(parsed.request_id, 100)

    def test_parse_too_short(self):
        self.assertIsNone(parse_host_block(b'\x06'))

    def test_parse_empty(self):
        self.assertIsNone(parse_host_block(b''))

    def test_known_login_request(self):
        raw = bytes.fromhex(
            '06 00 00 03 43 16 00 00 04 d8 00 00 00 00 6d 69'
            '63 72 6f 73 6f 66 74 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 74 65 73 74'
            '00 00 00 01 00 00 00 c0 32 3b 82 00 00 00 00 83'
            '83 83 83 83 83 83 84'
        )
        parsed = parse_host_block(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.msg_class, 0x06)
        self.assertEqual(parsed.selector, 0x00)
        self.assertEqual(parsed.request_id, 0)
        self.assertGreater(len(parsed.payload), 90)
        self.assertIn(b'microsoft', parsed.payload)


class TestParseRequestParams(unittest.TestCase):
    def test_byte_param(self):
        data = bytes([0x01, 0x42])
        params, descs = parse_request_params(data)
        self.assertEqual(len(params), 1)
        self.assertIsInstance(params[0], ByteParam)
        self.assertEqual(params[0].value, 0x42)

    def test_word_param(self):
        data = bytes([0x02]) + struct.pack('<H', 0x1234)
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], WordParam)
        self.assertEqual(params[0].value, 0x1234)

    def test_dword_param(self):
        data = bytes([0x03]) + struct.pack('<I', 0xDEADBEEF)
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], DwordParam)
        self.assertEqual(params[0].value, 0xDEADBEEF)

    def test_variable_param_inline_length(self):
        data = bytes([0x04, 0x85]) + b'hello'
        params, descs = parse_request_params(data)
        self.assertIsInstance(params[0], VarParam)
        self.assertEqual(len(params[0].data), 5)
        self.assertEqual(params[0].data, b'hello')

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
            '04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19'
            '3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00'
            '00 54 2b 10 04 b8 83'
        )
        params, descs = parse_request_params(payload)
        self.assertEqual(len(params), 2)
        self.assertIsInstance(params[0], VarParam)
        self.assertEqual(len(params[0].data), 17)
        self.assertIsInstance(params[1], VarParam)
        self.assertEqual(len(params[1].data), 17)
        old_pw = params[0].data.split(b'\x00', 1)[0]
        new_pw = params[1].data.split(b'\x00', 1)[0]
        self.assertEqual(old_pw, b'teste')
        self.assertEqual(new_pw, b'avocados')
        self.assertEqual(descs, [0x83])

    def test_known_login_payload(self):
        payload = bytes.fromhex(
            '03 43 16 00 00 04 d8 00 00 00 00 6d 69 63 72 6f'
            '73 6f 66 74 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 74 65 73 74'
            '00 00 00 01 00 00 00 c0 32 3b 82 00 00 00 00 83'
            '83 83 83 83 83 83 84'
        )
        params, descs = parse_request_params(payload)
        self.assertIsInstance(params[0], DwordParam)
        self.assertIsInstance(params[1], VarParam)
        self.assertIn(b'microsoft', params[1].data)
        self.assertIn(b'test', params[1].data)
        self.assertEqual(len(descs), 8)
        self.assertEqual(descs[:7], [0x83] * 7)
        self.assertEqual(descs[7], 0x84)


class TestTaggedReply(unittest.TestCase):
    def test_dword_reply(self):
        result = build_tagged_reply_dword(0)
        self.assertEqual(result, b'\x83\x00\x00\x00\x00')

    def test_dword_reply_nonzero(self):
        result = build_tagged_reply_dword(0x12345678)
        self.assertEqual(result, b'\x83' + struct.pack('<I', 0x12345678))

    def test_var_reply_short(self):
        data = b'\x00' * 16
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


if __name__ == '__main__':
    unittest.main()
