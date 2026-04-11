"""Tests for wire encoding: CRC-32, byte-stuffing, header byte encoding."""
import unittest

from server.wire import (
    crc32, byte_stuff, byte_unstuff, mask_crc,
    encode_header_byte, decode_header_byte, CRC_TABLE,
)
from server.config import ESCAPE_SET, STUFF_MAP, UNSTUFF_MAP


class TestCRC32(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(crc32(b''), 0)

    def test_single_zero(self):
        self.assertEqual(crc32(b'\x00'), CRC_TABLE[0])

    def test_known_transport_params(self):
        wire = bytes.fromhex(
            '80 80 e0 17 00 ff ff 03 00 01 00 00 00 01 00 00'
            ' 1b 32 00 00 00 01 00 00 00 58 02 00 00'
        )
        crc_val = crc32(wire)
        crc_bytes = crc_val.to_bytes(4, 'little')
        masked = mask_crc(crc_bytes)
        self.assertEqual(masked, bytes.fromhex('31 c4 49 2f'))

    def test_known_client_ctrl4(self):
        wire = bytes.fromhex('80 80 e0 03 00 ff ff 04')
        crc_val = crc32(wire)
        crc_bytes = crc_val.to_bytes(4, 'little')
        masked = mask_crc(crc_bytes)
        self.assertEqual(masked, bytes.fromhex('fc 03 18 a0'))

    def test_incremental_matches_bulk(self):
        data = b'Hello, Marvel protocol!'
        bulk = crc32(data)
        self.assertEqual(crc32(data), bulk)


class TestByteStuffing(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(byte_stuff(b''), b'')
        self.assertEqual(byte_unstuff(b''), b'')

    def test_roundtrip_no_special(self):
        data = b'Hello World 123'
        self.assertEqual(byte_unstuff(byte_stuff(data)), data)

    def test_roundtrip_all_special(self):
        data = bytes(ESCAPE_SET)
        self.assertEqual(byte_unstuff(byte_stuff(data)), data)

    def test_each_escape_mapping(self):
        for raw_byte, stuffed in STUFF_MAP.items():
            self.assertEqual(byte_stuff(bytes([raw_byte])), stuffed)

    def test_unstuff_each_mapping(self):
        for stuffed, raw_byte in UNSTUFF_MAP.items():
            self.assertEqual(byte_unstuff(bytes([0x1B, stuffed])), bytes([raw_byte]))

    def test_no_bare_0x0d_in_stuffed(self):
        data = bytes(range(256))
        stuffed = byte_stuff(data)
        self.assertNotIn(0x0D, stuffed)

    def test_no_bare_0x1b_in_stuffed(self):
        data = bytes(range(256))
        stuffed = byte_stuff(data)
        i = 0
        while i < len(stuffed):
            if stuffed[i] == 0x1B:
                self.assertLess(i + 1, len(stuffed), "Trailing 0x1B")
                self.assertIn(stuffed[i + 1], UNSTUFF_MAP, "Unknown escape")
                i += 2
            else:
                self.assertNotEqual(stuffed[i], 0x1B)
                i += 1

    def test_roundtrip_all_byte_values(self):
        data = bytes(range(256))
        self.assertEqual(byte_unstuff(byte_stuff(data)), data)

    def test_stuffing_increases_size(self):
        data = bytes(ESCAPE_SET)
        stuffed = byte_stuff(data)
        self.assertEqual(len(stuffed), len(data) * 2)


class TestHeaderByte(unittest.TestCase):
    SPECIAL_VALUES = {0x8D, 0x90, 0x8B}

    def test_roundtrip_special_values(self):
        for v in self.SPECIAL_VALUES:
            encoded = encode_header_byte(v)
            self.assertNotEqual(encoded, v, f"0x{v:02x} should be encoded")
            self.assertEqual(decode_header_byte(encoded), v)

    def test_encode_produces_xor_c0(self):
        self.assertEqual(encode_header_byte(0x8D), 0x8D ^ 0xC0)
        self.assertEqual(encode_header_byte(0x90), 0x90 ^ 0xC0)
        self.assertEqual(encode_header_byte(0x8B), 0x8B ^ 0xC0)

    def test_non_special_passthrough(self):
        for v in range(256):
            if v not in self.SPECIAL_VALUES:
                self.assertEqual(encode_header_byte(v), v,
                                 f"0x{v:02x} should pass through unchanged")

    def test_all_byte_values_roundtrip(self):
        ENCODED_FORMS = {0x4D, 0x50, 0x4B}
        for v in range(256):
            if v in ENCODED_FORMS:
                continue
            self.assertEqual(decode_header_byte(encode_header_byte(v)), v,
                             f"Roundtrip failed for 0x{v:02x}")


class TestMaskCRC(unittest.TestCase):
    def test_safe_bytes_unchanged(self):
        crc = bytes([0x20, 0x30, 0x40, 0x50])
        self.assertEqual(mask_crc(crc), crc)

    def test_escape_bytes_masked(self):
        for b in ESCAPE_SET:
            crc = bytes([b, 0x00, 0x00, 0x00])
            masked = mask_crc(crc)
            self.assertNotIn(masked[0], ESCAPE_SET,
                             f"Byte 0x{b:02x} should be masked out of ESCAPE_SET")


if __name__ == '__main__':
    unittest.main()
