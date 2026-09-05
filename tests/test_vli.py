"""Tests for Variable-Length Integer encoding/decoding."""

import unittest

from server.mpc import decode_vli, encode_vli


class TestVLI(unittest.TestCase):
    def test_1byte_zero(self):
        encoded = encode_vli(0)
        self.assertEqual(len(encoded), 1)
        val, length = decode_vli(encoded)
        self.assertEqual(val, 0)
        self.assertEqual(length, 1)

    def test_1byte_max(self):
        encoded = encode_vli(0x3E)
        self.assertEqual(len(encoded), 1)
        val, length = decode_vli(encoded)
        self.assertEqual(val, 0x3E)
        self.assertEqual(length, 1)

    def test_2byte_min(self):
        """0x3F is the widest 1-byte value but the client spills it to 2 bytes."""
        self.assertEqual(encode_vli(0x3F), b"\x80\x3f")

    def test_2byte_max(self):
        encoded = encode_vli(0x3FFE)
        self.assertEqual(len(encoded), 2)
        val, length = decode_vli(encoded)
        self.assertEqual(val, 0x3FFE)
        self.assertEqual(length, 2)

    def test_4byte_min(self):
        """0x3FFF is the widest 2-byte value but the client spills it to 4."""
        self.assertEqual(encode_vli(0x3FFF), b"\xc0\x00\x3f\xff")

    def test_4byte_large(self):
        encoded = encode_vli(0x3FFFFFFE)
        self.assertEqual(len(encoded), 4)
        val, length = decode_vli(encoded)
        self.assertEqual(val, 0x3FFFFFFE)
        self.assertEqual(length, 4)

    def test_max_value_has_no_encoding(self):
        with self.assertRaises(ValueError):
            encode_vli(0x3FFFFFFF)

    def test_roundtrip_range(self):
        for v in [0, 1, 32, 62, 63, 64, 100, 1000, 16382, 16383, 16384, 100000, 0x3FFFFFFE]:
            encoded = encode_vli(v)
            decoded, _ = decode_vli(encoded)
            self.assertEqual(decoded, v, f"Roundtrip failed for {v}")

    def test_1byte_top_bits_00(self):
        encoded = encode_vli(10)
        self.assertEqual(encoded[0] & 0xC0, 0x00)

    def test_2byte_top_bits_10(self):
        encoded = encode_vli(100)
        self.assertEqual(encoded[0] & 0xC0, 0x80)

    def test_4byte_top_bits_11(self):
        encoded = encode_vli(0x3FFF)
        self.assertEqual(encoded[0] & 0xC0, 0xC0)

    def test_decode_at_offset(self):
        prefix = b"\xaa\xbb"
        encoded = encode_vli(42)
        data = prefix + encoded
        val, length = decode_vli(data, pos=2)
        self.assertEqual(val, 42)

    def test_decode_empty(self):
        val, length = decode_vli(b"", 0)
        self.assertIsNone(val)
        self.assertEqual(length, 0)


if __name__ == "__main__":
    unittest.main()
