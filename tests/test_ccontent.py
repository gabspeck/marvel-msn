"""Tests for the empirical TextRuns / TextTree gate in
`server.services.medview.ccontent`."""

import unittest

from server.services.medview.ccontent import (
    StyleRun,
    decode_textruns,
    is_texttree,
)


class TestDecodeTextRuns(unittest.TestCase):
    def test_msn_today_8_7_fixture(self):
        # First 32 bytes of msn_today.ttl `8/7/object` (TextRuns).
        head = bytes.fromhex(
            "0200535468697320697320616e206578616d706c65206f6620636f6e74656e74"
        )
        decoded = decode_textruns(head)
        self.assertEqual(decoded.header_version, 0x02)
        self.assertEqual(decoded.header_byte_1, 0x00)
        # Leading control byte 'S' (0x53) is part of the payload; the
        # exact semantics aren't pinned yet (PR2 BBCTL.OCX RE will
        # resolve), but the prose body still parses cleanly.
        self.assertTrue(decoded.text.startswith("S"))
        self.assertIn("This is an example of content", decoded.text)
        self.assertEqual(decoded.style_runs, ())

    def test_empty_blob_returns_empty_container(self):
        # CContent `8/3` and `8/7` for missing/empty TextRuns ship as
        # `00 00` (2 B). Decoder must NOT raise.
        decoded = decode_textruns(b"\x00\x00")
        self.assertEqual(decoded.text, "")
        self.assertEqual(decoded.style_runs, ())
        self.assertEqual(decoded.header_version, 0x00)
        self.assertEqual(decoded.header_byte_1, 0x00)

    def test_zero_length_input_returns_empty(self):
        decoded = decode_textruns(b"")
        self.assertEqual(decoded.text, "")
        self.assertEqual(decoded.raw_payload, b"")

    def test_texttree_header_raises(self):
        # 8/6 in msn_today (TextTree): `01 05 ...`.
        with self.assertRaises(NotImplementedError):
            decode_textruns(bytes.fromhex("0105000102000b00"))

    def test_is_texttree_gate(self):
        self.assertTrue(is_texttree(bytes.fromhex("01050001")))
        self.assertFalse(is_texttree(bytes.fromhex("02005468")))
        self.assertFalse(is_texttree(b""))


class TestStyleRunDataclass(unittest.TestCase):
    """StyleRun is the PR1 surface for the future style-runs decoder;
    PR1 always emits an empty tuple, but the dataclass shape is fixed
    so downstream callers can begin to type against it."""

    def test_construction(self):
        run = StyleRun(char_offset=10, char_length=5, style_id=2)
        self.assertEqual(run.char_offset, 10)
        self.assertEqual(run.char_length, 5)
        self.assertEqual(run.style_id, 2)


if __name__ == "__main__":
    unittest.main()
