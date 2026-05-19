"""Tests for the empirical TextRuns / TextTree decoders in
`server.services.medview.ccontent`."""

import unittest
from pathlib import Path

import olefile

from scripts.inspect_blackbird_title import maybe_decompress_ck
from server.services.medview.ccontent import (
    PictureRef,
    StyleRun,
    decode_textruns,
    decode_texttree,
    is_texttree,
)


def _load_ttl_object(fixture: str, stream: str) -> bytes:
    """Read a CContent object stream from a TTL fixture, transparently
    decompressing the CK wrapper when present."""
    ole = olefile.OleFileIO(fixture)
    raw = ole.openstream(stream).read()
    wrapper = maybe_decompress_ck(raw)
    return wrapper["payload"] if wrapper else raw


class TestDecodeTextRuns(unittest.TestCase):
    FIXTURE = "tests/assets/story_test.ttl"

    def test_msn_today_8_7_fixture(self):
        # First 32 bytes of tests/assets/story_test.ttl `8/7/object` (TextRuns).
        head = bytes.fromhex(
            "0200535468697320697320616e206578616d706c65206f6620636f6e74656e74"
        )
        decoded = decode_textruns(head)
        self.assertEqual(decoded.header_version, 0x02)
        self.assertEqual(decoded.header_byte_1, 0x00)
        # `text` retains legacy semantics (everything from +2).
        self.assertTrue(decoded.text.startswith("S"))
        self.assertIn("This is an example of content", decoded.text)
        self.assertEqual(decoded.style_runs, ())
        # Paragraph markers surface the 'S' marker + prose.
        self.assertEqual(len(decoded.paragraph_markers), 1)
        off, marker, prose = decoded.paragraph_markers[0]
        self.assertEqual(off, 0)
        self.assertEqual(marker, "S")
        self.assertIn("This is an example of content", prose)

    def test_full_8_7_paragraph_split(self):
        # Full TextRuns body has two paragraphs: 'S' (story-body) +
        # '#' (ordered-list item). The scanner picks them up at the
        # right byte offsets.
        raw = _load_ttl_object(self.FIXTURE, "8/7/\x03object")
        decoded = decode_textruns(raw)
        markers = [(m[0], m[1]) for m in decoded.paragraph_markers]
        self.assertEqual(markers, [(0, "S"), (0x54, "#")])
        prose_first = decoded.paragraph_markers[0][2]
        self.assertIn("Blackbird Extensions!", prose_first)
        prose_second = decoded.paragraph_markers[1][2]
        self.assertTrue(prose_second.startswith("Ordered list"))

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
        # 8/6 in story_test.ttl (TextTree): `01 05 ...`. Caller should
        # branch on `is_texttree(raw)` and call `decode_texttree`.
        with self.assertRaises(ValueError):
            decode_textruns(bytes.fromhex("0105000102000b00"))

    def test_is_texttree_gate(self):
        self.assertTrue(is_texttree(bytes.fromhex("01050001")))
        self.assertFalse(is_texttree(bytes.fromhex("02005468")))
        self.assertFalse(is_texttree(b""))


class TestDecodeTextTree(unittest.TestCase):
    """Partial TextTree decoder — scans `[0x03 length text]` segments.

    Pinned against the two TextTree CContent streams in
    `tests/assets/story_test.ttl` (8/2 plain prose, 8/6 with a
    picture-INTRUDE record and an itemised list)."""

    FIXTURE = "tests/assets/story_test.ttl"

    def test_8_2_recovers_two_text_segments(self):
        raw = _load_ttl_object(self.FIXTURE, "8/2/\x03object")
        self.assertTrue(is_texttree(raw))
        decoded = decode_texttree(raw)
        self.assertEqual(
            [text for _, text in decoded.segments],
            ["Calendar of Events", "here's what's been happenin' "],
        )
        self.assertEqual(
            decoded.text,
            "Calendar of Events\nhere's what's been happenin' ",
        )
        self.assertEqual(decoded.style_runs, ())
        self.assertEqual(decoded.picture_refs, ())

    def test_8_6_recovers_text_and_picture_intrusion(self):
        raw = _load_ttl_object(self.FIXTURE, "8/6/\x03object")
        self.assertTrue(is_texttree(raw))
        decoded = decode_texttree(raw)
        # All visible prose segments from the story.
        texts = [text for _, text in decoded.segments]
        self.assertEqual(
            texts,
            [
                "MSN Today (update test)",
                "Here's an unordered list: ",
                "An item!",
                "And another",
                "Subitems!",
                "There' s levels!!",
                "Last one",
                "First item",
                "Identation don' t mean a thang!",
                "That's all folks.",
            ],
        )
        # One picture intrusion: PICTURE.PictureCtrl.1.
        self.assertEqual(len(decoded.picture_refs), 1)
        self.assertEqual(
            decoded.picture_refs[0].clsid,
            "PICTURE.PictureCtrl.1",
        )
        # Segments preserve document order via byte offsets.
        offsets = [off for off, _ in decoded.segments]
        self.assertEqual(offsets, sorted(offsets))

    def test_rejects_non_texttree_magic(self):
        with self.assertRaises(ValueError):
            decode_texttree(b"\x02\x00Hello")

    def test_handles_empty_after_magic(self):
        # Magic-only payload decodes to empty text, no segments.
        decoded = decode_texttree(b"\x01\x05")
        self.assertEqual(decoded.text, "")
        self.assertEqual(decoded.segments, ())
        self.assertEqual(decoded.picture_refs, ())


class TestStyleRunDataclass(unittest.TestCase):
    """StyleRun is the PR1 surface for the future style-runs decoder;
    PR1 always emits an empty tuple, but the dataclass shape is fixed
    so downstream callers can begin to type against it."""

    def test_construction(self):
        run = StyleRun(char_offset=10, char_length=5, style_id=2)
        self.assertEqual(run.char_offset, 10)
        self.assertEqual(run.char_length, 5)
        self.assertEqual(run.style_id, 2)


class TestPictureRefDataclass(unittest.TestCase):
    def test_construction(self):
        ref = PictureRef(byte_offset=0x4b5, clsid="PICTURE.PictureCtrl.1")
        self.assertEqual(ref.byte_offset, 0x4b5)
        self.assertEqual(ref.clsid, "PICTURE.PictureCtrl.1")


if __name__ == "__main__":
    unittest.main()
