"""Tests for the empirical TextRuns / TextTree decoders in
`server.services.medview.ccontent`."""

import unittest
from pathlib import Path

import olefile

from scripts.inspect_blackbird_title import maybe_decompress_ck
from server.services.medview.ccontent import (
    TEXT_NODE_TAG,
    PictureRef,
    StyleRun,
    decode_textruns,
    decode_texttree,
    is_texttree,
    parse_element_tree,
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

    def test_msn_today_8_7_truncated_head(self):
        # First 32 bytes of tests/assets/story_test.ttl `8/7/object` (TextRuns).
        # Body is CTypedPtrArray<CElementData>::Serialize: u16 count
        # then count × CElementData. count = 0x0002 = 2 (bytes 0..1).
        head = bytes.fromhex(
            "0200535468697320697320616e206578616d706c65206f6620636f6e74656e74"
        )
        decoded = decode_textruns(head)
        # Legacy (version, flag) view: bytes 0..1 are the count
        # (matches `02 00`), exposed as-is for backward compat.
        self.assertEqual(decoded.header_version, 0x02)
        self.assertEqual(decoded.header_byte_1, 0x00)
        # `text` retains legacy semantics (everything from +2).
        self.assertTrue(decoded.text.startswith("S"))
        self.assertIn("This is an example of content", decoded.text)
        self.assertEqual(decoded.style_runs, ())
        # Element 0's length byte is 0x53 (=83); 32-byte head has only
        # 30 of those, so the decoder can't fully parse element 0 and
        # returns an empty blob list.
        self.assertEqual(decoded.blobs, ())

    def test_full_8_7_decodes_to_two_blobs(self):
        # Full TextRuns body has two prose blobs:
        #   element 0: length=0x53 (83) "This is an example…Extensions! "
        #   element 1: length=0x23 (35) "Ordered list is supported as well: "
        raw = _load_ttl_object(self.FIXTURE, "8/7/\x03object")
        decoded = decode_textruns(raw)
        self.assertEqual(len(decoded.blobs), 2)
        self.assertTrue(decoded.blobs[0].startswith("This is an example"))
        self.assertIn("Blackbird Extensions!", decoded.blobs[0])
        self.assertEqual(len(decoded.blobs[0]), 0x53)
        self.assertTrue(decoded.blobs[1].startswith("Ordered list"))
        self.assertEqual(len(decoded.blobs[1]), 0x23)

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
        # One picture intrusion: PICTURE.PictureCtrl.1 + filename + IUID.
        self.assertEqual(len(decoded.picture_refs), 1)
        ref = decoded.picture_refs[0]
        self.assertEqual(ref.clsid, "PICTURE.PictureCtrl.1")
        self.assertEqual(ref.filename, "bitmap.bmp")
        # IUID = 16 bytes; first 4 = `61 9c fa e5` = LE u32 of the
        # picture's CLSID time-low field.
        self.assertEqual(len(ref.iuid), 16)
        self.assertEqual(ref.iuid[:4], bytes.fromhex("619cfae5"))
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


class TestElementTree(unittest.TestCase):
    """`CElementNode` grammar: `[u16 tag][u8 version]` then a
    version-dependent payload, then `[u16 child_count]` children.
    Version 2 is a fixed dword, 3 a CElementData blob, 5 a Pascal-string
    property list."""

    def test_paragraph_holds_one_text_leaf(self):
        # `<H1>Story title</H1>`: tag 7, one child, and the child is a
        # version-3 leaf carrying 11 bytes.
        body = bytes.fromhex("01") + bytes.fromhex("0700010100") + (
            bytes.fromhex("ffff030b") + b"Story title" + bytes.fromhex("0000")
        )
        root = parse_element_tree(body)
        self.assertIsNotNone(root)
        self.assertEqual((root.tag, root.version), (0x07, 1))
        self.assertEqual(len(root.children), 1)
        leaf = root.children[0]
        self.assertEqual(leaf.tag, TEXT_NODE_TAG)
        self.assertTrue(leaf.is_text)
        self.assertEqual(leaf.data, b"Story title")
        self.assertEqual(root.text, "Story title")

    def test_childless_element_has_no_text(self):
        root = parse_element_tree(bytes.fromhex("01") + bytes.fromhex("0600010000"))
        self.assertEqual(root.tag, 0x06)
        self.assertEqual(root.children, ())
        self.assertEqual(root.text, "")

    def test_version_two_dword_leaf_is_not_prose(self):
        # `story_test.ttl 8/6` puts one of these in the empty `<P>`
        # ahead of each list.
        body = bytes.fromhex("01") + bytes.fromhex("0600010100") + \
            bytes.fromhex("ffff02") + bytes.fromhex("01000000") + bytes.fromhex("0000")
        root = parse_element_tree(body)
        leaf = root.children[0]
        self.assertEqual((leaf.version, leaf.data), (2, b"\x01\x00\x00\x00"))
        self.assertEqual(root.text, "")

    def test_version_five_carries_pascal_property_pairs(self):
        body = (
            bytes.fromhex("01")
            + bytes.fromhex("2e0005") + bytes.fromhex("0200")
            + bytes([5]) + b"CLSID" + bytes([21]) + b"PICTURE.PictureCtrl.1"
            + bytes([2]) + b"CX" + bytes([4]) + b"1500"
            + bytes.fromhex("0000")
        )
        root = parse_element_tree(body)
        self.assertEqual(root.tag, 0x2E)
        self.assertEqual(
            root.props,
            (("CLSID", "PICTURE.PictureCtrl.1"), ("CX", "1500")),
        )

    def test_truncated_body_returns_none(self):
        self.assertIsNone(parse_element_tree(bytes.fromhex("010500")))
        self.assertIsNone(parse_element_tree(b""))

    def test_msn_today_plain_story_round_trips(self):
        raw = _load_ttl_object("tests/assets/story_test.ttl", "8/2/\x03object")
        decoded = decode_texttree(raw)
        root = decoded.root
        self.assertIsNotNone(root)
        self.assertEqual(root.tag, 0x05)
        head, body = root.children
        self.assertEqual((head.tag, head.children), (0x0B, ()))
        self.assertEqual([c.tag for c in body.children], [0x07, 0x06])
        self.assertEqual(body.children[0].text, "Calendar of Events")
        # The scanner's flattened `text` stays the same view.
        self.assertIn("Calendar of Events", decoded.text)


class TestPictureRefDataclass(unittest.TestCase):
    def test_construction(self):
        ref = PictureRef(
            byte_offset=0x4b5,
            clsid="PICTURE.PictureCtrl.1",
            filename="bitmap.bmp",
            iuid=b"\x01" * 16,
        )
        self.assertEqual(ref.byte_offset, 0x4b5)
        self.assertEqual(ref.clsid, "PICTURE.PictureCtrl.1")
        self.assertEqual(ref.filename, "bitmap.bmp")
        self.assertEqual(len(ref.iuid), 16)


if __name__ == "__main__":
    unittest.main()
