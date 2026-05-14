"""Unit tests for the MMV 2.0 MVB loader, pinned against NO_NSR.MVB."""

import pathlib
import unittest

from server.blackbird.wire import decode_case1_tlv
from server.services.medview.mvb_loader import (
    LoadedMVB,
    MvbFontDescriptor,
    MvbParagraph,
    build_mvb_bm0_baggage,
    build_mvb_first_paragraph_chunk,
    load_mvb,
    lower_mvb_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MVB_PATH = _REPO_ROOT / "resources" / "titles" / "NO_NSR.MVB"


class TestLoadMvb(unittest.TestCase):
    def test_known_mvb_parses_metadata(self):
        m = load_mvb(_MVB_PATH)
        self.assertIsNotNone(m)
        # |SYSTEM RecordType 1 (TITLE) is empty for this fixture.
        self.assertEqual(m.title, "")
        # MVBWINDOW Caption[51] ASCIIZ.
        self.assertEqual(m.caption, "Untitled")
        # MVBWINDOW X, Y, Width, Height (per-mille). 1023 = 0x3FF =
        # max-out used by some MVP authors.
        self.assertEqual(m.window_dims_permille, (0, 0, 1023, 1023))
        # |FONT NumDescriptors = 5; all stubbed to face[0] = "Helv"
        # until the pre-MVB descriptor layout is RE'd.
        self.assertEqual(len(m.font_table), 5)
        self.assertTrue(all(d.face_name == "Helv" for d in m.font_table))

    def test_non_scroll_field_pinned(self):
        m = load_mvb(_MVB_PATH)
        # First TOPICHEADER.NonScroll = 0xFFFFFFFF → no non-scrolling
        # region for this topic. This is the wire signal NO_NSR.MVB
        # exists to test against MSN's MOSVIEW.
        self.assertEqual(m.non_scroll, 0xFFFFFFFF)

    def test_first_paragraph_text_extracted(self):
        m = load_mvb(_MVB_PATH)
        # First RecordType 0x20 TOPICLINK in the topic body. The
        # paragraph is the topic heading text — the body paragraph
        # ("This topic should have NO NSR defined.") is the second
        # 0x20 record and not yet rendered.
        self.assertEqual(m.first_paragraph.text, "No NSR topic")
        # Twip metrics extracted from Paragraphinfo (compressed-short
        # SpacingAbove / SpacingBelow gating bits).
        self.assertEqual(m.first_paragraph.space_above_twips, 24)
        self.assertEqual(m.first_paragraph.space_below_twips, 6)

    def test_missing_path_returns_none(self):
        self.assertIsNone(load_mvb(pathlib.Path("/tmp/__no_mvb__.mvb")))


class TestLowerMvbToPayload(unittest.TestCase):
    def setUp(self):
        self.mvb = load_mvb(_MVB_PATH)
        self.assertIsNotNone(self.mvb)
        self.body = lower_mvb_to_payload(self.mvb)

    def test_body_contains_caption_cstring(self):
        self.assertIn(b"Untitled\x00", self.body)

    def test_body_contains_face_name(self):
        # sec0 face name table holds the 0x20-byte "Helv" slot.
        self.assertIn(b"Helv", self.body)

    def test_sec06_caption_at_offset_0x15_within_record(self):
        # sec06 record (0x98 B) contains the caption at offset 0x15
        # within. Locate by scanning for the ASCIIZ.
        idx = self.body.find(b"Untitled\x00")
        self.assertGreater(idx, 0)


class TestBuildMvbBm0Baggage(unittest.TestCase):
    def test_bm0_is_kind5_raster(self):
        m = load_mvb(_MVB_PATH)
        bag = build_mvb_bm0_baggage(m)
        # 8-byte container preamble; kind byte at +0x08.
        self.assertEqual(bag[8], 0x05)
        # 640×480 1bpp white raster fits in 38445 B (matches the empty
        # MSN Today baggage size).
        self.assertEqual(len(bag), 38445)


class TestBuildFirstParagraphChunk(unittest.TestCase):
    def test_chunk_carries_text_and_paragraph_spacing(self):
        m = load_mvb(_MVB_PATH)
        chunk = build_mvb_first_paragraph_chunk(m, title_slot=1, key=0x1000)
        # 0xBF dispatch byte.
        self.assertEqual(chunk[0], 0xBF)
        # title_slot at +0x01.
        self.assertEqual(chunk[1], 0x01)
        # ASCII text payload landed inside name_buf.
        self.assertIn(b"No NSR topic", chunk)

    def test_chunk_tlv_carries_space_above_below(self):
        m = load_mvb(_MVB_PATH)
        chunk = build_mvb_first_paragraph_chunk(m, title_slot=1, key=0x1000)
        # Locate the TLV — sits at chunk_offset 0x2B (case_offset 0x2A
        # + 1-byte preamble type tag, then 2-byte length varint). Per
        # build_case1_bf_chunk: case_offset=0x2A, preamble=3B, TLV at
        # 0x2D.
        tlv_off = 0x2D
        fields, _consumed = decode_case1_tlv(chunk[tlv_off:])
        # space_above 24 → field +0x16, space_below 6 → field +0x18.
        self.assertEqual(fields[0x16], 24)
        self.assertEqual(fields[0x18], 6)
        # left_indent / right_indent / first_line_indent stay 0 (not
        # set in NO_NSR.MVB's first paragraph).
        self.assertEqual(fields[0x1C], 0)
        self.assertEqual(fields[0x1E], 0)
        self.assertEqual(fields[0x20], 0)


class TestLoadedMvbDataclass(unittest.TestCase):
    """Pin LoadedMVB construction so accidental field rename is caught."""

    def test_construct_with_minimal_args(self):
        m = LoadedMVB(
            title="t", caption="c", window_dims_permille=(0, 0, 1000, 1000),
            font_table=(), non_scroll=0xFFFFFFFF,
            first_paragraph=MvbParagraph(
                text="", left_indent_twips=0, right_indent_twips=0,
                first_line_indent_twips=0, space_above_twips=0,
                space_below_twips=0, font_idx=0,
            ),
        )
        self.assertEqual(m.caption, "c")


if __name__ == "__main__":
    unittest.main()
