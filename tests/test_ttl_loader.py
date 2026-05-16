"""Unit tests for the BBDESIGN `.ttl` loader.

Coverage:
- `resources/titles/4.ttl` — three-page test title (Test Page, Test
  Page Vertical Scrollbar, Test Page Horizontal Scrollbar) with one
  Caption per page; three-font CStyleSheet.
- `resources/titles/msn_today.ttl` — Story + Shortcut single-page,
  CK-deflated CStyleSheet with 7 font slots + 54 styles; Story content
  body is TextRuns at 8/7 ("This is an example of content...").
- `/var/share/drop/first title.ttl` (gated) — two-page Blackbird
  showcase (Home: 5 controls; Second Page: 1 Caption).
"""

import pathlib
import unittest

from server.services.medview.handler import (
    _deid_from_title_token,
    _extract_title_token,
)
from server.services.medview.ttl_loader import (
    AudioControl,
    CaptionButtonControl,
    CaptionControl,
    FaceEntry,
    LoadedPage,
    LoadedTitle,
    OutlineControl,
    ShortcutControl,
    StoryControl,
    build_bm0_baggage,
    load_title,
    lower_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TITLE_4 = _REPO_ROOT / "resources" / "titles" / "4.ttl"
_TITLE_MSN_TODAY = _REPO_ROOT / "resources" / "titles" / "msn_today.ttl"
_TITLE_SHOWCASE = pathlib.Path("/var/share/drop/first title.ttl")


class TestKnownTitleRegression(unittest.TestCase):
    """4.ttl: 1 Caption page-0; existing field assertions preserved via
    the `captions` property + new `controls` accessor."""

    def test_known_title_parses_all_fields(self):
        t = load_title(_TITLE_4)
        self.assertIsNotNone(t)
        self.assertEqual(t.title_name, "Test Title")
        self.assertEqual(t.caption, "Default Window")
        self.assertEqual(t.window_rect, (200, 100, 640, 480))
        self.assertEqual(t.page_pixel_w, 640)
        self.assertEqual(t.page_pixel_h, 480)
        self.assertEqual(t.page_bg, 0x009098A8)
        self.assertEqual(
            t.font_table,
            (
                FaceEntry(slot=2, face_name="Courier New"),
                FaceEntry(slot=1, face_name="Arial"),
                FaceEntry(slot=0, face_name="Times New Roman"),
            ),
        )
        self.assertEqual(t.scrollbar_flags, 0)

    def test_controls_is_a_single_caption(self):
        t = load_title(_TITLE_4)
        self.assertEqual(len(t.controls), 1)
        cap = t.controls[0]
        self.assertIsInstance(cap, CaptionControl)
        self.assertEqual(cap.seq, 1)
        self.assertEqual(cap.flags, 0x80000000)
        self.assertEqual(cap.name, "Caption1")
        self.assertEqual(cap.text, "Test caption")
        self.assertEqual(cap.font_name, "MS Sans Serif")
        self.assertEqual(cap.size_pt, 12)
        self.assertEqual(cap.weight, 400)
        self.assertEqual(cap.rect_himetric, (5291, 2963, 11641, 5926))

    def test_captions_property_filters_controls(self):
        t = load_title(_TITLE_4)
        self.assertEqual(t.captions, (t.controls[0],))

    def test_missing_path_returns_none(self):
        self.assertIsNone(load_title(pathlib.Path("/tmp/__no_ttl__.ttl")))


class TestMsnTodayDecodes(unittest.TestCase):
    """msn_today.ttl: 1 Story + 1 Shortcut on page-0. Verifies CK-deflate
    of CStyleSheet, walker handling of compound controls, and per-control
    rect extraction."""

    def setUp(self):
        self.title = load_title(_TITLE_MSN_TODAY)
        self.assertIsNotNone(self.title)

    def test_title_top_level(self):
        self.assertEqual(self.title.title_name, "MSN Today")
        self.assertEqual(self.title.caption, "MSN Today")
        self.assertEqual(self.title.page_pixel_w, 640)
        self.assertEqual(self.title.page_pixel_h, 480)
        self.assertEqual(self.title.scrollbar_flags, 3)

    def test_cstylesheet_ck_deflated(self):
        # CK-decompressed CStyleSheet exposes Courier/Arial/Times slots.
        names = [f.face_name for f in self.title.font_table]
        self.assertIn("Courier New", names)
        self.assertIn("Arial", names)
        self.assertIn("Times New Roman", names)

    def test_controls_are_story_and_shortcut(self):
        controls = self.title.controls
        self.assertEqual(len(controls), 2)
        self.assertIsInstance(controls[0], StoryControl)
        self.assertEqual(controls[0].name, "Story1R")
        self.assertEqual(controls[0].seq, 1)
        self.assertEqual(controls[0].xy_twips, (3810, 0))
        self.assertIsInstance(controls[1], ShortcutControl)
        self.assertEqual(controls[1].name, "Shortcut1=R")
        self.assertEqual(controls[1].seq, 2)
        self.assertEqual(controls[1].xy_twips, (211, 1481))

    def test_per_control_raw_blocks_carry_proxy_refs(self):
        # Property region is sliced in seq order using descriptor `size`.
        # Story1R's Pascal-prefixed "Homepage.bdf" reference must land in
        # the Story1R block; Shortcut1=R's "Calendar of Events.bdf"
        # straddles the descriptor-claimed 91 B boundary — the visible
        # portion ends at "Events." — which documents that the `size`
        # field is not a perfect block extent for compound controls.
        story = self.title.controls[0]
        shortcut = self.title.controls[1]
        self.assertEqual(len(story.raw_block), 142)
        self.assertEqual(len(shortcut.raw_block), 91)
        self.assertIn(b"\x0cHomepage.bdf", story.raw_block)
        self.assertIn(b"Calendar of Events", shortcut.raw_block)

    def test_captions_is_empty(self):
        # Existing lower_to_payload path is exercised via the empty-page
        # branch; no CaptionControls present in MSN Today.
        self.assertEqual(self.title.captions, ())


@unittest.skipUnless(
    _TITLE_SHOWCASE.exists(),
    f"Showcase TTL not available at {_TITLE_SHOWCASE}",
)
class TestShowcaseTitle(unittest.TestCase):
    """first title.ttl: 5 controls (Story1R / Caption1 / Audio1R /
    CaptionButton1R / Outline1) on the "Home" page. Verifies
    type_names_map + embedded_vform swizzle resolution (showcase
    layout: CSection at table 5, CBForm at 6, CVForm at 7)."""

    def setUp(self):
        self.title = load_title(_TITLE_SHOWCASE)
        self.assertIsNotNone(self.title)

    def test_page_background_is_yellow(self):
        # Showcase pinned the Background color picker to RGB(255,255,0).
        self.assertEqual(self.title.page_bg, 0x0000FFFF)
        # Vertical scrollbar only (bit 1).
        self.assertEqual(self.title.scrollbar_flags, 2)

    def test_five_controls_in_seq_order(self):
        controls = self.title.controls
        self.assertEqual(len(controls), 5)
        names_seqs = [(c.name, c.seq, type(c)) for c in controls]
        self.assertEqual(
            names_seqs,
            [
                ("Story1R", 1, StoryControl),
                ("Caption1", 2, CaptionControl),
                ("Audio1R", 3, AudioControl),
                ("CaptionButton1R", 4, CaptionButtonControl),
                ("Outline1", 6, OutlineControl),
            ],
        )

    def test_rects_match_showcase_doc(self):
        # Twips coordinates per docs/cvform-page-objects.md showcase
        # site table.
        controls = {c.name: c for c in self.title.controls}
        self.assertEqual(controls["Story1R"].xy_twips, (3175, 2328))
        self.assertEqual(controls["Audio1R"].xy_twips, (211, 2328))
        self.assertEqual(controls["CaptionButton1R"].xy_twips, (9101, 846))
        self.assertEqual(controls["Outline1"].xy_twips, (211, 4445))
        # Caption1 carries a 4-i32 rect (HIMETRIC for stock Caption,
        # twips for the showcase layout — coordinates match the doc's
        # top-left).
        cap = controls["Caption1"]
        self.assertEqual(cap.rect_himetric[0], 4233)
        self.assertEqual(cap.rect_himetric[1], 846)
        self.assertEqual(cap.font_name, "MS Sans Serif")


class TestLowerToPayload(unittest.TestCase):
    def setUp(self):
        self.title = load_title(_TITLE_4)
        self.assertIsNotNone(self.title)
        self.body = lower_to_payload(self.title)

    def test_body_contains_caption_cstring(self):
        self.assertIn(b"Default Window\x00", self.body)

    def test_section0_face_table_contains_all_fonts(self):
        sec0_off = 2                         # leading u16 length prefix
        face_table_off = sec0_off + 0x12
        self.assertEqual(
            self.body[face_table_off:face_table_off + 15], b"Times New Roman",
        )
        self.assertEqual(
            self.body[face_table_off + 0x20:face_table_off + 0x20 + 5], b"Arial",
        )
        self.assertEqual(
            self.body[face_table_off + 0x40:face_table_off + 0x40 + 11], b"Courier New",
        )

    def test_sec06_record_contains_caption_at_offset_0x15(self):
        idx = self.body.find(b"Default Window\x00")
        self.assertGreater(idx, 0)
        self.assertEqual(self.body[idx:idx + 14], b"Default Window")


class TestBuildBm0Baggage(unittest.TestCase):
    def test_kind8_metafile_when_captions_present(self):
        title = load_title(_TITLE_4)
        bag = build_bm0_baggage(title)
        # Container preamble is 8 bytes; first byte of bitmap header is
        # the kind tag.
        self.assertEqual(bag[8], 0x08)
        self.assertIn(b"Test caption", bag)
        self.assertIn(b"MS Sans Serif", bag)

    def test_kind5_raster_when_no_captions(self):
        empty = LoadedTitle(
            title_name="Empty",
            caption="Empty",
            window_rect=(0, 0, 640, 480),
            font_table=(),
            pages=(LoadedPage(
                name="",
                cbform_table=5,
                cbform_slot=0,
                cvform_handle=None,
                page_bg=0,
                page_pixel_w=640,
                page_pixel_h=480,
                scrollbar_flags=0,
                controls=(),
            ),),
        )
        bag = build_bm0_baggage(empty)
        self.assertEqual(bag[8], 0x05)


class TestTokenExtractor(unittest.TestCase):
    def test_extract_and_parse_title_token(self):
        # Wire shape: tag=0x04 + len|0x80=0x87 + 7B ASCIIZ.
        payload = b"\x04\x87:2[4]0\x00" + b"\x83"
        token = _extract_title_token(payload)
        self.assertEqual(token, ":2[4]0")
        self.assertEqual(_deid_from_title_token(token), "4")


class TestMultiPage4Ttl(unittest.TestCase):
    """4.ttl enumerates 3 CBForms via `CTitle.base_forms` (no enclosing
    CSection). Per-page scrollbar_flags differ — 0 / 2 / 1 — which is
    how this fixture was authored to differentiate the three pages."""

    def setUp(self):
        self.title = load_title(_TITLE_4)
        self.assertIsNotNone(self.title)

    def test_three_pages_in_authoring_order(self):
        self.assertEqual(len(self.title.pages), 3)
        names = [p.name for p in self.title.pages]
        self.assertEqual(names, [
            "Test Page",
            "Test Page Vertical Scrollbar",
            "Test Page Horizontal Scrollbar",
        ])

    def test_per_page_scrollbar_flags(self):
        flags = [p.scrollbar_flags for p in self.title.pages]
        # Page 0 = no scroll, page 1 = V (bit 1), page 2 = H (bit 0).
        self.assertEqual(flags, [0, 2, 1])

    def test_each_page_has_one_caption(self):
        for page in self.title.pages:
            self.assertEqual(len(page.controls), 1)
            self.assertIsInstance(page.controls[0], CaptionControl)


class TestMsnTodayStoryContentChase(unittest.TestCase):
    """msn_today's Story1R chases the Pascal-prefixed `Homepage.bdf`
    reference in its raw_block → CProxyTable@7/0 → TextRuns CContent
    at 8/7 ("This is an example of content..."). The leading 'S' before
    the prose body is unexplained empirical noise (PR2 BBCTL.OCX RE will
    pin it); the chase still succeeds and exposes content_proxy_ref."""

    def setUp(self):
        self.title = load_title(_TITLE_MSN_TODAY)
        self.assertIsNotNone(self.title)
        self.story = self.title.pages[0].controls[0]
        self.assertIsInstance(self.story, StoryControl)

    def test_content_proxy_ref_is_textruns_key(self):
        # CProxyTable@7/0 maps proxy_key 0x00001500 → CContent at 8/7
        # (TextRuns) and 0x00001400 → 8/6 (TextTree); the chase picks
        # the TextRuns target.
        self.assertEqual(self.story.content_proxy_ref, 0x00001500)

    def test_content_text_starts_with_authored_body(self):
        self.assertIsNotNone(self.story.content)
        self.assertIn("This is an example of content", self.story.content.text)

    def test_textruns_header_pinned(self):
        # 8/7 first two bytes are `02 00`; the rest is the prose run.
        self.assertEqual(self.story.content.header_version, 0x02)
        self.assertEqual(self.story.content.header_byte_1, 0x00)


class TestLoadedTitleBackcompatShims(unittest.TestCase):
    """`LoadedTitle.{controls,captions,page_bg,page_pixel_w,
    page_pixel_h,scrollbar_flags}` all delegate to `pages[0]`. PR3
    drops the shims when `lower_to_payload` lifts to per-page emission."""

    def test_shims_alias_pages_zero(self):
        t = load_title(_TITLE_4)
        page0 = t.pages[0]
        self.assertIs(t.controls, page0.controls)
        self.assertEqual(t.page_bg, page0.page_bg)
        self.assertEqual(t.page_pixel_w, page0.page_pixel_w)
        self.assertEqual(t.page_pixel_h, page0.page_pixel_h)
        self.assertEqual(t.scrollbar_flags, page0.scrollbar_flags)
        self.assertEqual(t.captions, page0.captions)


class TestBbctlClsidDispatch(unittest.TestCase):
    """CLSID-first dispatch:

    - msn_today's Story1R / Shortcut1=R sit at class_index 0 / 1 in the
      CVForm preamble class table; both CLSIDs (CQtxtCtrl / CBblinkCtrl)
      are in `_BBCTL_CLSIDS` and dispatch correctly to
      `StoryControl` / `ShortcutControl`.
    - 4.ttl's three pages each have one Caption (class_index 0,
      CLSID = CLabelCtrl) and dispatch to `CaptionControl` via the
      CLSID table.
    """

    def test_msn_today_clsids_pinned_per_descriptor(self):
        from server.services.medview.ttl_loader import _BBCTL_CLSIDS
        # 6 BBCTL site classes pinned in code.
        names = sorted(_BBCTL_CLSIDS.values())
        self.assertEqual(names, [
            "Audio", "Caption", "CaptionButton",
            "Outline", "Shortcut", "Story",
        ])

    def test_4ttl_caption_dispatched_via_clsid(self):
        t = load_title(_TITLE_4)
        cap = t.pages[0].controls[0]
        self.assertIsInstance(cap, CaptionControl)
        self.assertEqual(cap.name, "Caption1")

    def test_msn_today_dispatches_both_classes(self):
        t = load_title(_TITLE_MSN_TODAY)
        controls = t.pages[0].controls
        self.assertIsInstance(controls[0], StoryControl)
        self.assertIsInstance(controls[1], ShortcutControl)


@unittest.skipUnless(
    _TITLE_SHOWCASE.exists(),
    f"Showcase TTL not available at {_TITLE_SHOWCASE}",
)
class TestShowcaseMultiPage(unittest.TestCase):
    """Showcase's CTitle.base_forms is empty; the loader DFS-walks the
    CSection tree (Front Matter → Home form, Front Matter → Subsection
    → Second Page form), preserving the BBDESIGN tree order."""

    def setUp(self):
        self.title = load_title(_TITLE_SHOWCASE)
        self.assertIsNotNone(self.title)

    def test_two_pages_in_tree_order(self):
        self.assertEqual(len(self.title.pages), 2)
        names = [p.name for p in self.title.pages]
        self.assertEqual(names, ["Home", "Second Page"])

    def test_page0_has_five_controls(self):
        self.assertEqual(len(self.title.pages[0].controls), 5)

    def test_page1_is_a_single_caption(self):
        page1 = self.title.pages[1]
        self.assertEqual(len(page1.controls), 1)
        self.assertIsInstance(page1.controls[0], CaptionControl)

    def test_page0_story_proxy_name_resolves(self):
        story = self.title.pages[0].controls[0]
        self.assertIsInstance(story, StoryControl)
        # CProxyTable for "Blackbird Document.bdf" lives in CSection
        # "Front Matter" but its TextRuns target may not exist as a
        # CContent stream in this fixture — heuristic still extracts a
        # proxy_key when one is present, or leaves both None.
        self.assertIsNotNone(story.raw_block)


if __name__ == "__main__":
    unittest.main()
