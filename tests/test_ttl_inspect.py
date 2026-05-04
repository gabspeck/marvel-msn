"""Tests for the Blackbird .ttl inspector — focused on the CStyleSheet
style-record parse RE'd from VIEWDLL.DLL `?Serialize@CStyle@@…` and
peers (`docs/blackbird-title-format.md` §"CStyle/CParaProps/CCharProps"
+ `docs/mosview-authored-text-and-font-re.md` §"Section-0 Header
Schema").
"""

from __future__ import annotations

import unittest
from pathlib import Path

from server.blackbird.ttl_inspect import (
    CSTYLE_DEFAULT_PROPS,
    CSTYLE_NAME_DICTIONARY,
    decode_handle,
    encode_handle,
    inspect_blackbird_title,
    parse_cstylesheet,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TTL = REPO_ROOT / "resources" / "titles" / "4.ttl"


class CStyleSheetParseTests(unittest.TestCase):
    """Pin the on-disk CStyleSheet grammar against the reference TTL.

    `resources/titles/4.ttl` is `MSN Today` (sha256 4a6e884f…) — the
    only TTL the synthesizer fully supports today. CStyleSheet has 7
    fonts (keys 0–6, including one empty entry) and 54 styles."""

    @classmethod
    def setUpClass(cls):
        inspection = inspect_blackbird_title(SAMPLE_TTL)
        cls.stylesheet = next(
            o for o in inspection["object_streams"]
            if o["class_name"] == "CStyleSheet"
        )
        cls.parsed = cls.stylesheet["parsed"]

    def test_parser_consumes_full_payload(self):
        # `parse_cstylesheet` raises on trailing bytes — re-running it
        # directly proves there's nothing left after the style map.
        result = parse_cstylesheet(self.stylesheet["payload"])
        self.assertEqual(len(result["styles"]), result["style_count"])
        self.assertEqual(result["style_count"], 54)
        self.assertEqual(result["linked_stylesheet_present"], 0)
        self.assertIsNone(result["linked_stylesheet_swizzle"])

    def test_styles_have_expected_count_and_dense_ids(self):
        styles = self.parsed["styles"]
        self.assertEqual(len(styles), 54)
        self.assertEqual([s["style_id"] for s in styles], list(range(54)))

    def test_name_index_matches_style_id(self):
        # In this TTL the packed selector's high-6-bit `name_index`
        # always equals the style_id — ensures the bit-shift decode is
        # right (selector >> 2).
        for s in self.parsed["styles"]:
            self.assertEqual(s["name_index"], s["style_id"])

    def test_root_style_has_no_based_on(self):
        root = self.parsed["styles"][0]
        self.assertFalse(root["is_intrusion"])
        self.assertIsNone(root["based_on"])  # 0xff sentinel decoded to None
        self.assertIsNotNone(root["para_props"])
        self.assertIsNotNone(root["char_props"])

    def test_inheritance_chain_walks_back_to_root(self):
        # Walk each non-intrusion style's based_on chain to make sure
        # it terminates at the root and doesn't loop.
        styles_by_id = {s["style_id"]: s for s in self.parsed["styles"]}
        for s in self.parsed["styles"]:
            if s["is_intrusion"]:
                continue
            seen = set()
            cursor = s
            while cursor["based_on"] is not None:
                self.assertNotIn(cursor["style_id"], seen,
                                 f"based_on cycle through sid {cursor['style_id']}")
                seen.add(cursor["style_id"])
                cursor = styles_by_id[cursor["based_on"]]
            self.assertIsNone(cursor["based_on"])

    def test_intrusion_styles_match_wrap_dictionary_entries(self):
        # The 7 "Wrap: …" entries in CSTYLE_NAME_DICTIONARY (indices
        # 0x2f..0x35) are the intrusion styles — VIEWDLL exposes
        # `CStyle::GetIntrusion` reading the secondary byte from this
        # offset. In the reference TTL these are exactly sid 47..53.
        intrusion_styles = [s for s in self.parsed["styles"] if s["is_intrusion"]]
        self.assertEqual([s["style_id"] for s in intrusion_styles], list(range(47, 54)))
        for s in intrusion_styles:
            self.assertEqual(s["intrusion_index"], 0)
            self.assertIsNone(s["para_props"])
            self.assertIsNone(s["char_props"])
            self.assertTrue(s["name"].startswith("Wrap:"),
                            f"intrusion sid {s['style_id']} resolves to {s['name']!r}")

    def test_intrusion_index_within_published_range(self):
        # BBDESIGN validator "Intrusion argument is invalid. Valid
        # values are 0 to 8." pins the on-disk range. Any future TTL
        # we add must respect this so the engine's GetIntrusion
        # consumer doesn't reject the style.
        for s in self.parsed["styles"]:
            if not s["is_intrusion"]:
                continue
            self.assertIsNotNone(s["intrusion_index"])
            self.assertGreaterEqual(s["intrusion_index"], 0)
            self.assertLessEqual(s["intrusion_index"], 8,
                                 f"sid {s['style_id']} intrusion_index "
                                 f"{s['intrusion_index']} > 8 (BBDESIGN max)")

    def test_style_1_has_authored_text_color(self):
        # Style 1's CCharProps is the only one with an explicit color
        # in this TTL — the masks decode to bit-3-set, yielding
        # text_color = 0x80 = 128 (RGB(128,0,0) dark red, COLORREF LE).
        s1 = self.parsed["styles"][1]
        self.assertEqual(s1["char_props"]["fields"].get("text_color"), 128)

    def test_styles_7_through_15_carry_tab_stops_increasing_by_18(self):
        # The first tab-bearing run (style ids 7–15) places one tab per
        # style at positions 18, 36, 54, … — confirms CParaProps tab
        # bit (mask_explicit bit 12) and per-tab encoding (u16 pos +
        # u8 type) parse correctly.
        for offset, s in enumerate(self.parsed["styles"][7:16]):
            tabs = s["para_props"]["tabs"]
            self.assertEqual(len(tabs), 1)
            self.assertEqual(tabs[0]["position"], 18 * (offset + 1))
            self.assertEqual(tabs[0]["type"], 0)

    def test_font_ids_resolve_against_font_table(self):
        # No style in this TTL ships an explicit font_id (CCharProps
        # mask bit 1 is clear everywhere — every style inherits its
        # font from the parent or stylesheet default). The check
        # nonetheless pins the invariant the wire-side lowering will
        # rely on: any explicit `font_id` must match a `fonts[].key`.
        font_keys = {f["key"] for f in self.parsed["fonts"]}
        for s in self.parsed["styles"]:
            char_props = s["char_props"]
            if char_props is None:
                continue
            font_id = char_props["fields"].get("font_id")
            if font_id is None:
                continue
            self.assertIn(font_id, font_keys,
                          f"sid {s['style_id']} font_id {font_id} not in font table")

    def test_size_distribution_matches_phase_a_buckets(self):
        # Phase A enumeration found 5 distinct record byte-widths. Pin
        # the expected counts so future TTLs that change the mix get
        # caught early.
        # Sizes after stripping (style_id u16 + class tag): 3 bytes
        # (intrusion), 6 bytes (char-props-only), 11 bytes (small
        # CParaProps + minimal CCharProps), 16 bytes (CParaProps + tab
        # list + minimal CCharProps), and the special wrapper-prefixed
        # record 0.
        styles = self.parsed["styles"]
        intrusion_count = sum(1 for s in styles if s["is_intrusion"])
        char_only_count = sum(1 for s in styles if s["char_props_only"]
                              and not s["is_intrusion"])
        with_tabs_count = sum(1 for s in styles
                              if s["para_props"]
                              and s["para_props"]["tabs"])
        self.assertEqual(intrusion_count, 7)   # sids 47–53
        self.assertEqual(char_only_count, 14)  # 6-byte records
        self.assertEqual(with_tabs_count, 18)  # sids 7–24

    def test_name_index_resolves_to_dictionary_entry(self):
        # `name_index` looks up the predefined 54-entry dictionary
        # from VIEWDLL.DLL (CSTYLE_NAME_DICTIONARY). The reference TTL
        # uses dense ids 0..53 so each `name` round-trips against the
        # dictionary entry of the same index.
        for s in self.parsed["styles"]:
            self.assertEqual(s["name"], CSTYLE_NAME_DICTIONARY[s["name_index"]])

    def test_dictionary_pin_known_entries(self):
        # Lock the dictionary to the names recovered from VIEWDLL —
        # any future regression that mis-derives the table fails here.
        self.assertEqual(CSTYLE_NAME_DICTIONARY[0], "Normal")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[1], "Heading 1")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[16], "Section 1")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[30], "Hyperlink")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[34], "Strikethrough")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[47], "Wrap: Design feature")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[53], "Wrap: Custom 2")
        self.assertEqual(len(CSTYLE_NAME_DICTIONARY), 54)

    def test_default_props_pin_known_entries(self):
        # Lock the per-style defaults baked into VIEWDLL @ 0x40770e00.
        # Spot-checks across the table — full pin is the verbatim
        # literal in CSTYLE_DEFAULT_PROPS.
        normal = CSTYLE_DEFAULT_PROPS[0]
        self.assertEqual(normal["based_on"], 0xffff)  # root style
        self.assertEqual(normal["flags_word"], 0x0000)
        self.assertEqual(normal["font_id"], 1)
        self.assertEqual(normal["pt_size"], 11)

        h1 = CSTYLE_DEFAULT_PROPS[1]
        self.assertEqual(h1["based_on"], 0)  # inherits from Normal
        self.assertEqual(h1["flags_word"], 0x7e02)  # bold ON, others absent
        self.assertEqual(h1["font_id"], 2)  # Arial
        self.assertEqual(h1["pt_size"], 22)
        self.assertEqual(h1["space_before"], 18)

        # Hyperlink, Strikethrough, Underline all share the same
        # CCharProps payload (underline ON / 0x7b08). Hyperlink adds
        # a blue text_color; the strike effect is name-special-cased
        # in the renderer, not encoded as a flag bit.
        hyperlink = CSTYLE_DEFAULT_PROPS[30]
        underline = CSTYLE_DEFAULT_PROPS[38]
        strike = CSTYLE_DEFAULT_PROPS[34]
        self.assertEqual(hyperlink["flags_word"], 0x7b08)
        self.assertEqual(underline["flags_word"], 0x7b08)
        self.assertEqual(strike["flags_word"], 0x7b08)
        self.assertEqual(hyperlink["text_color"], 0x00ff0000)  # COLORREF blue
        self.assertEqual(strike["text_color"], 0xffffffff)  # no_change
        self.assertEqual(underline["text_color"], 0xffffffff)

        # All three "char-props-only" style classes
        # (char_props_only=1) — engine constructs CStyle without a
        # CParaProps in defaults.
        self.assertEqual(hyperlink["char_props_only"], 1)
        self.assertEqual(strike["char_props_only"], 1)

        # TOC indents grow by 18 per level (TOC 1 at 18, TOC 2 at 36,
        # …, TOC 9 at 162).
        for n in range(9):
            self.assertEqual(
                CSTYLE_DEFAULT_PROPS[7 + n]["left_indent"], 18 * (n + 1))

        # Preformatted/Code/Fixed Width pin font_id=3 (Courier in
        # standard TTL conventions).
        self.assertEqual(CSTYLE_DEFAULT_PROPS[35]["font_id"], 3)
        self.assertEqual(CSTYLE_DEFAULT_PROPS[40]["font_id"], 3)
        self.assertEqual(CSTYLE_DEFAULT_PROPS[44]["font_id"], 3)

        # Abstract Heading is the only style that pins justify=2
        # (centered) in defaults — confirms `justify` byte is a
        # MFC-style enum (0=left, 1=right, 2=center, ...).
        self.assertEqual(CSTYLE_DEFAULT_PROPS[25]["justify"], 2)

        self.assertEqual(len(CSTYLE_DEFAULT_PROPS), 47)


class HandleEncodingTests(unittest.TestCase):
    """Pin the CDPO object-handle bit format.

    Verified against every handle in `resources/titles/4.ttl` and
    in `/var/share/drop/first title.ttl` — 36/36 round-trip cleanly.
    """

    def test_encode_decode_roundtrip(self):
        for tid in (0, 1, 4, 10, 0x1f, 0x3ff):
            for slot in (0, 1, 7, 0x100, 0x1FFFFF):
                self.assertEqual(decode_handle(encode_handle(tid, slot)),
                                 (tid, slot))

    def test_known_pins(self):
        # Pinned values from `resources/titles/4.ttl` and the older
        # Blackbird sample.
        # CTitle slot 0 = first instance of CTitle in this TTL.
        # In 4.ttl CTitle's table_id is 2 → handle 0x00400000.
        self.assertEqual(encode_handle(2, 0), 0x00400000)
        # The "first title.ttl" 4/1 linked-stylesheet swizzle pin:
        # tid=4 (CStyleSheet) slot=0 → 0x00800000 → 4/0 (the base).
        self.assertEqual(encode_handle(4, 0), 0x00800000)
        # CContent slot 7 → 0x01400007 (the Canyon.mid in the sample).
        self.assertEqual(encode_handle(10, 7), 0x01400007)

    def test_slot_field_caps_at_21_bits(self):
        # Slot exceeding 21 bits must reject. The format leaves 11
        # bits for table_id (which matches the observed maximum
        # level_specifier `0xa = 10` in TTLs surveyed).
        with self.assertRaises(ValueError):
            encode_handle(1, 1 << 21)


class FirstTitleSampleTests(unittest.TestCase):
    """End-to-end smoke test for `/var/share/drop/first title.ttl`.

    Older Blackbird title that ships without `\\x03TitleProps`, uses
    HEX storage names (`a/1`, `a/7`), and has TWO stylesheets with
    the section-local one linking to the title-level one. Skipped
    if the sample isn't present on the filesystem.
    """

    SAMPLE_PATH = Path("/var/share/drop/first title.ttl")

    @classmethod
    def setUpClass(cls):
        if not cls.SAMPLE_PATH.is_file():
            raise unittest.SkipTest(f"sample not present at {cls.SAMPLE_PATH}")
        cls.r = inspect_blackbird_title(cls.SAMPLE_PATH)

    def test_class_inventory(self):
        counts = {}
        for o in self.r['object_streams']:
            counts[o['class_name']] = counts.get(o['class_name'], 0) + 1
        # CMagnet, AudioProxy via CProxyTable, two CStyleSheets,
        # nested sections — features absent from the Marvel reference.
        self.assertEqual(counts['CTitle'], 1)
        self.assertEqual(counts['CSection'], 2)
        self.assertEqual(counts['CStyleSheet'], 2)
        self.assertEqual(counts['CMagnet'], 1)
        self.assertEqual(counts['CContent'], 4)
        self.assertEqual(counts['CProxyTable'], 3)

    def test_linked_stylesheet_swizzle_resolves_to_base(self):
        # Section-local `4/1` with linked_stylesheet_present=1 should
        # have its swizzle resolve via its own handle table to `4/0`.
        roots = {o['object_root']: o for o in self.r['object_streams']}
        local = roots['4/1']
        self.assertEqual(local['parsed']['linked_stylesheet_present'], 1)
        self.assertEqual(local['parsed']['linked_stylesheet_swizzle'], 0)
        target_handle = local['handles'][0]
        tid, slot = decode_handle(target_handle)
        self.assertEqual(self.r['table_names'][tid], 'CStyleSheet')
        self.assertEqual(slot, 0)
        # The linked-to base really is 4/0 — empty styles, more
        # constrained font list (no Garamond).
        base = roots[f"{tid:x}/{slot:x}"]
        self.assertEqual(base['object_root'], '4/0')
        self.assertEqual(base['parsed']['style_count'], 0)
        self.assertEqual(base['parsed']['linked_stylesheet_present'], 0)

    def test_section_local_stylesheet_overrides_heading_1(self):
        # 4/1 customizes Heading 1 with Garamond 26pt (font key 4 in
        # 4/1's font map, NOT in 4/0's).
        roots = {o['object_root']: o for o in self.r['object_streams']}
        local = roots['4/1']
        h1 = next(s for s in local['parsed']['styles'] if s['name'] == 'Heading 1')
        self.assertEqual(h1['char_props']['fields']['font_id'], 4)
        self.assertEqual(h1['char_props']['fields']['pt_size'], 26)
        # Garamond is the new font this stylesheet adds.
        local_fonts = {f['key']: f['name'] for f in local['parsed']['fonts']}
        self.assertEqual(local_fonts[4], 'Garamond')

    def test_all_handles_decode_to_existing_storage(self):
        roots = {o['object_root'] for o in self.r['object_streams']}
        for o in self.r['object_streams']:
            for h in o['handles']:
                tid, slot = decode_handle(h)
                self.assertIn(f"{tid:x}/{slot:x}", roots,
                              f"handle 0x{h:08x} from {o['object_root']} "
                              f"does not resolve to a stored object")


if __name__ == "__main__":
    unittest.main()
