"""Unit tests for VIEWDLL's built-in style table (`bbstyles`).

The table is the fallback every `.ttl` that overrides no style leans
on. `tests/assets/story_title.ttl` is such a title, and its BBVIEW
render (`reference/screenshots/story title.png`) is what the resolved
values below reproduce: Arial Bold 22 pt heading, Arial Bold 18 pt
sub-heading, Times New Roman 11 pt body, bulleted lists at a quarter
inch.
"""

import unittest

from server.services.medview import bbstyles


class TestTableShape(unittest.TestCase):

    def test_index_space_is_the_full_fifty_four_names(self):
        # 47 records at VA 0x40770e00 + 7 intrusion names at
        # 0x407717c0 — the span CStyle::FindNameIndex walks.
        self.assertEqual(len(bbstyles.BUILTIN_STYLES), 54)
        self.assertEqual(bbstyles.BUILTIN_STYLES[0].name, "Normal")
        self.assertEqual(bbstyles.BUILTIN_STYLES[46].name, "Sample")
        self.assertEqual(bbstyles.BUILTIN_STYLES[53].name, "Wrap: Custom 2")

    def test_indices_match_positions(self):
        for i, style in enumerate(bbstyles.BUILTIN_STYLES):
            self.assertEqual(style.index, i)

    def test_normal_is_the_only_chain_root(self):
        roots = [s.name for s in bbstyles.BUILTIN_STYLES if s.based_on < 0]
        self.assertEqual(roots, ["Normal"])


class TestResolution(unittest.TestCase):

    def resolve(self, name):
        return bbstyles.resolve(bbstyles.STYLE_BY_NAME[name])

    def test_normal_is_times_eleven_point(self):
        s = self.resolve("Normal")
        self.assertEqual((s.font_face, s.pt_size), ("Times New Roman", 11))
        self.assertFalse(s.bold)
        self.assertEqual(s.fore_color, 0x000000)
        self.assertEqual(s.back_color, 0xFFFFFF)
        self.assertEqual((s.space_before, s.space_after), (0, 11))

    def test_heading_1_overrides_face_size_and_bold(self):
        s = self.resolve("Heading 1")
        self.assertEqual((s.font_face, s.pt_size), ("Arial", 22))
        self.assertTrue(s.bold)
        self.assertEqual((s.space_before, s.space_after), (18, 0))

    def test_heading_2_inherits_bold_and_face_from_heading_1(self):
        # Its own attribute word is 0x7F00 — every mask bit set, so it
        # defines nothing and the chain supplies bold + Arial.
        self.assertEqual(bbstyles.STYLE_BY_NAME["Heading 2"].char_attrs, 0x7F00)
        s = self.resolve("Heading 2")
        self.assertEqual((s.font_face, s.pt_size), ("Arial", 18))
        self.assertTrue(s.bold)
        self.assertEqual((s.space_before, s.space_after), (14, 0))

    def test_deep_headings_inherit_size_down_the_chain(self):
        self.assertEqual(self.resolve("Heading 4").pt_size, 12)
        # Headings 5 and 6 set no size of their own.
        self.assertEqual(self.resolve("Heading 5").pt_size, 12)
        self.assertEqual(self.resolve("Heading 6").pt_size, 12)

    def test_both_list_styles_bullet_and_hang_a_quarter_inch(self):
        for name in ("List Bullet", "List Number"):
            s = self.resolve(name)
            self.assertTrue(s.bullet, name)
            self.assertEqual(s.left_indent, 18, name)
            self.assertEqual(s.indent_by, 18, name)
            self.assertEqual(
                s.special_line_indent, bbstyles.SPECIAL_INDENT_HANGING, name,
            )
            # Body text, inherited from Normal.
            self.assertEqual((s.font_face, s.pt_size), ("Times New Roman", 11))
            self.assertEqual(s.space_after, 11)

    def test_character_attribute_bits(self):
        self.assertTrue(self.resolve("Bold").bold)
        self.assertTrue(self.resolve("Italic").italic)
        self.assertTrue(self.resolve("Underline").underline)
        self.assertFalse(self.resolve("Italic").bold)
        keyboard = self.resolve("Keyboard")
        self.assertTrue(keyboard.bold)
        self.assertTrue(keyboard.italic)

    def test_monospace_styles_take_font_three(self):
        for name in ("Preformatted", "Code", "Fixed Width"):
            self.assertEqual(self.resolve(name).font_face, "Courier New", name)

    def test_hyperlink_is_blue_and_underlined(self):
        s = self.resolve("Hyperlink")
        self.assertTrue(s.underline)
        self.assertEqual(s.fore_color, 0xFF0000)   # COLORREF 0x00BBGGRR

    def test_toc_levels_step_eighteen_points(self):
        got = [self.resolve(f"TOC {n}").left_indent for n in range(1, 10)]
        self.assertEqual(got, [18, 36, 54, 72, 90, 108, 126, 144, 162])

    def test_font_map_overrides_the_builtin_faces(self):
        s = bbstyles.resolve(
            bbstyles.STYLE_BY_NAME["Heading 1"], {2: "Verdana"},
        )
        self.assertEqual(s.font_face, "Verdana")


class TestElementMapping(unittest.TestCase):

    def test_known_paragraph_tags(self):
        self.assertEqual(
            bbstyles.style_for_element(bbstyles.TAG_PARAGRAPH).name, "Normal",
        )
        self.assertEqual(
            bbstyles.style_for_element(bbstyles.TAG_HEADING_1).name, "Heading 1",
        )
        self.assertEqual(
            bbstyles.style_for_element(bbstyles.TAG_HEADING_2).name, "Heading 2",
        )

    def test_list_item_style_comes_from_the_enclosing_list(self):
        self.assertEqual(
            bbstyles.style_for_element(
                bbstyles.TAG_LIST_ITEM, bbstyles.TAG_UNORDERED_LIST,
            ).name,
            "List Bullet",
        )
        self.assertEqual(
            bbstyles.style_for_element(
                bbstyles.TAG_LIST_ITEM, bbstyles.TAG_ORDERED_LIST,
            ).name,
            "List Number",
        )

    def test_unmapped_tag_falls_back_to_normal(self):
        self.assertEqual(bbstyles.style_for_element(0x7FFF).name, "Normal")
        # A list item outside any list, too.
        self.assertEqual(
            bbstyles.style_for_element(bbstyles.TAG_LIST_ITEM).name, "Normal",
        )


if __name__ == "__main__":
    unittest.main()
