"""Tests for `src.server.blackbird.drawtext` — the GDI DrawText word-wrap
port. Uses a synthetic fixed-width measurer (every char = 10px) so the
break decisions are pinned independently of any font.

Behavior pinned against `private/ntos/w32/ntuser/rtl/drawtext.c`
(DT_GetLineBreak / GetNextWordbreak / DT_AdjustWhiteSpaces).
"""

import unittest

from src.server.blackbird import drawtext


def _w10(s: str) -> int:
    """Synthetic extent: 10px per character."""
    return len(s) * 10


_LEFT = drawtext.DT_WORDBREAK | drawtext.DT_NOPREFIX | drawtext.DT_LEFT
_RIGHT = drawtext.DT_WORDBREAK | drawtext.DT_NOPREFIX | drawtext.DT_RIGHT
_CENTER = drawtext.DT_WORDBREAK | drawtext.DT_NOPREFIX | drawtext.DT_CENTER


class TestWrapText(unittest.TestCase):
    def test_fits_on_one_line(self):
        self.assertEqual(
            drawtext.wrap_text("aaa bbb", _LEFT, _w10, 200),
            ["aaa bbb"],
        )

    def test_greedy_break_between_words(self):
        # "aaa bbb ccc": "aaa bbb" = 70 > 60 → break before "bbb".
        # DT_LEFT keeps the trailing space on the line it ends.
        self.assertEqual(
            drawtext.wrap_text("aaa bbb ccc", _LEFT, _w10, 60),
            ["aaa ", "bbb ", "ccc"],
        )

    def test_right_align_trims_trailing_space(self):
        # DT_RIGHT drops the trailing space from the line it ends.
        self.assertEqual(
            drawtext.wrap_text("aaa bbb ccc", _RIGHT, _w10, 60),
            ["aaa", "bbb", "ccc"],
        )

    def test_center_align_trims_both_sides(self):
        self.assertEqual(
            drawtext.wrap_text("aaa bbb ccc", _CENTER, _w10, 60),
            ["aaa", "bbb", "ccc"],
        )

    def test_single_overlong_word_stays_on_its_own_line(self):
        # A plain label (no DT_EDITCONTROL) never splits inside a word;
        # the over-long word overflows on its own line.
        self.assertEqual(
            drawtext.wrap_text("Hi xxxxx yo", _LEFT, _w10, 25),
            ["Hi", "xxxxx", "yo"],
        )

    def test_explicit_linebreak_crlf(self):
        self.assertEqual(
            drawtext.wrap_text("aaa\r\nbbb", _LEFT, _w10, 1000),
            ["aaa", "bbb"],
        )

    def test_lone_lf_breaks(self):
        self.assertEqual(
            drawtext.wrap_text("aaa\nbbb", _LEFT, _w10, 1000),
            ["aaa", "bbb"],
        )

    def test_no_wordbreak_flag_only_splits_on_crlf(self):
        fmt = drawtext.DT_NOPREFIX | drawtext.DT_LEFT  # no DT_WORDBREAK
        self.assertEqual(
            drawtext.wrap_text("aaa bbb ccc ddd", fmt, _w10, 50),
            ["aaa bbb ccc ddd"],
        )

    def test_every_wrapped_line_fits_except_overlong_words(self):
        text = "the quick brown fox jumps over the lazy dog"
        width = 80
        for line in drawtext.wrap_text(text, _RIGHT, _w10, width):
            words = line.split()
            if len(words) > 1:
                self.assertLessEqual(_w10(line), width, f"line too wide: {line!r}")

    def test_empty_string(self):
        self.assertEqual(drawtext.wrap_text("", _LEFT, _w10, 100), [])


class TestGetNextWordbreak(unittest.TestCase):
    def test_breaks_after_word_at_space(self):
        # "ab cd": from 0, stops AT the space (index 2).
        self.assertEqual(drawtext.get_next_wordbreak("ab cd", 0, 5, True), 2)

    def test_leading_space_advances_one(self):
        # Starting on the space, advance one past it (index 3).
        self.assertEqual(drawtext.get_next_wordbreak("ab cd", 2, 5, True), 3)

    def test_stops_at_cr(self):
        self.assertEqual(drawtext.get_next_wordbreak("ab\r", 0, 3, True), 2)


if __name__ == "__main__":
    unittest.main()
