"""Tests for `src.server.blackbird.irindex` — the text index BBIRService searches.

Matching runs over synthetic documents; the extraction path that turns a
published `CContent` object into one is covered against the store separately.
"""

import unittest

from server.blackbird.irindex import Document, search


def _doc(path, text, title="title"):
    return Document(guid=b"\0" * 16, storage_path=path, title=title, text=text)


class TestSearch(unittest.TestCase):
    _DOCS = [
        _doc("8/0", "Blackbird title\nStory text yadda yadda yadda"),
        _doc("8/1", "Another story about birds"),
        _doc("8/2", "Nothing relevant here"),
    ]

    def test_single_term(self):
        self.assertEqual([d.storage_path for _s, d in search(["yadda"], self._DOCS)], ["8/0"])

    def test_terms_are_anded(self):
        # "story" is in both documents, "yadda" in only one.
        self.assertEqual(
            [d.storage_path for _s, d in search(["story", "yadda"], self._DOCS)], ["8/0"]
        )

    def test_case_insensitive(self):
        self.assertEqual([d.storage_path for _s, d in search(["BLACKBIRD"], self._DOCS)], ["8/0"])

    def test_ranked_by_occurrence_count(self):
        hits = search(["story"], self._DOCS)
        self.assertEqual([d.storage_path for _s, d in hits], ["8/0", "8/1"])
        self.assertEqual([s for s, _d in hits], [1, 1])

    def test_score_sums_every_term(self):
        # "yadda" appears three times, "story" once.
        self.assertEqual(search(["yadda", "story"], self._DOCS)[0][0], 4)

    def test_no_match(self):
        self.assertEqual(search(["absent"], self._DOCS), [])

    def test_empty_terms_match_nothing(self):
        # An all-empty term list would otherwise match every document.
        self.assertEqual(search([], self._DOCS), [])
        self.assertEqual(search([""], self._DOCS), [])

    def test_limit(self):
        self.assertEqual(len(search(["a"], self._DOCS, limit=1)), 1)


class TestDocumentFields(unittest.TestCase):
    def test_heading_is_the_first_non_empty_line(self):
        self.assertEqual(_doc("1/0", "\n\nFirst\nSecond").heading, "First")

    def test_heading_falls_back_to_the_storage_path(self):
        self.assertEqual(_doc("3/1", "   \n  ").heading, "3/1")

    def test_snippet_collapses_whitespace(self):
        self.assertEqual(_doc("1/0", "a\n b  c\n").snippet, "a b c")

    def test_snippet_is_bounded(self):
        self.assertEqual(len(_doc("1/0", "x " * 200).snippet), 120)


if __name__ == "__main__":
    unittest.main()
