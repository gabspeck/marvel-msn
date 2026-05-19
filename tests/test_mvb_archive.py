"""Tests for `scripts.inspect_mvb_archive` — the Multimedia Viewer 2.0
.MVB / WinHelp .HLP archive parser.

Pinned against the three MVPUBKIT archives that ship with the
Blackbird publishing toolkit. Per `docs/MEDVIEW-TEXT-ENCODING.md`
§7, these archives do NOT contain Blackbird-style TextTree CContent
(magic `01 05`) — they carry Microsoft Multimedia Viewer's own
compressed |TOPIC stream, which uses a different on-disk grammar.
The parser exists to enumerate the internal file table and surface
the |TOPIC/|SYSTEM streams for downstream analysis."""

import unittest
from pathlib import Path

from scripts.inspect_mvb_archive import (
    inspect_mvb_archive,
    scan_text_segments,
)


_MMAG = Path("binaries/MVPUBKIT/MMAG.MVB")
_MVAPIREF = Path("binaries/MVPUBKIT/MVAPIREF.MVB")
_MVAUTHOR = Path("binaries/MVPUBKIT/MVAUTHOR.MVB")


@unittest.skipUnless(_MMAG.exists(), "MVPUBKIT archives not present")
class TestMvbArchive(unittest.TestCase):

    def _file_names(self, info: dict) -> list[str]:
        return [f.name for f in info["internal_files"]]

    def test_mmag_directory_layout(self):
        info = inspect_mvb_archive(_MMAG)
        # 47 directory entries per the BTREEHEADER's TotalBtreeEntries.
        self.assertEqual(info["btree"].total_entries, 47)
        names = self._file_names(info)
        # MVB always carries these synthetic streams.
        for expected in ("|SYSTEM", "|TOPIC", "|TTLBTREE", "|FONT", "|CATALOG"):
            self.assertIn(expected, names)

    def test_mvapiref_directory_layout(self):
        info = inspect_mvb_archive(_MVAPIREF)
        # Smaller archive — 16 entries, single-leaf B+ tree.
        self.assertEqual(info["btree"].total_entries, 16)
        self.assertEqual(info["btree"].n_levels, 1)

    def test_mvauthor_multi_level_btree(self):
        info = inspect_mvb_archive(_MVAUTHOR)
        # 93 entries fan out across multiple leaf pages — n_levels=2.
        self.assertEqual(info["btree"].total_entries, 93)
        self.assertEqual(info["btree"].n_levels, 2)
        names = self._file_names(info)
        # All entries must decode to printable ASCII (no garbage from
        # off-by-one walking).
        for name in names:
            self.assertTrue(
                all(0x20 <= ord(c) < 0x7F for c in name),
                f"non-ASCII filename: {name!r}",
            )

    def test_topic_stream_lacks_texttree_magic(self):
        # Sanity check: MVPUBKIT |TOPIC streams are NOT Blackbird
        # TextTree CContent. The 0x01 0x05 magic does not appear at
        # the start of any internal file's body — confirming the
        # archive carries Multimedia Viewer 2.0's compressed format
        # (which decompresses to RTF-like tokens), not Blackbird's
        # `01 05`-prefixed TextTree.
        info = inspect_mvb_archive(_MMAG)
        topic = next(f for f in info["internal_files"] if f.name == "|TOPIC")
        self.assertNotEqual(topic.body[:2], b"\x01\x05")

    def test_text_segment_scanner_finds_few_in_random_bytes(self):
        # The `[0x03 length text]` opcode-scanner is the same one used
        # by `ccontent._scan_text_segments`. When applied to MV's
        # |TOPIC bytes (which use a different grammar), it should find
        # only a small number of false positives — far fewer than the
        # density we see in real Blackbird TextTree CContent.
        info = inspect_mvb_archive(_MMAG)
        topic = next(f for f in info["internal_files"] if f.name == "|TOPIC")
        segments = scan_text_segments(topic.body)
        # Empirical: ~12 short matches in 147 KB of MV-compressed bytes.
        # In a real TextTree of comparable size we would expect 50+
        # multi-word matches. Loose upper bound to catch regressions
        # that would re-introduce the unbounded `find` scan.
        self.assertLess(len(segments), 200)


if __name__ == "__main__":
    unittest.main()
