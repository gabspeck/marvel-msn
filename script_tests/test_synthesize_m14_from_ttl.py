from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from inspect_mediaview_cache import parse_cache_file, parse_payload  # noqa: E402
from synthesize_m14_from_ttl import (  # noqa: E402
    SynthesisError,
    build_source_model,
    sanitize_cache_leaf,
    synthesize_payload,
    validate_supported_subset,
    write_artifacts,
)


SAMPLE_TTL = REPO_ROOT / "msn today.ttl"


class SynthesizeM14Tests(unittest.TestCase):
    def test_sanitize_cache_leaf(self) -> None:
        self.assertEqual(
            sanitize_cache_leaf(r"C:\A\[B]\file.m14"),
            "MVCache__C__A__B__file.m14_0.tmp",
        )

    def test_supported_subset_rejects_extra_visible_entry(self) -> None:
        model = build_source_model(SAMPLE_TTL)
        model["visible_entries"].append(dict(model["visible_entries"][0]))
        with self.assertRaises(SynthesisError):
            validate_supported_subset(model)

    def test_payload_round_trips_through_cache_parser(self) -> None:
        model = build_source_model(SAMPLE_TTL)
        payload, _ = synthesize_payload(model, r"E:\MSN Today.m14")
        parsed = parse_payload(payload)
        self.assertEqual(parsed.sec07.record_count, 3)
        self.assertEqual(parsed.sec08.record_count, 3)
        self.assertEqual(parsed.sec06.record_count, 3)
        self.assertEqual(parsed.sec04.count, 9)
        self.assertEqual(parsed.sec13.count, 2)
        self.assertGreater(parsed.font_blob.length, 0)
        self.assertFalse(parsed.trailing)

    def test_write_artifacts_emits_parseable_cache_and_synthetic_m14(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out_m14 = tmp / "out" / "sample.m14"
            mosbin_dir = tmp / "mosbin"
            report_path = tmp / "report.json"
            open_path = r"E:\MSN Today.m14"
            report = write_artifacts(
                ttl_path=SAMPLE_TTL,
                out_m14=out_m14,
                mosview_open_path=open_path,
                mosbin_dir=mosbin_dir,
                report_path=report_path,
            )

            cache_path = Path(report["cache_path"])
            self.assertEqual(
                cache_path.name,
                sanitize_cache_leaf(open_path),
            )
            cache = parse_cache_file(cache_path.read_bytes(), payload_only=False)
            parsed = parse_payload(cache.payload)
            self.assertEqual(cache.header0, report["mediaview"]["metadata"]["cache_header0"])
            self.assertEqual(cache.header1, report["mediaview"]["metadata"]["cache_header1"])
            self.assertEqual(parsed.sec07.record_count, 3)
            self.assertEqual(parsed.sec08.record_count, 3)
            self.assertEqual(parsed.sec06.record_count, 3)

            self.assertTrue(out_m14.exists())
            self.assertTrue(report_path.exists())
            self.assertEqual(out_m14.read_bytes()[:8], b"SM14POC\x00")
            self.assertEqual(report["parser_title_path"], "[E:\\MSN Today.m14]0")
            self.assertIn("unresolved_fields", report)
            self.assertGreater(len(report["unresolved_fields"]), 0)


if __name__ == "__main__":
    unittest.main()
