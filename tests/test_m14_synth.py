"""Round-trip tests for the MediaView 1.4 payload synthesizer.

Adapted from `~/projetos/blackbird-re/tests/test_synthesize_m14_from_ttl.py`.
The `write_artifacts` test is dropped — that entry point lived in the
upstream `.m14`-envelope writer which the marvel-msn fork does not lift
(see `src/server/blackbird/m14_synth.py` module docstring).
"""

from __future__ import annotations

import unittest
from pathlib import Path

from server.blackbird.m14_parse import parse_payload
from server.blackbird.m14_synth import (
    build_source_model,
    sanitize_cache_leaf,
    synthesize_payload,
    validate_supported_subset,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TTL = REPO_ROOT / "resources" / "titles" / "4.ttl"


class SynthesizeM14Tests(unittest.TestCase):
    def test_sanitize_cache_leaf(self) -> None:
        self.assertEqual(
            sanitize_cache_leaf(r"C:\A\[B]\file.m14"),
            "MVCache__C__A__B__file.m14_0.tmp",
        )

    def test_supported_subset_accepts_extra_topic_source_entry(self) -> None:
        model = build_source_model(SAMPLE_TTL)
        extra_entry = dict(model["topic_source_entries"][0])
        extra_entry["entry_index"] = len(model["topic_source_entries"])
        extra_entry["proxy_name"] = "Homepage Copy"
        model["topic_source_entries"].append(extra_entry)
        model["section"]["contents"].append(model["section"]["contents"][0])
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


if __name__ == "__main__":
    unittest.main()
