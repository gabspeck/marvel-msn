"""CContent decoder for Blackbird TTL — TextRuns body only.

Scope (PR1): empirical TextRuns header pin against
`tests/assets/story_test.ttl 8/7` (122 B). Decoder is tolerant of short
/ empty payloads (returns an empty
container) and explicit on TextTree payloads (raises NotImplementedError
so callers can defer).

The leading-byte semantics ([u8 version=2][u8 header_byte_1=0]) and any
in-stream style markers are not yet RE'd. Future PR (BBCTL.OCX +
MVPUBKIT compiler) is expected to pin both. For now, `text` is the raw
ASCII run from offset 2 onwards and `style_runs` is empty; consumers
should match on substring rather than equality."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StyleRun:
    """One per-character style annotation. `style_id` references a slot
    in the title's CStyleSheet; resolution is not in scope for PR1."""
    char_offset: int
    char_length: int
    style_id: int


@dataclass(frozen=True)
class TextRunsContent:
    """Decoded CContent payload for a `TextRuns` typed body."""
    text: str
    style_runs: tuple[StyleRun, ...]
    header_version: int                                    # observed: 0x02 in story_test.ttl 8/7
    header_byte_1: int
    raw_payload: bytes                                     # bytes from offset 2 onwards


_TEXTTREE_HEADER_PREFIX = bytes.fromhex("0105")


def is_texttree(raw: bytes) -> bool:
    """TextTree payloads start with `01 05`. CK-decompress before
    calling — TextTree bodies are also CK-wrapped in some TTLs."""
    return len(raw) >= 2 and raw[:2] == _TEXTTREE_HEADER_PREFIX


def decode_textruns(raw: bytes) -> TextRunsContent:
    """Empirical TextRuns parser.

    - Payloads shorter than 2 B (e.g. `00 00` empty blob) decode to an
      empty container.
    - TextTree payloads raise `NotImplementedError`; callers should
      gate on `is_texttree(raw)`.
    """
    if is_texttree(raw):
        raise NotImplementedError("TextTree decode is not implemented yet")
    if len(raw) < 2:
        return TextRunsContent(
            text="",
            style_runs=(),
            header_version=0,
            header_byte_1=0,
            raw_payload=b"",
        )
    version = raw[0]
    header_byte_1 = raw[1]
    payload = bytes(raw[2:])
    text = payload.decode("ascii", errors="replace")
    return TextRunsContent(
        text=text,
        style_runs=(),
        header_version=version,
        header_byte_1=header_byte_1,
        raw_payload=payload,
    )
