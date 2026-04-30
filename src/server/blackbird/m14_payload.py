"""Wire-mode adapter for the MediaView 1.4 payload synthesizer.

`build_m14_payload_for_deid(deid)` is the single entry point used by
`services.medview` to produce the bytes shipped on the TitleOpen `0x86`
dynamic section. Resolves `<titles_root>/<deid>.ttl`, runs the
synthesizer, strips the leading `FNTB` font blob (see below), and
returns `(payload_bytes, caption)`. Never raises — falls back to an
empty 9-section payload with the deid-derived caption on missing /
unsynthesizable `.ttl`.

WHY STRIP FONT_BLOB
The synthesizer in `m14_synth.synthesize_font_blob` emits
`b"FNTB" + u16 ver=1 + u16 font_count + ...`. MVTTL14C
`TitleOpenEx @ 0x7E843291` reads font_count as `i16` at offset 0
(`b"FN"` = 0x4E46 = ~20K signed) and walks `slots_offset` bytes into
the `GlobalAlloc`'d copy. Synthesizer's font_blob is a structural
placeholder for the offline `.m14` debug envelope, not a wire-faithful
section-0 layout. Section 0 = `b"\\x00\\x00"` steers MVTTL14C into
the safe `LAB_7e8432c4` branch (`docs/MEDVIEW.md` §4.4).

The synthesizer stays unmodified to mirror upstream blackbird-re; the
strip happens here at the wire boundary.

WHY THE BARE DEID FOR `mosview_open_path`
Marvel's HRMOSExec(c=6) path does not pass a Windows path to
`MVTTL14C` — the spec on the wire is just `:2[<deid>]0`. The
synthesizer's `[%s]0` wrapping (`m14_synth.build_stock_parser_title_path`)
is for client-side cache-leaf computation only; on the first-open path
Marvel targets, the deid alone is what lands in `sec6a` as `[4]0`.
Cache-replay fidelity (matching the live `MVCache_*.tmp` filename) is
TBD — no live trace yet — and not blocking first-open.
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path

from .m14_parse import parse_payload
from .m14_synth import (
    SynthesisError,
    build_source_model,
    synthesize_payload,
)
from .ttl_inspect import inspect_blackbird_title

log = logging.getLogger(__name__)


# Sentinel rect values for the first sec06 record (window scaffold).
# Flags=0 → bit 0x08 clear (outer rect = parent fraction, denominator 0x400),
# bit 0x01 clear (non-scrolling rect also fractional), bit 0x40 clear
# (no bottom-align). Outer rect = full parent (0,0,0x400,0x400). The
# non-scrolling pane is parked as a thin top sliver so the scrolling pane
# (synthesised by MOSVIEW from the leftover area) gets the visible bulk.
# Colorrefs default to white (0x00FFFFFF). Field offsets are code-proven
# in `docs/mosview-mediaview-format.md` "Selector 0x06: 0x98-byte
# Window-Scaffold Records".
_SEC06_DEFAULT_FLAGS = 0x00
_SEC06_OUTER_RECT = (0, 0, 0x400, 0x400)
_SEC06_NONSCROLL_RECT = (0, 0, 0x400, 0x40)
_SEC06_PANE_COLOR = 0x00FFFFFF


def _titles_root() -> Path:
    """Resolve the per-title fixture root. Override with MSN_TITLES_ROOT;
    default is `<repo>/resources/titles/`."""
    env = os.environ.get("MSN_TITLES_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "resources" / "titles"


def build_empty_m14_payload(caption: str) -> bytes:
    """9-section payload with empty fixed-record tables and caption-only blobs.

    Used as the fallback when `<deid>.ttl` is missing or unsynthesizable.
    Layout exactly matches the synthesizer-produced wire shape so that
    `m14_parse.parse_payload` accepts it without trailing bytes.
    """
    name = caption.rstrip("\x00") or "Untitled"
    name_blob = name.encode("latin-1", errors="replace") + b"\x00"
    return b"".join(
        [
            b"\x00\x00",                              # font_blob: empty
            b"\x00\x00",                              # sec07: empty
            b"\x00\x00",                              # sec08: empty
            b"\x00\x00",                              # sec06: empty
            struct.pack("<H", len(name_blob)) + name_blob,  # sec01: caption
            b"\x00\x00",                              # sec02: empty
            struct.pack("<H", len(name_blob)) + name_blob,  # sec6a: caption
            b"\x00\x00",                              # sec13 entry_bytes=0
            b"\x00\x00",                              # sec04 count=0
        ]
    )


def _patch_first_sec06_window_scaffold(payload: bytes) -> bytes:
    """Overwrite the synthesizer's garbage rect/flag bytes in sec06[0].

    The first sec06 record drives MOSVIEW's outer `MosViewContainer`
    window construction (caption +0x15, flags +0x48, outer rect
    +0x49..+0x54, pane colorrefs +0x78/+0x7c, non-scrolling pane rect
    +0x80..+0x8c). The synthesizer's `BB06` records put the 116-byte
    `preview` blob (text/image bytes) at +0x24..+0x97, which clobbers
    those positions with random data — observed symptom: MOSVIEW
    minimizes itself after "Preparing title..." passes.

    Patches only the documented scaffold fields; other bytes (BB06
    magic, kind/index/flags at +0x04..+0x07, address/topic/hash dwords,
    packed_lengths, content CRC) are left as the synthesizer wrote them.
    Records 1+ are untouched — `docs/mosview-mediaview-format.md` confirms
    MOSVIEW's main open path consumes only sec06[0].
    """
    parsed = parse_payload(payload)
    if parsed.sec06.record_count == 0:
        return payload
    record_start = parsed.sec06.offset + 2
    record = bytearray(payload[record_start:record_start + 0x98])
    # +0x15 caption: 9 bytes ASCIIZ; empty so the outer container has no titlebar text
    record[0x15:0x1E] = b"\x00" * 9
    # +0x48 flags
    record[0x48] = _SEC06_DEFAULT_FLAGS
    # +0x49..+0x54 outer rect (4 × u32 LE, unaligned)
    struct.pack_into("<IIII", record, 0x49, *_SEC06_OUTER_RECT)
    # +0x78 / +0x7c colorrefs
    struct.pack_into("<II", record, 0x78, _SEC06_PANE_COLOR, _SEC06_PANE_COLOR)
    # +0x80..+0x8c non-scrolling pane rect
    struct.pack_into("<IIII", record, 0x80, *_SEC06_NONSCROLL_RECT)
    return payload[:record_start] + bytes(record) + payload[record_start + 0x98:]


def _strip_font_blob(payload: bytes) -> bytes:
    """Replace the leading [u16 len][font_blob] section with `b"\\x00\\x00"`.

    See module docstring "WHY STRIP FONT_BLOB" for the engine-side
    reasoning. The rest of the payload (sec07/08/06/01/02/6a/13/04) is
    preserved byte-for-byte.
    """
    if len(payload) < 2:
        raise ValueError("payload too short to carry a font_blob length prefix")
    (font_len,) = struct.unpack_from("<H", payload, 0)
    if 2 + font_len > len(payload):
        raise ValueError(
            f"font_blob length {font_len} overruns payload of {len(payload)} bytes"
        )
    return b"\x00\x00" + payload[2 + font_len:]


def _try_caption_from_ttl(path: Path) -> str | None:
    """Best-effort `CTitle.name` lookup used when synthesis fails partway."""
    try:
        inspection = inspect_blackbird_title(path)
    except (OSError, ValueError):
        return None
    title_props = inspection.get("title_prop_map", {})
    name_prop = title_props.get("name") or title_props.get("localname")
    if name_prop is None:
        return None
    value = name_prop.get("value")
    return str(value) if value else None


def build_m14_payload_for_deid(deid: str) -> tuple[bytes, str]:
    """Resolve `<deid>.ttl` and produce a wire-ready 9-section payload.

    Returns `(payload_bytes, caption)`. Never raises; on any failure
    (missing file, parse error, subset-validation rejection) falls back
    to `build_empty_m14_payload(caption_or_"Title <deid>")`.
    """
    deid = (deid or "").strip()
    fallback_caption = f"Title {deid}" if deid else "Untitled"
    if not deid:
        return build_empty_m14_payload(fallback_caption), fallback_caption

    path = _titles_root() / f"{deid}.ttl"
    if not path.is_file():
        log.info("ttl_missing deid=%r path=%s — using empty payload", deid, path)
        return build_empty_m14_payload(fallback_caption), fallback_caption

    try:
        model = build_source_model(path)
        payload, _ = synthesize_payload(model, deid)
    except (SynthesisError, ValueError, OSError) as exc:
        log.warning(
            "m14_synthesize_failed deid=%r path=%s: %s — using empty payload",
            deid, path, exc,
        )
        caption = _try_caption_from_ttl(path) or fallback_caption
        return build_empty_m14_payload(caption), caption

    caption = model["title"]["name"] or fallback_caption
    wire_payload = _strip_font_blob(payload)
    wire_payload = _patch_first_sec06_window_scaffold(wire_payload)
    log.info(
        "m14_synthesized deid=%r path=%s caption=%r raw_len=%d wire_len=%d entries=%d",
        deid, path, caption, len(payload), len(wire_payload),
        len(model["visible_entries"]),
    )
    return wire_payload, caption
