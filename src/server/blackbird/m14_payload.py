"""Wire-mode adapter for the MediaView 1.4 payload synthesizer.

`build_m14_payload_for_deid(deid)` is the single entry point used by
`services.medview` to produce the bytes shipped on the TitleOpen `0x86`
dynamic section. Resolves `<titles_root>/<deid>.ttl`, runs the
synthesizer, replaces the synthesizer's `FNTB`-magic font blob with a
real section-0 font table per
`docs/mosview-authored-text-and-font-re.md` "Minimal Valid Section-0
Recipe", and patches the first sec06 record's window scaffold fields.
Returns `(payload_bytes, caption)`. Never raises — falls back to an
empty 9-section payload with the deid-derived caption on missing /
unsynthesizable `.ttl`.

WHY REPLACE FONT_BLOB
The synthesizer in `m14_synth.synthesize_font_blob` emits
`b"FNTB" + u16 ver=1 + u16 font_count + ...` — a structural placeholder
for the offline `.m14` debug envelope. MVTTL14C
`TitleOpenEx @ 0x7E843291` reads font_count as `i16` at offset 0
(`b"FN"` = 0x4E46 = ~20K signed) and would walk off the
`GlobalAlloc`'d copy. The wire requires a real section-0 layout
(header at +0x00..+0x11, face table, 0x2a-stride descriptor table,
0x92-stride override table, pointer table). Replacing the synthesizer's
blob with a hand-built minimal section-0 unblocks `CreateFontIndirectA`
on style 0 → `Times New Roman`.

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
from dataclasses import dataclass, field
from pathlib import Path

from .m14_parse import parse_payload
from .m14_synth import (
    SynthesisError,
    build_source_model,
    build_visible_entry_metadata,
    synthesize_metadata,
    synthesize_payload,
    synthetic_crc,
)
from .ttl_inspect import inspect_blackbird_title

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TitleOpenMetadata:
    """Wire-mode metadata dwords shipped in the TitleOpen static reply.

    Field semantics per `docs/mosview-mediaview-format.md` "Materialized
    Title Object Fields":
      - `va_get_contents` → title +0x8c (`vaGetContents`); first-paint entry address
      - `addr_get_contents` → title +0x90 (`addrGetContents`); address-contents base
      - `topic_count` → title +0x94 (`TitleGetInfo(0x0B)` upper bound)
      - `cache_header0/1` → 8-byte validation tuple compared against `MVCache_*.tmp`
    """

    va_get_contents: int = 0
    addr_get_contents: int = 0
    topic_count: int = 0
    cache_header0: int = 0
    cache_header1: int = 0


@dataclass(frozen=True)
class TopicEntry:
    """Per-topic mapping consumed by selector 0x06 / 0x07 / 0x15 cache pushes.

    Synthesizer assigns these in `m14_synth.build_visible_entry_metadata`:
      - `topic_number` = `entry_index + 1` (selector 0x07 cache key)
      - `address`      = `0x1000 + entry_index * 0x100` (va, also addr for first paint)
      - `context_hash` = `CRC32(proxy_name.lower())` (selector 0x06 cache key)
      - `text`         = ANSI story buffer from TextRuns CContent (case-1 chunk text)

    `text` is empty for image entries or empty-TextRuns text entries.
    """

    topic_number: int
    address: int
    context_hash: int
    proxy_name: str
    kind: str  # "text" | "image"
    text: bytes = b""


@dataclass(frozen=True)
class M14PayloadResult:
    """Output of `build_m14_payload_for_deid` — wire body + per-topic mapping.

    `payload` is the wire-ready bytes shipped in the TitleOpen `0x86`
    section; `caption` drives logging and the "About Title" dialog
    (`docs/mosview-mediaview-format.md` §"Selector 0x01 / 0x02 String
    Handling"); `metadata` carries the static-section dwords; and
    `topics` is the per-topic mapping consumed by cache-miss handlers
    (selector 0x06 vaConvertHash, 0x07 vaConvertTopicNumber, 0x15
    vaResolve). Indexed lookups on the handler side use:
      - `topic_number` → cache-pushed va (real, not echo-key)
      - `context_hash` → same va via hash→va mapping
      - `address` (va) → text content for case-1 chunks
    """

    payload: bytes
    caption: str
    metadata: TitleOpenMetadata = field(default_factory=TitleOpenMetadata)
    topics: tuple[TopicEntry, ...] = ()

    def topic_by_number(self, topic_number: int) -> TopicEntry | None:
        for t in self.topics:
            if t.topic_number == topic_number:
                return t
        return None

    def topic_by_hash(self, context_hash: int) -> TopicEntry | None:
        for t in self.topics:
            if t.context_hash == context_hash:
                return t
        return None

    def topic_by_address(self, address: int) -> TopicEntry | None:
        for t in self.topics:
            if t.address == address:
                return t
        return None


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
    `m14_parse.parse_payload` accepts it without trailing bytes. Ships
    the real section-0 font table even though no text items reference
    it — keeps the engine on a fully-validated branch.
    """
    name = caption.rstrip("\x00") or "Untitled"
    name_blob = name.encode("latin-1", errors="replace") + b"\x00"
    font_blob = _SECTION0_FONT_BLOB
    return b"".join(
        [
            struct.pack("<H", len(font_blob)) + font_blob,  # font_blob: minimal section-0
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


# Section-0 layout constants (`docs/mosview-authored-text-and-font-re.md`).
# Header is 18 bytes (`u16` slots at +0x00,+0x02,+0x04,+0x06,+0x08,+0x0a,
# +0x0c, padding at +0x0e, +0x10). Stride for descriptor record is 0x2a,
# face table entry is 0x20 ANSI bytes, override record is 0x92 (unused on
# the first-paint path), pointer table entry is 4 bytes.
_SEC0_HEADER_SIZE = 0x12
_SEC0_FACE_ENTRY_SIZE = 0x20
_SEC0_DESCRIPTOR_SIZE = 0x2A
_SEC0_OVERRIDE_SIZE = 0x92
_SEC0_POINTER_ENTRY_SIZE = 4

# Sentinel "inherit" rgb24 for descriptor.text_color / descriptor.back_color.
_SEC0_RGB_INHERIT = b"\x01\x01\x01"

_SEC0_DEFAULT_FACE_NAME = "Times New Roman"
_SEC0_DEFAULT_LF_HEIGHT = -12
_SEC0_DEFAULT_LF_WEIGHT = 400


def _encode_face_table_entry(face_name: str) -> bytes:
    """Encode a 0x20-byte ANSI face-table entry (NUL-padded).

    Schema: `docs/mosview-authored-text-and-font-re.md` §"Section-0 Header
    Schema". `hMVSetFontTable` indexes this table at
    `face_name_table_off + face_slot_index * 0x20` and reads the ANSI
    string up to its first NUL.
    """
    encoded = face_name.encode("ascii", errors="replace")
    if len(encoded) >= _SEC0_FACE_ENTRY_SIZE:
        raise ValueError(f"face name too long for 0x20-byte slot: {face_name!r}")
    return encoded.ljust(_SEC0_FACE_ENTRY_SIZE, b"\x00")


def _encode_descriptor(
    face_slot_index: int,
    lf_height: int = _SEC0_DEFAULT_LF_HEIGHT,
    lf_weight: int = _SEC0_DEFAULT_LF_WEIGHT,
) -> bytes:
    """Encode a 0x2a-byte descriptor record per the §"Descriptor Record" doc.

    Fields not listed (lfWidth, lfEscapement, lfOrientation, lfItalic,
    lfUnderline, lfStrikeOut, lfCharSet, lfOutPrecision, lfClipPrecision,
    lfQuality, lfPitchAndFamily, style_flags, extra_flags) default to 0
    per the "Minimal Valid Section-0 Recipe". `text_color` / `back_color`
    use the `0x010101` "inherit" sentinel.
    """
    rec = bytearray(_SEC0_DESCRIPTOR_SIZE)
    struct.pack_into(
        "<HHH",
        rec,
        0x00,
        face_slot_index & 0xFFFF,    # +0x00 face_slot_index
        0,                            # +0x02 descriptor_aux_id
        0,                            # +0x04 override_style_id (0 = no chain)
    )
    rec[0x06:0x09] = _SEC0_RGB_INHERIT  # +0x06 text_color
    rec[0x09:0x0C] = _SEC0_RGB_INHERIT  # +0x09 back_color
    struct.pack_into(
        "<iiiii",
        rec,
        0x0C,
        lf_height,                    # +0x0C lfHeight
        0,                             # +0x10 lfWidth
        0,                             # +0x14 lfEscapement
        0,                             # +0x18 lfOrientation
        lf_weight,                     # +0x1C lfWeight
    )
    # +0x20..+0x29 — all remaining LOGFONT bytes + style_flags / extra_flags
    # left at zero (already initialised by bytearray()).
    return bytes(rec)


def _build_section0_font_table() -> bytes:
    """Build the minimal valid section-0 font blob.

    Layout:

      +0x00  header (18 B) — face_name_table_off, descriptor_table_off,
             override_table_off, pointer_table_off, descriptor_count=1,
             override_count=0
      +0x12  face table  — one 0x20-byte entry: "Times New Roman"
      +0x32  descriptors — one 0x2a-byte entry: face_slot=0, lfHeight=-12,
             lfWeight=400, all else 0/inherit
      +0x5C  overrides   — empty (override_count=0)
      +0x5C  pointer tbl — one 4-byte null entry

    Total size: 0x60 bytes.

    Per `docs/mosview-authored-text-and-font-re.md` §"Minimal Valid
    Section-0 Recipe" — covers `CreateFontIndirectA` on style 0.
    """
    descriptor_count = 1
    override_count = 0
    face_name_table_off = _SEC0_HEADER_SIZE
    descriptor_table_off = face_name_table_off + (1 * _SEC0_FACE_ENTRY_SIZE)
    override_table_off = descriptor_table_off + (descriptor_count * _SEC0_DESCRIPTOR_SIZE)
    pointer_table_off = override_table_off + (override_count * _SEC0_OVERRIDE_SIZE)

    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                       # +0x00 header_word_0 (unused on first paint)
        descriptor_count,        # +0x02 descriptor_count
        face_name_table_off,     # +0x04 face_name_table_off
        descriptor_table_off,    # +0x06 descriptor_table_off
        override_count,          # +0x08 override_count
        override_table_off,      # +0x0a override_table_off
        0,                       # +0x0c header_word_0c (unused on first paint)
    )
    # +0x0e/+0x0f padding stays zero; +0x10 pointer_table_off
    struct.pack_into("<H", header, 0x10, pointer_table_off)

    face_table = _encode_face_table_entry(_SEC0_DEFAULT_FACE_NAME)
    descriptor_table = _encode_descriptor(face_slot_index=0)
    override_table = b""
    pointer_table = struct.pack("<I", 0)  # one null entry

    return bytes(header) + face_table + descriptor_table + override_table + pointer_table


_SECTION0_FONT_BLOB = _build_section0_font_table()


def _install_section0_font_table(payload: bytes) -> bytes:
    """Replace the synthesizer's leading `[u16 len][FNTB...]` with the
    real section-0 font table.

    See module docstring "WHY REPLACE FONT_BLOB" for the engine-side
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
    new_blob = _SECTION0_FONT_BLOB
    return struct.pack("<H", len(new_blob)) + new_blob + payload[2 + font_len:]


def _clear_synthesizer_fixed_records(payload: bytes) -> bytes:
    """Drop synthesizer's `BB07` / `BB08` records to zero counts.

    `m14_synth.synthesize_sec0[7|8]_records` emits records with
    `b"BB07"` / `b"BB08"` debug magic at offset 0 plus packed CRC /
    preview garbage at every offset MOSVIEW reads (flags +0x0b/+0x01,
    inline title +0x0c/+0x02, x/y/w/h, COLORREF). Per
    `docs/mosview-mediaview-format.md` §"Selectors MOSVIEW Actually
    Consumes" only sec06 is on the first-paint critical path; sec07
    feeds extra `MosChildView` windows and sec08 feeds popup descriptors,
    both optional (engine synthesises a default popup `[The Default
    Popup]` after parsing real records).

    Dropping them to byte_length=0 is safer than shipping garbage —
    MOSVIEW skips the heap-collect loops, no extra child windows or
    popups are spawned, and the outer + non-scrolling + scrolling
    panes (driven by sec06[0]) own all the visible chrome. sec06 is
    left intact so `_patch_first_sec06_window_scaffold` can overwrite
    its first record's documented offsets in the next pass.
    """
    parsed = parse_payload(payload)
    sec07_data_start = parsed.sec07.offset
    sec06_data_start = parsed.sec06.offset
    # Replace [u16 sec07_len][sec07_records][u16 sec08_len][sec08_records]
    # with [u16 0][u16 0]. sec06 is preserved.
    return (
        payload[:sec07_data_start]
        + b"\x00\x00\x00\x00"
        + payload[sec06_data_start:]
    )


def _extract_text_runs_body(payload: bytes) -> bytes:
    """Lower one TextRuns CContent payload to its ANSI story buffer.

    Observed format (`docs/blackbird-title-format.md` "CContent" +
    Homepage.bdf empirical dump): `[u16 schema_prefix][ANSI text]`.
    Strategy: skip the 2-byte prefix, strip a leading `'S'` marker
    that prefixes every observed body, truncate at the first NUL.

    The exact role of the leading `'S'` byte and the `'#'` paragraph
    delimiters is RE-deferred. Returns empty bytes for empty / unknown
    payloads.
    """
    if len(payload) < 3:
        return b""
    body = payload[2:]
    nul = body.find(b"\x00")
    if nul >= 0:
        body = body[:nul]
    if body.startswith(b"S"):
        body = body[1:]
    return bytes(body)


def _build_topic_entries(model: dict) -> tuple[TopicEntry, ...]:
    """Assemble per-topic entries from the synthesizer's visible entries.

    Coordinates `m14_synth.build_visible_entry_metadata` — same address
    seed (0x1000), same topic_number assignment (entry_index + 1), same
    context_hash (CRC32 of lowercased proxy name) — so that the va
    values shipped in TitleOpen reply match the keys the engine sends
    back via selectors 0x06 (hash) / 0x07 (topic) / 0x15 (va).
    """
    entries = build_visible_entry_metadata(model)
    out: list[TopicEntry] = []
    for entry in entries:
        if entry["kind"] == "text":
            text = _extract_text_runs_body(
                entry.get("text_runs", {}).get("payload", b"")
            )
        else:
            text = b""
        out.append(
            TopicEntry(
                topic_number=entry["topic_number"],
                address=entry["address"],
                context_hash=entry["context_hash"],
                proxy_name=entry["proxy_name"],
                kind=entry["kind"],
                text=text,
            )
        )
    return tuple(out)


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


def _empty_metadata(payload: bytes) -> TitleOpenMetadata:
    """Metadata for the empty-fallback path: only cache_header0 carries
    a real CRC of the payload bytes. Other dwords are zero — the engine
    accepts zeros on the no-content path (verified empirically against
    medview.py:296-299 probe with contents_va in {0, 0x10000, 0xCAFEBABE})."""
    return TitleOpenMetadata(
        va_get_contents=0,
        addr_get_contents=0,
        topic_count=0,
        cache_header0=synthetic_crc(payload),
        cache_header1=0,
    )


def build_m14_payload_for_deid(deid: str) -> M14PayloadResult:
    """Resolve `<deid>.ttl` and produce a wire-ready 9-section payload.

    Returns `M14PayloadResult` carrying:
      - `payload`: bytes for the TitleOpen `0x86` dynamic section
      - `caption`: `CTitle.name` or `"Title <deid>"` fallback
      - `metadata`: TitleOpen static-section dwords (per
        `docs/mosview-mediaview-format.md` "Materialized Title Object Fields")
      - `topics`: per-topic mapping (topic_number / address / context_hash /
        text) consumed by selector 0x06 / 0x07 / 0x15 cache pushes

    Never raises; on any failure (missing file, parse error,
    subset-validation rejection) falls back to an empty payload with
    the deid-derived caption.
    """
    deid = (deid or "").strip()
    fallback_caption = f"Title {deid}" if deid else "Untitled"
    if not deid:
        empty = build_empty_m14_payload(fallback_caption)
        return M14PayloadResult(
            payload=empty,
            caption=fallback_caption,
            metadata=_empty_metadata(empty),
            topics=(),
        )

    path = _titles_root() / f"{deid}.ttl"
    if not path.is_file():
        log.info("ttl_missing deid=%r path=%s — using empty payload", deid, path)
        empty = build_empty_m14_payload(fallback_caption)
        return M14PayloadResult(
            payload=empty,
            caption=fallback_caption,
            metadata=_empty_metadata(empty),
            topics=(),
        )

    try:
        model = build_source_model(path)
        raw_payload, _ = synthesize_payload(model, deid)
        synth_metadata, _ = synthesize_metadata(model, raw_payload, deid)
        topics = _build_topic_entries(model)
    except (SynthesisError, ValueError, OSError) as exc:
        log.warning(
            "m14_synthesize_failed deid=%r path=%s: %s — using empty payload",
            deid, path, exc,
        )
        caption = _try_caption_from_ttl(path) or fallback_caption
        empty = build_empty_m14_payload(caption)
        return M14PayloadResult(
            payload=empty,
            caption=caption,
            metadata=_empty_metadata(empty),
            topics=(),
        )

    caption = model["title"]["name"] or fallback_caption
    # Wire-mode pipeline:
    # 1. Replace synthesizer's FNTB placeholder with real section-0 font table
    # 2. Drop sec07/sec08 BB-magic records to zero counts
    # 3. Patch sec06[0] window scaffold offsets with valid rect/colorrefs
    wire_payload = _install_section0_font_table(raw_payload)
    wire_payload = _clear_synthesizer_fixed_records(wire_payload)
    wire_payload = _patch_first_sec06_window_scaffold(wire_payload)
    # cache_header0/1 are computed against the WIRE payload (post-strip
    # / post-patch), not the synthesizer's raw output, so the engine's
    # cache-hit check on subsequent opens compares against bytes that
    # actually went on the wire.
    metadata = TitleOpenMetadata(
        va_get_contents=synth_metadata["va_get_contents"],
        addr_get_contents=synth_metadata["addr_get_contents"],
        topic_count=synth_metadata["title_info_0b"],
        cache_header0=synthetic_crc(wire_payload),
        cache_header1=synth_metadata["cache_header1"],
    )
    log.info(
        "m14_synthesized deid=%r path=%s caption=%r raw_len=%d wire_len=%d "
        "entries=%d topics=%d va=0x%08x addr=0x%08x topic_count=%d",
        deid, path, caption, len(raw_payload), len(wire_payload),
        len(model["visible_entries"]), len(topics),
        metadata.va_get_contents, metadata.addr_get_contents,
        metadata.topic_count,
    )
    return M14PayloadResult(
        payload=wire_payload,
        caption=caption,
        metadata=metadata,
        topics=topics,
    )
