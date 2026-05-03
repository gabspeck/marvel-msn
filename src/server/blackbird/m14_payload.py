"""Wire-mode builder for the MediaView 1.4 TitleOpen body.

`build_m14_payload_for_deid(deid)` is the single entry point used by
`services.medview` to produce the bytes shipped on the TitleOpen `0x86`
dynamic section. Resolves `<titles_root>/<deid>.ttl`, lowers the
supported TTL subset into the wire payload directly, and always emits a
real section-0 font table plus code-proven fixed-record sections.
Returns `(payload_bytes, caption)`. Never raises — falls back to an
empty 9-section payload with the deid-derived caption on missing /
unsynthesizable `.ttl`.

WHY THE REAL SECTION-0 FONT TABLE
The offline synthesizer's `FNTB` blob is only a debug placeholder.
MVTTL14C `TitleOpenEx @ 0x7E843291` expects a real section-0 layout
(header at +0x00..+0x11, face table, 0x2a-stride descriptor table,
0x92-stride override table, pointer table). Shipping the minimal valid
section-0 recipe unblocks `CreateFontIndirectA` on style 0 → `Times New
Roman`.

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

from .m14_synth import (
    SynthesisError,
    build_section_strings,
    build_selector_13_entries,
    build_source_model,
    build_topic_source_metadata,
    encode_blob_section,
    encode_c_string,
    encode_c_string_table,
    encode_counted_string_section,
    synthesize_metadata,
    synthetic_crc,
    validate_supported_subset,
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

    Synthesizer assigns these in `m14_synth.build_topic_source_metadata`
    from the supported top-level authored proxy/content entries:
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
# bit 0x01 clear (top-band rect also fractional), bit 0x40 clear
# (no bottom-align). Outer rect = full parent (0,0,0x400,0x400). The
# child-rect band is parked as a thin top sliver. Empiric synthetic-title
# probes show this band sits above the white scrollbar strip; the deeper
# black content surface comes from a later scrolling-path paint layer.
# The top band is forced magenta while the scrolling-host strip is forced
# green for visibility probes. Field offsets are
# code-proven
# in `docs/mosview-mediaview-format.md` "Selector 0x06: 0x98-byte
# Window-Scaffold Records".
_SEC06_DEFAULT_FLAGS = 0x00
_SEC06_OUTER_RECT = (0, 0, 0x400, 0x400)
_SEC06_NONSCROLL_RECT = (0, 0, 0x400, 0x40)
_SEC06_TOP_BAND_COLOR = 0x00FF00FF
_SEC06_SCROLL_HOST_COLOR = 0x0000FF00


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
    Layout exactly matches the live wire shape so that
    `m14_parse.parse_payload` accepts it without trailing bytes. Ships
    the real section-0 font table even though no text items reference it
    — keeps the engine on a fully-validated branch.
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
_SEC0_RGB_WHITE = b"\xFF\xFF\xFF"

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
    text_color: bytes = _SEC0_RGB_WHITE,
    back_color: bytes = _SEC0_RGB_INHERIT,
) -> bytes:
    """Encode a 0x2a-byte descriptor record per the §"Descriptor Record" doc.

    Fields not listed (lfWidth, lfEscapement, lfOrientation, lfItalic,
    lfUnderline, lfStrikeOut, lfCharSet, lfOutPrecision, lfClipPrecision,
    lfQuality, lfPitchAndFamily, style_flags, extra_flags) default to 0
    per the "Minimal Valid Section-0 Recipe". The current wire experiment
    forces descriptor 0 text to white so case-1 text remains visible even
    when the title-default text color resolves to black; background color
    still inherits from the title default.
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
    rec[0x06:0x09] = text_color         # +0x06 text_color
    rec[0x09:0x0C] = back_color         # +0x09 back_color
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
             override_table_off, pointer_table_off, descriptor_count=0xFFFF,
             override_count=0
      +0x12  face table  — one 0x20-byte entry: "Times New Roman"
      +0x32  descriptors — one 0x2a-byte entry: face_slot=0, lfHeight=-12,
             lfWeight=400, text_color=white, all else 0/inherit
      +0x5C  overrides   — empty (override_count=0)
      +0x5C  pointer tbl — one 4-byte null entry

    Total size: 0x60 bytes.

    Per `docs/mosview-authored-text-and-font-re.md` §"Minimal Valid
    Section-0 Recipe" — covers `CreateFontIndirectA` on style 0.

    DESCRIPTOR_COUNT = 0xFFFF — clamp every style_id to 0
    `MVCL14N!FUN_7e896610 @ 0x7E896632` does
        MOVSX EAX, word ptr [EDI+2]   ; sign-extend descriptor_count
        CMP   EAX, style_id
        JG    skip                    ; signed: skip clamp if count > id
        XOR   ECX, ECX                ; else style_id = 0
    The case-1 layout pass inherits font index from `puVar2[+0x18]`
    (initialised to 0xFFFF / -1 in `MVCL14N!FUN_7e890fd0 @ 0x7E891034`),
    so the slot emitted by `FUN_7e892d30` carries `slot+0x3F = -1`.
    With `descriptor_count = 1` (signed `1 > -1` → true) the clamp is
    skipped and `FUN_7e896590` reads at
    `descriptor_table_off + (-1)*0x2a = base - 42` — garbage outside
    the descriptor table → `CreateFontIndirectA` builds an invisible
    font (lfHeight ≈ 0, lfWeight = stray bytes from the face entry).
    Setting `descriptor_count = 0xFFFF` makes the sign-extended value
    -1, so `signed -1 > -1` is FALSE → style_id is forced to 0 →
    descriptor[0] is read → Times New Roman renders. With one
    descriptor, every legal style id resolves to the same font, which
    matches the first-paint contract anyway.
    """
    # `descriptor_count` is only consumed by the clamp at FUN_7e896610;
    # the engine never iterates that count, so reporting 0xFFFF (= -1)
    # in the header is safe even though we still emit exactly one
    # descriptor record on the wire.
    advertised_descriptor_count = 0xFFFF
    actual_descriptor_count = 1
    override_count = 0
    face_name_table_off = _SEC0_HEADER_SIZE
    descriptor_table_off = face_name_table_off + (1 * _SEC0_FACE_ENTRY_SIZE)
    override_table_off = descriptor_table_off + (actual_descriptor_count * _SEC0_DESCRIPTOR_SIZE)
    pointer_table_off = override_table_off + (override_count * _SEC0_OVERRIDE_SIZE)

    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                            # +0x00 header_word_0 (unused on first paint)
        advertised_descriptor_count,  # +0x02 descriptor_count (sign-extended → -1)
        face_name_table_off,          # +0x04 face_name_table_off
        descriptor_table_off,         # +0x06 descriptor_table_off
        override_count,               # +0x08 override_count
        override_table_off,           # +0x0a override_table_off
        0,                            # +0x0c header_word_0c (unused on first paint)
    )
    # +0x0e/+0x0f padding stays zero; +0x10 pointer_table_off
    struct.pack_into("<H", header, 0x10, pointer_table_off)

    face_table = _encode_face_table_entry(_SEC0_DEFAULT_FACE_NAME)
    descriptor_table = _encode_descriptor(face_slot_index=0)
    override_table = b""
    pointer_table = struct.pack("<I", 0)  # one null entry

    return bytes(header) + face_table + descriptor_table + override_table + pointer_table


_SECTION0_FONT_BLOB = _build_section0_font_table()


def _encode_fixed_section(records: list[bytes], record_size: int) -> bytes:
    for record in records:
        if len(record) != record_size:
            raise ValueError(f"record does not match size 0x{record_size:x}")
    payload = b"".join(records)
    if len(payload) > 0xFFFF:
        raise ValueError(f"fixed-record section too large: 0x{len(payload):x}")
    return struct.pack("<H", len(payload)) + payload


def _build_sec06_window_scaffold_record() -> bytes:
    """Build the one code-proven window scaffold used on the live wire path.

    RE outcome for the current supported TTL subset:
      - no authored source recovered for selector 0x07 child panes
      - no authored source recovered for selector 0x08 popups
      - selector 0x06[0] alone drives the outer container plus the
        top-band / scrolling-host split

    The record therefore carries only the documented scaffold fields and
    leaves all non-proven bytes zeroed.
    """
    record = bytearray(0x98)
    record[0x15:0x1E] = b"\x00" * 9
    record[0x48] = _SEC06_DEFAULT_FLAGS
    struct.pack_into("<IIII", record, 0x49, *_SEC06_OUTER_RECT)
    struct.pack_into(
        "<II",
        record,
        0x78,
        _SEC06_TOP_BAND_COLOR,
        _SEC06_SCROLL_HOST_COLOR,
    )
    struct.pack_into("<IIII", record, 0x80, *_SEC06_NONSCROLL_RECT)
    return bytes(record)


def _build_live_wire_payload(model: dict, mosview_open_path: str) -> bytes:
    """Build the wire payload without the offline synth placeholders.

    `topics` / `va_get_contents` / `topic_count` still come from the
    supported top-level authored proxy/content order. The fixed-record
    sections are driven only by the code-proven window semantics:
      - selector 0x07: no authored child panes recovered
      - selector 0x08: no authored popup descriptors recovered
      - selector 0x06: one scaffold record for the default pane layout
    """
    strings = build_section_strings(model)
    sec01 = encode_c_string(model["title"]["name"])
    sec02 = b""
    sec6a = encode_c_string(mosview_open_path)
    sec13_entries = build_selector_13_entries()
    sec06_records = [_build_sec06_window_scaffold_record()]
    return b"".join(
        [
            encode_blob_section(_SECTION0_FONT_BLOB),
            _encode_fixed_section([], 0x2B),
            _encode_fixed_section([], 0x1F),
            _encode_fixed_section(sec06_records, 0x98),
            encode_blob_section(sec01),
            encode_blob_section(sec02),
            encode_blob_section(sec6a),
            encode_counted_string_section(sec13_entries),
            encode_c_string_table(strings),
        ]
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
    """Assemble per-topic entries from the supported top-level topic sources.

    Coordinates `m14_synth.build_topic_source_metadata` — same address
    seed (0x1000), same topic_number assignment (entry_index + 1), and
    same context_hash (CRC32 of lowercased proxy name) — so that the va
    values shipped in the TitleOpen reply match the keys the engine
    sends back via selectors 0x06 (hash) / 0x07 (topic) / 0x15 (va).
    """
    entries = build_topic_source_metadata(model)
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
        validate_supported_subset(model)
        wire_payload = _build_live_wire_payload(model, deid)
        synth_metadata, _ = synthesize_metadata(model, wire_payload, deid)
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
    metadata = TitleOpenMetadata(
        va_get_contents=synth_metadata["va_get_contents"],
        addr_get_contents=synth_metadata["addr_get_contents"],
        topic_count=synth_metadata["title_info_0b"],
        cache_header0=synth_metadata["cache_header0"],
        cache_header1=synth_metadata["cache_header1"],
    )
    log.info(
        "m14_synthesized deid=%r path=%s caption=%r wire_len=%d "
        "topic_sources=%d topics=%d va=0x%08x addr=0x%08x topic_count=%d",
        deid, path, caption, len(wire_payload),
        len(model["topic_source_entries"]), len(topics),
        metadata.va_get_contents, metadata.addr_get_contents,
        metadata.topic_count,
    )
    return M14PayloadResult(
        payload=wire_payload,
        caption=caption,
        metadata=metadata,
        topics=topics,
    )
