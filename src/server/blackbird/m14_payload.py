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
MVTTL14C `TitleOpenEx @ 0x7E843291` expects a real section-0 layout
(header at +0x00..+0x11, face table, 0x2a-stride descriptor table,
0x92-stride override table, pointer table). The live-wire path lowers
the parsed `CStyleSheet` into a multi-face / multi-descriptor blob via
`_build_section0_for_stylesheet` — one face entry per font key, one
descriptor per style_id with fully merged LOGFONTA bytes. The empty-
fallback path (no `.ttl` available) keeps the minimal recipe (single
`Times New Roman` face entry, single descriptor) so `CreateFontIndirectA`
still resolves on style 0.

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
from .ttl_inspect import (
    CSTYLE_DEFAULT_PROPS,
    inspect_blackbird_title,
    parse_text_runs_paragraphs,
)

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
class TopicParagraph:
    """One authored paragraph + the section-0 `style_id` it renders with.

    `style_id` indexes into the section-0 descriptor table built by
    `_build_section0_for_stylesheet`; the case-1 chunk's `\\x80 <style_u16>`
    control op selects this descriptor. The first paragraph of a topic
    is currently assigned `style_id = 1` (Heading 1) per heuristic — see
    `_paragraphs_from_text_runs` for the full rule. Real per-paragraph
    style refs require TextTree RE that is still deferred.
    """

    text: str
    style_id: int


@dataclass(frozen=True)
class TopicEntry:
    """Per-topic mapping consumed by selector 0x06 / 0x07 / 0x15 cache pushes.

    Synthesizer assigns these in `m14_synth.build_topic_source_metadata`
    from the supported top-level authored proxy/content entries:
      - `topic_number` = `entry_index + 1` (selector 0x07 cache key)
      - `address`      = `0x1000 + entry_index * 0x100` (va, also addr for first paint)
      - `context_hash` = `CRC32(proxy_name.lower())` (selector 0x06 cache key)
      - `paragraphs`   = ordered authored paragraphs (TextRuns body split on `'#'`)

    `paragraphs` is empty for image entries and for text entries with an
    empty TextRuns payload. Consumers fall back to the title caption
    when no paragraph is available.
    """

    topic_number: int
    address: int
    context_hash: int
    proxy_name: str
    kind: str  # "text" | "image"
    paragraphs: tuple[TopicParagraph, ...] = ()


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


# sec06 window-scaffold defaults. Flags=0 → bit 0x08 clear (outer rect
# = parent fraction, denominator 0x400), bit 0x01 clear (top-band rect
# also fractional), bit 0x40 clear (no bottom-align). Outer rect =
# full parent (0,0,0x400,0x400). The child-rect band is parked as a
# thin top sliver. Field offsets are code-proven in
# `docs/mosview-mediaview-format.md` "Selector 0x06: 0x98-byte
# Window-Scaffold Records". The three COLORREFs (outer container at
# +0x5B, top band at +0x78, scrolling-host strip at +0x7C) all default
# to white — matches the authored Normal back_color in
# `CSTYLE_DEFAULT_PROPS[0]` and avoids the prior red/magenta/green
# RE-instrument scheme bleeding into shipped .ttl renders.
_SEC06_DEFAULT_FLAGS = 0x00
_SEC06_OUTER_RECT = (0, 0, 0x400, 0x400)
_SEC06_NONSCROLL_RECT = (0, 0, 0x400, 0x40)
_SEC06_BACKDROP_WHITE = 0x00FFFFFF
_SEC06_CONTAINER_COLOR = _SEC06_BACKDROP_WHITE
_SEC06_TOP_BAND_COLOR = _SEC06_BACKDROP_WHITE
_SEC06_SCROLL_HOST_COLOR = _SEC06_BACKDROP_WHITE


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

_SEC0_DEFAULT_FACE_NAME = "Times New Roman"
_SEC0_DEFAULT_LF_HEIGHT = -12
_SEC0_DEFAULT_LF_WEIGHT = 400
_SEC0_BOLD_LF_WEIGHT = 700

# CCharProps `flags_word` bit pairs (`docs/mosview-authored-text-and-font-re.md`
# §"On-Disk → Wire Field Mapping"). Each tuple: (attribute key, absent_mask
# bit in high byte, value bit in low byte). When `absent_mask` is set the
# attribute inherits from the parent; otherwise `value_bit` IS the explicit
# value.
_FLAG_BIT_TABLE = (
    ("bold",      0x0100, 0x0002),
    ("italic",    0x0200, 0x0004),
    ("underline", 0x0400, 0x0008),
    ("super",     0x0800, 0x0010),
    ("sub",       0x1000, 0x0020),
)

# CCharProps field-level sentinels: `0xfffe` = "absent", `0xffff` =
# "no_change". Both treated as transparent for u16 fields. Color
# fields use the same sentinels widened to u32.
_CCP_U16_SENTINELS = (0xFFFE, 0xFFFF)
_CCP_U32_SENTINELS = (0xFFFFFFFE, 0xFFFFFFFF)

# Resolution-chain depth limit, matches `FUN_7e8963b0` engine-side cap.
_SEC0_RESOLVE_DEPTH_LIMIT = 0x14

# Strikethrough is a name-tagged effect: `name_index 0x22` always sets
# `lfStrikeOut`, regardless of `flags_word` bits (per "Reserved bits"
# finding — strike is delivered by the renderer via NAME, not a flag).
_NAME_INDEX_STRIKETHROUGH = 0x22


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


def _build_face_table(fonts: list[dict] | None) -> bytes:
    """Build the section-0 face table from `CStyleSheet.fonts`.

    `fonts` is a list of `{key, name}` per `parse_stylesheet_header`. Output
    is sized to `max(key) + 1`; slots without a font entry are zero-filled.
    Empty / missing names also yield a zero slot — matches font key 0
    convention (reserved as the "inherit" / empty slot in authored TTLs).

    Returns the minimal `Times New Roman` single-entry table when `fonts`
    is empty / None — used by the empty-fallback path so descriptor 0
    still resolves to a real face string.
    """
    if not fonts:
        return _encode_face_table_entry(_SEC0_DEFAULT_FACE_NAME)
    max_key = max(f["key"] for f in fonts)
    table = bytearray((max_key + 1) * _SEC0_FACE_ENTRY_SIZE)
    for f in fonts:
        if not f["name"]:
            continue
        slot = f["key"] * _SEC0_FACE_ENTRY_SIZE
        table[slot:slot + _SEC0_FACE_ENTRY_SIZE] = _encode_face_table_entry(f["name"])
    return bytes(table)


def _encode_descriptor(
    face_slot_index: int,
    lf_height: int,
    lf_weight: int,
    lf_italic: int = 0,
    lf_underline: int = 0,
    lf_strikeout: int = 0,
    text_color: bytes = _SEC0_RGB_INHERIT,
    back_color: bytes = _SEC0_RGB_INHERIT,
) -> bytes:
    """Encode a 0x2a-byte descriptor record per §"Descriptor Record" in
    `docs/mosview-authored-text-and-font-re.md`. `descriptor + 0x0c..+0x27`
    is the LOGFONTA prefix copied into `CreateFontIndirectA` (proved by
    `FUN_7e896ba0`); face name resolves via `face_slot_index` against the
    face table at `face_name_table_off + face_slot_index * 0x20`."""
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
    rec[0x20] = lf_italic & 0xFF         # +0x20 lfItalic
    rec[0x21] = lf_underline & 0xFF      # +0x21 lfUnderline
    rec[0x22] = lf_strikeout & 0xFF      # +0x22 lfStrikeOut
    # +0x23..+0x29 — lfCharSet/lfOutPrecision/lfClipPrecision/lfQuality/
    # lfPitchAndFamily/style_flags/extra_flags all zero (defaults documented
    # in §"Minimal Valid Section-0 Recipe"; on-disk source has no
    # corresponding fields).
    return bytes(rec)


def _initial_resolved_attrs() -> dict:
    """Engine-global fallback for fields with no source up the chain.

    Mirrors `LoadDefaultStyle`'s baked-in defaults: Times New Roman 12pt,
    no styling, both colors set to "inherit from title default" (wire
    sentinel `0x010101`)."""
    return {
        "font_id": 1,
        "pt_size": 12,
        "text_color": None,
        "back_color": None,
        "bold": False,
        "italic": False,
        "underline": False,
        "super": False,
        "sub": False,
        "strikeout": False,
    }


def _merge_flags(resolved: dict, flags_word: int) -> None:
    """Merge a CCharProps `flags_word` into a resolved attrs dict.

    Per attribute, when the absent_mask bit is clear the value bit is the
    explicit value; when set, the attribute inherits (no change to
    `resolved`). See `_FLAG_BIT_TABLE` for bit layout."""
    for attr, absent_mask, value_bit in _FLAG_BIT_TABLE:
        if not (flags_word & absent_mask):
            resolved[attr] = bool(flags_word & value_bit)


def _apply_default_props(resolved: dict, defaults: dict) -> None:
    """Apply per-name-index defaults from CSTYLE_DEFAULT_PROPS."""
    if defaults["font_id"] != 0:
        resolved["font_id"] = defaults["font_id"]
    if defaults["pt_size"] != 0:
        resolved["pt_size"] = defaults["pt_size"]
    if defaults["text_color"] not in _CCP_U32_SENTINELS:
        resolved["text_color"] = defaults["text_color"]
    if defaults["back_color"] not in _CCP_U32_SENTINELS:
        resolved["back_color"] = defaults["back_color"]
    _merge_flags(resolved, defaults["flags_word"])


def _apply_char_props(resolved: dict, fields: dict) -> None:
    """Apply authored CCharProps overrides on top of resolved attrs."""
    fid = fields.get("font_id")
    if fid is not None and fid != 0 and fid not in _CCP_U16_SENTINELS:
        resolved["font_id"] = fid
    pt = fields.get("pt_size")
    if pt is not None and pt != 0 and pt not in _CCP_U16_SENTINELS:
        resolved["pt_size"] = pt
    tc = fields.get("text_color")
    if tc is not None and tc not in _CCP_U32_SENTINELS:
        resolved["text_color"] = tc
    bc = fields.get("back_color")
    if bc is not None and bc not in _CCP_U32_SENTINELS:
        resolved["back_color"] = bc
    fw = fields.get("flags_word")
    if fw is not None:
        _merge_flags(resolved, fw)


def _resolve_style_attrs(style_id: int, parsed_by_id: dict[int, dict]) -> dict:
    """Resolve a style's wire attributes by walking its based_on chain.

    Walks from leaf (`style_id`) up to root, capping at
    `_SEC0_RESOLVE_DEPTH_LIMIT` (mirrors `FUN_7e8963b0` engine cap). Then
    replays the chain root→leaf, layering per-name-index defaults
    (`CSTYLE_DEFAULT_PROPS`) followed by authored CCharProps overrides at
    each level. Result is a flat attrs dict consumed by
    `_encode_descriptor_for_style`.

    Strikethrough special-case: when the leaf's `name_index == 0x22`, set
    `strikeout = True` regardless of the merged flags_word (the renderer
    delivers strike via name match, not a flag bit — pinned in
    `docs/mosview-authored-text-and-font-re.md` §"Reserved bits")."""
    chain: list[tuple[int, int, dict | None]] = []
    seen: set[int] = set()
    cursor: int | None = style_id
    while (
        cursor is not None
        and len(chain) < _SEC0_RESOLVE_DEPTH_LIMIT
        and cursor not in seen
    ):
        seen.add(cursor)
        parsed = parsed_by_id.get(cursor)
        if parsed is None:
            chain.append((cursor, cursor, None))
            break
        chain.append((cursor, parsed["name_index"], parsed))
        cursor = parsed["based_on"]
    chain.reverse()  # root → leaf

    resolved = _initial_resolved_attrs()
    for _sid, name_index, parsed in chain:
        if name_index < len(CSTYLE_DEFAULT_PROPS):
            _apply_default_props(resolved, CSTYLE_DEFAULT_PROPS[name_index])
        if parsed and parsed["char_props"]:
            _apply_char_props(resolved, parsed["char_props"]["fields"])

    leaf = parsed_by_id.get(style_id)
    if leaf and leaf["name_index"] == _NAME_INDEX_STRIKETHROUGH:
        resolved["strikeout"] = True

    return resolved


def _encode_color(value: int | None) -> bytes:
    """Pack a COLORREF (or None for inherit) into the descriptor's rgb24
    field. COLORREF byte order is `[R, G, B, 0]`; we ship the first three
    bytes verbatim. `None` resolves to the "inherit from title default"
    sentinel `0x010101`."""
    if value is None:
        return _SEC0_RGB_INHERIT
    return (value & 0xFFFFFF).to_bytes(3, "little")


def _descriptor_from_resolved(resolved: dict) -> bytes:
    """Encode a fully-resolved attrs dict into a 0x2a-byte descriptor."""
    pt_size = resolved["pt_size"]
    lf_height = -(pt_size * 20) if pt_size else _SEC0_DEFAULT_LF_HEIGHT
    lf_weight = _SEC0_BOLD_LF_WEIGHT if resolved["bold"] else _SEC0_DEFAULT_LF_WEIGHT
    return _encode_descriptor(
        face_slot_index=resolved["font_id"],
        lf_height=lf_height,
        lf_weight=lf_weight,
        lf_italic=1 if resolved["italic"] else 0,
        lf_underline=1 if resolved["underline"] else 0,
        lf_strikeout=1 if resolved["strikeout"] else 0,
        text_color=_encode_color(resolved["text_color"]),
        back_color=_encode_color(resolved["back_color"]),
    )


def _pack_section0_header(
    descriptor_count_field: int,
    face_table_size: int,
    descriptor_count_actual: int,
    override_count: int,
) -> bytes:
    """Emit the 18-byte section-0 header. `descriptor_count_field` is what
    the engine sign-extends and compares against incoming style_ids in
    `MVCL14N!FUN_7e896610`; the actual records emitted are determined by
    `descriptor_count_actual`."""
    face_name_table_off = _SEC0_HEADER_SIZE
    descriptor_table_off = face_name_table_off + face_table_size
    override_table_off = (
        descriptor_table_off + descriptor_count_actual * _SEC0_DESCRIPTOR_SIZE
    )
    pointer_table_off = override_table_off + override_count * _SEC0_OVERRIDE_SIZE
    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                              # +0x00 header_word_0 (unused on first paint)
        descriptor_count_field & 0xFFFF,  # +0x02 descriptor_count
        face_name_table_off,            # +0x04 face_name_table_off
        descriptor_table_off,           # +0x06 descriptor_table_off
        override_count,                 # +0x08 override_count
        override_table_off,             # +0x0a override_table_off
        0,                              # +0x0c header_word_0c (unused)
    )
    struct.pack_into("<H", header, 0x10, pointer_table_off)
    return bytes(header)


def _build_minimal_section0() -> bytes:
    """Build the minimal valid section-0 font blob (96 bytes total).

    One face entry (`Times New Roman`), one descriptor (face_slot=0,
    lfHeight=-12, lfWeight=400, both colors inherit). Used on the
    empty-fallback path when no `.ttl` model is available.

    `descriptor_count = 0xFFFF` (sign-extended → -1) forces every incoming
    `style_id` through the `FUN_7e896610` clamp to 0, so every authored
    style_id renders against descriptor[0]. Without this clamp the case-1
    layout pass inherits font index `-1` from `FUN_7e890fd0` and reads
    `descriptor_table_off + (-1)*0x2a` — garbage that yields an invisible
    font."""
    face_table = _encode_face_table_entry(_SEC0_DEFAULT_FACE_NAME)
    descriptor_table = _encode_descriptor(
        face_slot_index=0,
        lf_height=_SEC0_DEFAULT_LF_HEIGHT,
        lf_weight=_SEC0_DEFAULT_LF_WEIGHT,
    )
    header = _pack_section0_header(
        descriptor_count_field=0xFFFF,
        face_table_size=len(face_table),
        descriptor_count_actual=1,
        override_count=0,
    )
    pointer_table = struct.pack("<I", 0)
    return header + face_table + descriptor_table + pointer_table


_SECTION0_FONT_BLOB = _build_minimal_section0()


def _merge_linked_stylesheet_styles(
    stylesheet: dict,
) -> list[dict]:
    """Apply Phase 4 linked-stylesheet merge to a section-local stylesheet.

    When `linked_stylesheet_present == 1`, the section-local stylesheet's
    style list overrides the title-level base for matching `style_id`s.
    Resolution semantics in `docs/mosview-authored-text-and-font-re.md`:
    walk handle table at the swizzle index, decode the target via
    `decode_handle()`, merge by style_id with local taking precedence.

    Today's `build_source_model` exposes only one CStyleSheet, so the
    linked target is unreachable. Returns the local style list unchanged
    in that case — Phase 4 is structurally a no-op until multi-stylesheet
    TTLs are surfaced upstream. The merge logic itself, when a future
    upstream wires up `stylesheet["linked_stylesheet_styles"]`, is:
    base.union(local), with local entries overriding base on style_id."""
    local_styles = stylesheet.get("styles", [])
    base_styles = stylesheet.get("linked_stylesheet_styles") or []
    if not base_styles:
        return list(local_styles)
    merged_by_id: dict[int, dict] = {s["style_id"]: s for s in base_styles}
    for s in local_styles:
        merged_by_id[s["style_id"]] = s
    return [merged_by_id[k] for k in sorted(merged_by_id)]


def _build_section0_for_stylesheet(stylesheet: dict) -> bytes:
    """Build a multi-face / multi-descriptor section-0 from a parsed
    `CStyleSheet`.

    Phase 1: face table sized to `max(font.key) + 1`, one entry per
    `CStyleSheet.fonts[i]`.
    Phase 2: one descriptor per style_id, fully merged via
    `_resolve_style_attrs` (per-name-index defaults + based_on chain +
    authored CCharProps overrides).
    Phase 3: shipped empty (override_count = 0); descriptors are
    pre-merged so the engine's override walker has nothing to add.
    Phase 4: applied via `_merge_linked_stylesheet_styles`.

    Falls back to `_build_minimal_section0()` when the stylesheet has
    no styles — keeps the engine on a fully-validated branch."""
    merged_styles = _merge_linked_stylesheet_styles(stylesheet)
    if not merged_styles:
        return _build_minimal_section0()

    parsed_by_id = {s["style_id"]: s for s in merged_styles}
    descriptor_count = max(parsed_by_id) + 1
    face_table = _build_face_table(stylesheet.get("fonts"))

    descriptor_table = bytearray()
    for style_id in range(descriptor_count):
        resolved = _resolve_style_attrs(style_id, parsed_by_id)
        descriptor_table += _descriptor_from_resolved(resolved)

    header = _pack_section0_header(
        descriptor_count_field=descriptor_count,
        face_table_size=len(face_table),
        descriptor_count_actual=descriptor_count,
        override_count=0,
    )
    # Pointer-table sized to match the face table — `MVCL14N!FUN_7e896661`
    # indexes `pointer_table[face_slot_index * 4]` and dereferences a
    # non-zero entry at `[+0x16]` to seed `title+0xB4`. With a one-entry
    # null table any descriptor whose `face_slot_index >= 1` walks past
    # the blob end and reads neighbour memory — observed AV at EAX
    # garbage (0x04080000) on MOSVIEW open of `4.ttl`. Zero-filling all
    # slots forces the alternate `MOV [ESI+0xB4], 0` branch, which the
    # first-paint path doesn't read again.
    face_entry_count = len(face_table) // _SEC0_FACE_ENTRY_SIZE
    pointer_table = b"\x00" * (face_entry_count * _SEC0_POINTER_ENTRY_SIZE)
    return header + face_table + bytes(descriptor_table) + pointer_table


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
    struct.pack_into("<I", record, 0x5B, _SEC06_CONTAINER_COLOR)
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
    section0_blob = _build_section0_for_stylesheet(model["stylesheet"])
    return b"".join(
        [
            encode_blob_section(section0_blob),
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


_HEADING_STYLE_ID = 1   # CSTYLE_NAME_DICTIONARY[1] = "Heading 1"
_BODY_STYLE_ID = 0      # CSTYLE_NAME_DICTIONARY[0] = "Normal"


def _paragraphs_from_text_runs(payload: bytes) -> tuple[TopicParagraph, ...]:
    """Lower a TextRuns CContent into a tuple of styled paragraphs.

    Heuristic style assignment: the first authored paragraph maps to
    Heading 1 (`style_id = 1`), the rest to Normal (`style_id = 0`).
    Per-paragraph style refs are not preserved on the wire by TextRuns
    alone — that information lives in TextTree, where the inline item-
    record headers carry name_index/style_id refs (RE-deferred). The
    heuristic mirrors the typical authored shape (one heading followed
    by body paragraphs) and is the smallest mapping that exercises both
    bold/Arial and Roman typography on the rendering path.
    """
    paragraphs = parse_text_runs_paragraphs(payload)
    if not paragraphs:
        return ()
    out = [TopicParagraph(text=paragraphs[0], style_id=_HEADING_STYLE_ID)]
    out.extend(
        TopicParagraph(text=p, style_id=_BODY_STYLE_ID)
        for p in paragraphs[1:]
    )
    return tuple(out)


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
            paragraphs = _paragraphs_from_text_runs(
                entry.get("text_runs", {}).get("payload", b"")
            )
        else:
            paragraphs = ()
        out.append(
            TopicEntry(
                topic_number=entry["topic_number"],
                address=entry["address"],
                context_hash=entry["context_hash"],
                proxy_name=entry["proxy_name"],
                kind=entry["kind"],
                paragraphs=paragraphs,
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
