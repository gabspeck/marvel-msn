"""Parse a BBDESIGN-authored `.ttl` and lower its content to MEDVIEW wire.

Scope: enumerate every CBForm in the title (via `CTitle.base_forms`
plus DFS through `CSection.sections`/`CSection.forms`) and surface each
as a `LoadedPage`. The first page's geometry / controls / captions are
also exposed via backcompat properties on `LoadedTitle` so PR1 keeps
`lower_to_payload` and `build_bm0_baggage` on the page-0 path. PR3 lifts
both to per-page emission.
"""

from __future__ import annotations

import logging
import pathlib
import re
import struct
from dataclasses import dataclass, field

import olefile

from ...blackbird.wire import (
    build_baggage_container,
    build_kind5_raster,
    build_kind8_baggage,
    TextItem,
    build_text_metafile,
    build_trailer,
)
from .ccontent import TextRunsContent, decode_textruns, is_texttree
from .ole_helpers import (
    SectionRecord,
    maybe_decompress_ck,
    ole_storage_id,
    parse_handles_by_storage,
    parse_proxy_table,
    parse_section,
    parse_simple_property_table,
    parse_type_names_map,
    resolve_swizzle,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class FaceEntry:
    slot: int                                # CStyleSheet font key (u16)
    face_name: str                           # LOGFONTA lfFaceName


@dataclass(frozen=True)
class Control:
    """Base BBCTL site record. `name` is the raw site name from the
    descriptor (e.g. "Caption1", "Shortcut1=R", "CaptionButton1R")."""
    seq: int                                 # 1-based descriptor sequence
    flags: int                               # descriptor flags u32
    name: str


@dataclass(frozen=True)
class CaptionControl(Control):
    """Caption1: read-only static text. Persist layout pinned via
    `BBCTL.OCX!CLabelCtrl::DoPropExchange` (FUN_40009356, v=4) +
    `FUN_40003dbc` (border parent, v=3) + stock prop mask `0xD2` set in
    `FUN_40008e81` (constructor).

    Persist call order (BBCTL.OCX decompile):
    1. ExchangeVersion v=4
    2. parent border persist (ExchangeVersion v=3 → ExchangeStockProps →
       BevelWidth, FrameStyle, BevelHilight, BevelShadow, FrameColor)
    3. idTag (LONG, default -1)
    4. strCaption (CString, the visible label)
    5. fWordWrap (BOOL, default FALSE)
    6. fAutoSize (BOOL, default FALSE)
    7. iAlignment (LONG, default 0)
    8. fTransparent (LONG, default TRUE; v≥3 only)

    On-disk layout in the LAST descriptor's `inline_tail` (the shared
    per-caption record buffer for multi-caption pages, or the single
    descriptor's inline_tail for single-caption pages):

      +0x00..+0x0F  rect (i32×4 in HIMETRIC, LTRB)
      +0x10..+0x3B  44-B form-level header (MS Forms 1.0 site wrapper +
                   width/height_redundant + 0x1D const + zero + 6-B
                   `font_pre_clsid` containing the stock `back_color`)
      +0x3C..+0x4B  StdFont CLSID
      +0x4C..       Font body:
                     +0x10  u8 version = 1
                     +0x11  u16 charset
                     +0x13  u8 attrs (italic 0x02, underline 0x04,
                                       strikeout 0x08)
                     +0x14  u16 weight
                     +0x16  u32 cy_lo (points * 10000)
                     +0x1A  u8 name_len
                     +0x1B  N B ASCII name (no NUL)
      after Font:
        +0x00 (4 B)  BevelWidth (LONG, default 0)
        +0x04 (4 B)  FrameStyle (LONG, default 0)
        +0x08 (4 B)  BevelHilight (COLORREF, default 0xFFFFFF, v≥3)
        +0x0C (4 B)  BevelShadow (COLORREF, default 0x000000, v≥3)
        +0x10 (4 B)  FrameColor (COLORREF, default 0x000000, v≥2)
        +0x14 (4 B)  idTag (LONG, default -1)
        +0x18 (1+N B) strCaption (Pascal-string)

    Post-strCaption (10-byte block immediately after strCaption end):
        +0x00 (2 B)  fWordWrap   (BOOL VARIANT_BOOL, default 0)
        +0x02 (2 B)  fAutoSize   (BOOL VARIANT_BOOL, default 0)
        +0x04 (2 B)  iAlignment  (short, default 0; 0=left 1=center 2=right)
        +0x06 (4 B)  fTransparent(LONG, default 1)
    Pinned empirically: `4.ttl` pages 1/2 and `first title.ttl` page 1
    (all four default-valued single-Caption fixtures) share the exact
    same 10 bytes `00 00 00 00 00 00 01 00 00 00`, which decode to the
    MFC defaults (0, 0, 0, 1). The values BBDESIGN doesn't vary across
    fixtures so non-default-value verification is deferred to future
    single-property probes — but the offsets and types are pinned.

    Stock-prop COLORREF wrapped in the 6-B `font_pre_clsid` (bytes
    `[u8 0][u32 COLORREF][u8 0]` at `font_off-5..font_off`) is the
    `back_color`. Default observed value `0xC8D0D8` = COLOR_3DFACE.
    Probe variants exhibit `0x0000FF` (red) and `0xFFF0FF` (ivory) for
    Caption 2 / 3 of `4.ttl` page 0."""
    text: str
    font_name: str
    size_pt: int                             # font_size_cy_lo // 10000
    weight: int                              # 400 = FW_NORMAL
    rect_himetric: tuple[int, int, int, int] # (L, T, R, B) HIMETRIC (0.01mm)
    italic: bool = False
    underline: bool = False
    strikeout: bool = False
    charset: int = 0                         # LOGFONTA lfCharSet (WORD)
    back_color: int = 0xC8D0D8               # COLORREF stock prop (font_pre_clsid)
    bevel_width: int = 0                     # LONG
    frame_style: int = 0                     # LONG
    bevel_hilight: int = 0xFFFFFF            # COLORREF (v ≥ 3)
    bevel_shadow: int = 0                    # COLORREF (v ≥ 3)
    frame_color: int = 0                     # COLORREF (v ≥ 2)
    id_tag: int = -1                         # LONG; -1 = no script binding
    word_wrap: bool = False                  # BOOL (post-strCaption, default-only)
    auto_size: bool = False                  # BOOL (post-strCaption, default-only)
    alignment: int = 0                       # LONG (post-strCaption, default-only)
    transparent: bool = True                 # LONG (post-strCaption, default-only)
    color_rgb: int = 0                       # back_color alias (back-compat)


@dataclass(frozen=True)
class _CompoundControl(Control):
    """Helper base for compound BBCTL controls (Story / Audio /
    CaptionButton / Outline / Shortcut). `xy_twips` is the (x, y) top-
    left from the inline tail; `raw_block` is the descriptor's inline
    tail bytes (decoders that aren't yet RE'd carry the bytes through
    for offline inspection)."""
    xy_twips: tuple[int, int]
    raw_block: bytes


@dataclass(frozen=True)
class StoryControl(_CompoundControl):
    """Story control (BBCTL.OCX class `CQtxtCtrl`, ProgID
    `QTXT.QtxtCtrl.1`). `content_proxy_ref` is the proxy_key (e.g.
    0x00001500) selected for this Story's text body; `content` is the
    decoded TextRuns payload. Both are None when the chase failed
    (logged at INFO). PR1 uses a heuristic Pascal-string → CProxyTable
    name match — content_proxy_ref is sourced from the matched proxy
    entry rather than RE'd from the persist stream; deeper per-field
    decoding remains TODO (see `docs/re-passes/BBCTL.OCX.md`)."""
    content_proxy_ref: int | None = None
    content: TextRunsContent | None = None


@dataclass(frozen=True)
class CaptionButtonControl(_CompoundControl):
    """CaptionButton (BBCTL.OCX class `CLabelBtnCtrl`, ProgID
    `LABELBTN.LabelBtnCtrl.1`)."""


@dataclass(frozen=True)
class AudioControl(_CompoundControl):
    """Audio (BBCTL.OCX class `CAudioCtrl`, ProgID
    `AUDIO.AudioCtrl.1`)."""


@dataclass(frozen=True)
class OutlineControl(_CompoundControl):
    """Outline (BBCTL.OCX class `CInfomapCtrl`, ProgID
    `INFOMAP.InfomapCtrl.1`)."""


@dataclass(frozen=True)
class ShortcutControl(_CompoundControl):
    """Shortcut (BBCTL.OCX class `CBblinkCtrl`, ProgID
    `BBLINK.BblinkCtrl.1`)."""


@dataclass(frozen=True)
class UnknownControl(Control):
    """Fallback when neither CLSID nor name prefix matches a known BBCTL
    kind. Carries `raw_block` + `clsid` for offline inspection."""
    raw_block: bytes
    clsid: bytes | None = None


@dataclass(frozen=True)
class LoadedPage:
    """One CBForm-rooted page. Per-page state lives here; title-level
    state (caption / window_rect / font_table) stays on `LoadedTitle`."""
    name: str                                # CBForm.<table>/<slot> properties.name
    cbform_table: int
    cbform_slot: int
    cvform_handle: int | None
    page_bg: int                             # CVForm Page background COLORREF (u32 LE)
    page_pixel_w: int                        # CVForm Page width  (px)
    page_pixel_h: int                        # CVForm Page height (px)
    scrollbar_flags: int                     # CVForm Page +0x18; bit0=H, bit1=V
    controls: tuple[Control, ...]

    @property
    def captions(self) -> tuple[CaptionControl, ...]:
        return tuple(c for c in self.controls if isinstance(c, CaptionControl))


@dataclass(frozen=True)
class LoadedTitle:
    """BBDESIGN-authored title. `pages` is in BBDESIGN tree order.

    Page-0 backcompat properties were dropped in PR3 — callers must
    address pages explicitly (`title.pages[0].controls`,
    `title.pages[i].page_bg`, etc.). The two lowering helpers
    (`lower_to_payload`, `build_all_bm_baggage`) emit per-page output.
    """
    title_name: str                          # CTitle properties["name"]
    caption: str                             # CBFrame caption — host window title
    window_rect: tuple[int, int, int, int]   # CBFrame (left, top, width, height) pixels
    font_table: tuple[FaceEntry, ...]
    pages: tuple[LoadedPage, ...] = field(default_factory=tuple)


_STDFONT_CLSID = bytes.fromhex("0352e30b918fce119de300aa004bb851")
_BBCTL_SITE_MARKER = bytes.fromhex("73 00 03 00")


def _parse_title_name(stream: bytes) -> str:
    """`name` (VT_STRING) out of `1/0/\\x03properties`.

    Wire shape: `[u32 count]{[u8 namelen][name][u8 type][u32 strlen][bytes]}`.
    Only the `name` field is relevant.
    """
    pos = 0
    count = struct.unpack_from("<I", stream, pos)[0]
    pos += 4
    for _ in range(count):
        namelen = stream[pos]
        pos += 1
        prop_name = stream[pos:pos + namelen].decode("ascii", errors="replace")
        pos += namelen
        ptype = struct.unpack_from("<H", stream, pos)[0]
        pos += 2
        if ptype == 0x0008:                                # VT_STRING
            slen = struct.unpack_from("<I", stream, pos)[0]
            pos += 4
            data = stream[pos:pos + slen]
            pos += slen
            if prop_name == "name":
                return data.rstrip(b"\x00").decode("ascii", errors="replace")
        else:
            raise ValueError(f"unsupported CTitle property type 0x{ptype:04x}")
    return ""


def _parse_cbframe(buf: bytes) -> tuple[str, tuple[int, int, int, int]]:
    """CBFrame: version=2, frame_name, caption, (left, top, width, height)."""
    if buf[0] != 0x02:
        raise ValueError(f"unsupported CBFrame version: {buf[0]}")
    pos = 1
    name_len = buf[pos]
    pos += 1 + name_len
    cap_len = buf[pos]
    pos += 1
    caption = buf[pos:pos + cap_len].decode("ascii", errors="replace")
    pos += cap_len
    rect = struct.unpack_from("<IIII", buf, pos)
    return caption, rect


def _parse_cstylesheet(buf: bytes) -> tuple[FaceEntry, ...]:
    """CStyleSheet font table.

    Wire shape (4.ttl): `[u8 version=9][u16 font_count][u16 style_count]
    { [u8 namelen][ASCII name][u16 key] }*font_count [u8 trailer]`.
    style_count tolerates non-zero values (msn_today.ttl: 54 styles
    after the font table; unused here).
    """
    if buf[0] != 0x09:
        raise ValueError(f"unsupported CStyleSheet version: {buf[0]}")
    pos = 1
    font_count = struct.unpack_from("<H", buf, pos)[0]
    pos += 2
    pos += 2                                               # style_count (unused)
    faces: list[FaceEntry] = []
    for _ in range(font_count):
        namelen = buf[pos]
        pos += 1
        name = buf[pos:pos + namelen].decode("ascii", errors="replace")
        pos += namelen
        slot = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
        faces.append(FaceEntry(slot=slot, face_name=name))
    return tuple(faces)


@dataclass(frozen=True)
class _CVFormPage:
    background: int                          # COLORREF at +0x10
    scrollbar_flags: int                     # u32 at +0x18 (bit0=H, bit1=V)
    width_px: int                            # u32 at +0x1C
    height_px: int                           # u32 at +0x20


def _parse_cvform_page(buf: bytes) -> _CVFormPage:
    """CVForm Page (5/x) properties block.

    Layout pinned via test_title.ttl differential pages (Test Page,
    Test Page Vertical Scrollbar, Test Page Horizontal Scrollbar) — only
    the +0x18 dword toggles between the variants.
    """
    background, _mouse_cursor, scrollbar_flags, width_px, height_px = struct.unpack_from(
        "<IIIII", buf, 0x10,
    )
    return _CVFormPage(
        background=background,
        scrollbar_flags=scrollbar_flags,
        width_px=width_px,
        height_px=height_px,
    )


@dataclass(frozen=True)
class _SiteDescriptor:
    """Raw site-descriptor record + its inline data span.

    `inline_tail` = bytes from name+NUL up to the next descriptor's seq
    field (or to the MS Forms trailer CLSID for the last descriptor).
    For Caption-style controls, `inline_tail` contains the full property
    block. For compound controls (Story/Audio/CaptionButton/Outline/
    Shortcut) it contains a small preamble — further property data lives
    further down the post-descriptor region.

    `class_index` is the low byte of `flags`, indexing into the CVForm
    preamble's class table (see `_parse_cvform_class_table`).
    `clsid` is the looked-up 16-B class CLSID (or None when the form
    has no matching slot).
    """
    seq: int
    flags: int
    name: str
    size: int                                # descriptor.size — semantic open
    descriptor_off: int
    name_end: int                            # offset of trailing NUL
    inline_tail: bytes
    class_index: int                         # `flags & 0xFF`
    clsid: bytes | None                      # `class_table[class_index]` or None


# `0e f1 28 57` = first 4 bytes of MS Forms 1.0 Form CLSID
# {5728F10E-27CC-101B-A8EF-00000B65C5F8}. The Form embeds this CLSID
# once in its preamble at +0x28 and once again in the trailing class-
# registration block. The walker uses the second occurrence as the end
# of the descriptor list.
_FORM_CLSID_PREFIX = bytes.fromhex("0ef12857")
_FORM_PREAMBLE_END = 0x28
_BBCTL_SITE_MARKER_U32 = 0x00030073

# CVForm preamble carries a class-CLSID table. Layout pinned across
# 4.ttl / msn_today / showcase: 16-B CLSIDs at offset 0x9A (154), each
# stride 40 B. Each site descriptor's `flags & 0xFF` indexes into this
# table to select the BBCTL control class.
_CVFORM_CLASS_TABLE_OFF = 0x9A
_CVFORM_CLASS_TABLE_STRIDE = 40


# BBCTL.OCX CLSIDs extracted from `Register_C{Class}Ctrl_*` MFC factory
# initializers (DllRegisterServer → Ordinal_403 chain). 6 CLSIDs map to
# the 6 site-class names emitted by BBDESIGN's CVForm authoring tool
# (Story / Caption / Audio / CaptionButton / Outline / Shortcut); the
# remaining 4 are BBCTL controls not exercised by any current TTL
# fixture (PictureButton / PrintPsf / Picture / Psf).
#
# Annotated in Ghidra (MSN95 project, BBCTL.OCX):
# - CLSID_CQtxtCtrl_QTXT_BBCTL_STORY              @ 0x40023fd8
# - CLSID_CLabelCtrl_LABEL_BBCTL_CAPTION          @ 0x40021c50
# - CLSID_CAudioCtrl_AUDIO_BBCTL_AUDIO            @ 0x4001fe90
# - CLSID_CLabelBtnCtrl_LABELBTN_BBCTL_CAPTIONBUTTON @ 0x4001f888
# - CLSID_CInfomapCtrl_INFOMAP_BBCTL_OUTLINE      @ 0x40022d58
# - CLSID_CBblinkCtrl_BBLINK_BBCTL_SHORTCUT       @ 0x400210b0
_BBCTL_CLSIDS: dict[bytes, str] = {
    bytes.fromhex("00ae8392bf6ace11b94200aa004a7abf"): "Story",
    bytes.fromhex("d0096f1a7465ce11a25f00aa003e4475"): "Caption",
    bytes.fromhex("60359058eb57ce11a68500aa005f54d7"): "Audio",
    bytes.fromhex("8bf178b684871b10bd5200aa003e4475"): "CaptionButton",
    bytes.fromhex("e053d2dee2f4cd11ab6d00aa003e4475"): "Outline",
    bytes.fromhex("a066f706094fce119a0000aa006b1e42"): "Shortcut",
}


def _parse_cvform_class_table(raw: bytes) -> tuple[bytes, ...]:
    """Walk the CVForm preamble's class CLSID table.

    Empirical: each entry is 16 B at +154 / +194 / +234 / ..., stride
    40. Continue while the next slot bytes match a known BBCTL CLSID;
    stop on first non-match or buffer end. Returns the in-order list of
    class CLSIDs (one per distinct class referenced by sites in the
    form). Tested against 4.ttl (1 CLSID per page), msn_today (2),
    showcase 7/0 (5), showcase 7/1 (1)."""
    out: list[bytes] = []
    pos = _CVFORM_CLASS_TABLE_OFF
    while pos + 16 <= len(raw):
        candidate = bytes(raw[pos:pos + 16])
        if candidate not in _BBCTL_CLSIDS:
            break
        out.append(candidate)
        pos += _CVFORM_CLASS_TABLE_STRIDE
    return tuple(out)


# Minimum on-disk length of the site-class name prefix, indexed by the
# class name resolved from the CVForm class table. When `prefix_len + 1
# > 8`, the name field can't fit in the 8-byte slot and is therefore
# always NUL-terminated. When it fits in 8 bytes, the field is exactly
# 8 bytes wide: NUL-padded for shorter names, no terminator for names
# that fill the slot exactly. The 8-byte slot rule is pinned by:
#   - Caption1 / Outline1 (8 chars, no NUL, rect/xy_twips immediately
#     follow) — showcase + 4.ttl
#   - Story1R / Audio1R (7 chars + 1 NUL pad) — msn_today + showcase
#   - Shortcut1=R (11 chars + NUL) — msn_today
#   - CaptionButton1R (15 chars + NUL) — showcase
_SITE_NAME_PREFIX_MIN_LEN: dict[str, int] = {
    "Caption": 7,
    "CaptionButton": 13,
    "Story": 5,
    "Audio": 5,
    "Outline": 7,
    "Shortcut": 8,
}
_SITE_NAME_SLOT = 8
_SITE_NAME_MAX = 64                                # safety cap for NUL scan


def _scan_site_name(
    raw: bytes, name_off: int, end_of_list: int, class_name: str | None,
) -> int:
    """Compute the end offset of a site descriptor's name field.

    BBDESIGN writes site names into an 8-byte slot: names shorter than 8
    chars are NUL-padded, names exactly 8 chars have no terminator (the
    next byte is inline data — rect for Caption, xy_twips for compound
    controls), and names longer than 8 chars overflow with a NUL
    terminator after the last char.

    The first two cases are ambiguous from bytes alone when the inline
    data's first byte is a printable ASCII value (e.g. Caption4 in
    4.ttl has `rect.left = 1905 = 0x0771` whose LSB is `'q'`). The
    class CLSID resolves the ambiguity: known classes with a prefix
    that fits in the 8-byte slot take exactly 8 bytes when no NUL is
    found within the slot; classes whose prefix can't fit (e.g.
    CaptionButton, Shortcut) always overflow and use NUL termination.
    """
    field_end = min(name_off + _SITE_NAME_SLOT, end_of_list)
    end = name_off
    while end < field_end and raw[end] != 0:
        end += 1
    if end < field_end:
        return end                                  # NUL within 8-byte slot
    prefix_len = _SITE_NAME_PREFIX_MIN_LEN.get(class_name or "", 0)
    if prefix_len + 1 <= _SITE_NAME_SLOT:
        return field_end                            # exactly-8-char name
    cap = min(name_off + _SITE_NAME_MAX, end_of_list)
    while end < cap and raw[end] != 0:
        end += 1
    return end


def _walk_cbform(raw: bytes) -> tuple[_SiteDescriptor, ...]:
    """Walk site descriptors in a CVForm (Form preamble at +0x00, sites
    starting at +0x28). Each descriptor produces a `_SiteDescriptor`
    with `inline_tail` carrying bytes up to the next site (or to the
    trailing form CLSID at end of file).

    Each descriptor's `flags & 0xFF` indexes into the CVForm preamble's
    class table (parsed via `_parse_cvform_class_table`) to resolve a
    16-B BBCTL class CLSID. The resolved class drives `_scan_site_name`
    so the name field's exact byte boundary is pinned before slicing
    `inline_tail`. CLSID-first dispatch + name-prefix fallback happens
    in `_decode_descriptor`."""
    trailer_off = raw.find(_FORM_CLSID_PREFIX, _FORM_PREAMBLE_END + 4)
    end_of_list = trailer_off if trailer_off >= 0 else len(raw)
    class_table = _parse_cvform_class_table(raw)

    records: list[tuple[int, int, int, str, int, int, int, bytes | None]] = []
    pos = _FORM_PREAMBLE_END
    while True:
        m = raw.find(_BBCTL_SITE_MARKER, pos)
        if m < 0 or m + 12 > end_of_list:
            break
        seq_off = m - 4
        if seq_off < pos:
            pos = m + 4
            continue
        seq, marker, size, flags = struct.unpack_from("<IIII", raw, seq_off)
        if marker != _BBCTL_SITE_MARKER_U32:
            pos = m + 4
            continue
        class_index = flags & 0xFF
        clsid = (
            class_table[class_index]
            if 0 <= class_index < len(class_table)
            else None
        )
        class_name = _BBCTL_CLSIDS.get(clsid) if clsid is not None else None
        name_off = seq_off + 16
        name_end = _scan_site_name(raw, name_off, end_of_list, class_name)
        name = raw[name_off:name_end].decode("ascii", errors="replace")
        records.append(
            (seq, flags, size, name, seq_off, name_end, class_index, clsid),
        )
        pos = name_end + 1

    descriptors: list[_SiteDescriptor] = []
    for idx, rec in enumerate(records):
        seq, flags, size, name, seq_off, name_end, class_index, clsid = rec
        next_start = (
            records[idx + 1][4] if idx + 1 < len(records) else end_of_list
        )
        descriptors.append(_SiteDescriptor(
            seq=seq,
            flags=flags,
            name=name,
            size=size,
            descriptor_off=seq_off,
            name_end=name_end,
            inline_tail=raw[name_end:next_start],
            class_index=class_index,
            clsid=clsid,
        ))
    return tuple(descriptors)


# Named offsets for the CLabelCtrl persist stream layout (anchored on
# the StdFont CLSID). Pinned via BBCTL.OCX FUN_40009356 / FUN_40003dbc
# decompile + byte-trace against 4.ttl / first title.ttl fixtures.

_FONT_PRE_CLSID_BYTES = 6                                  # 6-B wrapper before CLSID
_FONT_PRE_CLSID_COLORREF_OFF = -5                          # COLORREF inside font_pre_clsid
_FONT_BODY_VERSION_OFF = 0x10                              # u8 = 1
_FONT_BODY_CHARSET_OFF = 0x11                              # u16
_FONT_BODY_ATTRS_OFF = 0x13                                # u8: italic 0x02, underline 0x04, strikeout 0x08
_FONT_BODY_WEIGHT_OFF = 0x14                               # u16
_FONT_BODY_CY_LO_OFF = 0x16                                # u32 = pt * 10000
_FONT_BODY_NAME_LEN_OFF = 0x1A                             # u8
_FONT_BODY_NAME_OFF = 0x1B                                 # N B ASCII

# Border / class-specific props directly after Font name (no padding).
# Offsets relative to (font_off + 0x1B + name_len).
_BORDER_BEVEL_WIDTH_OFF = 0x00
_BORDER_FRAME_STYLE_OFF = 0x04
_BORDER_BEVEL_HILIGHT_OFF = 0x08
_BORDER_BEVEL_SHADOW_OFF = 0x0C
_BORDER_FRAME_COLOR_OFF = 0x10
_CLABEL_ID_TAG_OFF = 0x14
_CLABEL_STR_CAPTION_OFF = 0x18

# Post-strCaption fields (10 B total). Empirical layout pinned via
# byte-trace across `4.ttl` pages 1/2 and `/var/share/drop/first
# title.ttl` page 1 — all four default-valued captions share the same
# 10-byte block immediately after strCaption: `00 00 00 00 00 00 01
# 00 00 00`, decoding to (fWordWrap=0, fAutoSize=0, iAlignment=0,
# fTransparent=1) — exactly the MFC defaults for v=4 captions.
# PX_Bool / PX_Long here use 2-byte VARIANT_BOOL / 2-byte short for
# the first three slots and a 4-byte LONG for the last:
#   +0x00  u16   fWordWrap       (PX_Bool, default 0)
#   +0x02  u16   fAutoSize       (PX_Bool, default 0)
#   +0x04  u16   iAlignment      (PX_Long via PX_Short pathway, default 0)
#   +0x06  u32   fTransparent    (PX_Long, default 1)
_POST_TEXT_WORD_WRAP_OFF = 0x00
_POST_TEXT_AUTO_SIZE_OFF = 0x02
_POST_TEXT_ALIGNMENT_OFF = 0x04
_POST_TEXT_TRANSPARENT_OFF = 0x06
_POST_TEXT_SIZE = 0x0A

_ATTR_ITALIC = 0x02
_ATTR_UNDERLINE = 0x04
_ATTR_STRIKEOUT = 0x08


def _decode_label_persist(
    buf: bytes,
    font_off: int,
) -> dict:
    """Walk the CLabelCtrl persist stream from a StdFont CLSID anchor.

    Returns a dict of all decoded fields. Bounds-checked: when the buf
    truncates before a field, that field is set to its MFC default.
    Caller seeds non-decoded fields (post-strCaption) with their MFC
    defaults — see CaptionControl docstring."""
    out: dict = {
        "back_color": 0xC8D0D8,
        "charset": 0,
        "italic": False,
        "underline": False,
        "strikeout": False,
        "weight": 0,
        "size_cy": 0,
        "font_name": "",
        "bevel_width": 0,
        "frame_style": 0,
        "bevel_hilight": 0xFFFFFF,
        "bevel_shadow": 0,
        "frame_color": 0,
        "id_tag": -1,
        "str_caption": "",
        "word_wrap": False,
        "auto_size": False,
        "alignment": 0,
        "transparent": True,
    }

    # Pre-Font stock prop: back_color (4 B COLORREF inside 6-B
    # font_pre_clsid wrapper). +0x36..+0x3B = `[u8 0][u32 COLORREF][u8 0]`.
    color_off = font_off + _FONT_PRE_CLSID_COLORREF_OFF
    if color_off >= 0 and color_off + 4 <= len(buf):
        out["back_color"] = struct.unpack_from("<I", buf, color_off)[0]

    # Font body — variable length, anchored at font_off + CLSID size.
    body_start = font_off + 16
    if body_start + _FONT_BODY_NAME_LEN_OFF >= len(buf):
        return out
    out["charset"] = struct.unpack_from(
        "<H", buf, font_off + _FONT_BODY_CHARSET_OFF,
    )[0]
    attrs = buf[font_off + _FONT_BODY_ATTRS_OFF]
    out["italic"] = bool(attrs & _ATTR_ITALIC)
    out["underline"] = bool(attrs & _ATTR_UNDERLINE)
    out["strikeout"] = bool(attrs & _ATTR_STRIKEOUT)
    out["weight"] = struct.unpack_from(
        "<H", buf, font_off + _FONT_BODY_WEIGHT_OFF,
    )[0]
    out["size_cy"] = struct.unpack_from(
        "<I", buf, font_off + _FONT_BODY_CY_LO_OFF,
    )[0]
    nlen = buf[font_off + _FONT_BODY_NAME_LEN_OFF]
    name_off = font_off + _FONT_BODY_NAME_OFF
    if name_off + nlen > len(buf):
        return out
    out["font_name"] = buf[name_off:name_off + nlen].decode(
        "ascii", errors="replace",
    )

    # Border + idTag + strCaption — pinned positionally.
    post_name = name_off + nlen
    if post_name + 0x18 > len(buf):
        return out
    out["bevel_width"] = struct.unpack_from(
        "<i", buf, post_name + _BORDER_BEVEL_WIDTH_OFF,
    )[0]
    out["frame_style"] = struct.unpack_from(
        "<i", buf, post_name + _BORDER_FRAME_STYLE_OFF,
    )[0]
    out["bevel_hilight"] = struct.unpack_from(
        "<I", buf, post_name + _BORDER_BEVEL_HILIGHT_OFF,
    )[0]
    out["bevel_shadow"] = struct.unpack_from(
        "<I", buf, post_name + _BORDER_BEVEL_SHADOW_OFF,
    )[0]
    out["frame_color"] = struct.unpack_from(
        "<I", buf, post_name + _BORDER_FRAME_COLOR_OFF,
    )[0]
    out["id_tag"] = struct.unpack_from(
        "<i", buf, post_name + _CLABEL_ID_TAG_OFF,
    )[0]

    text_off = post_name + _CLABEL_STR_CAPTION_OFF
    if text_off >= len(buf):
        return out
    cap_len = buf[text_off]
    text_start = text_off + 1
    text_end = min(text_start + cap_len, len(buf))
    out["str_caption"] = buf[text_start:text_end].decode(
        "ascii", errors="replace",
    )

    # Post-strCaption fields. Block size = 0x0A, fits exactly into the
    # 10-byte slot between strCaption end and the next descriptor's
    # pre-Font region (or, in single-Caption pages, the form trailer).
    post_text = text_end
    if post_text + _POST_TEXT_SIZE > len(buf):
        return out
    out["word_wrap"] = bool(struct.unpack_from(
        "<H", buf, post_text + _POST_TEXT_WORD_WRAP_OFF,
    )[0])
    out["auto_size"] = bool(struct.unpack_from(
        "<H", buf, post_text + _POST_TEXT_AUTO_SIZE_OFF,
    )[0])
    out["alignment"] = struct.unpack_from(
        "<H", buf, post_text + _POST_TEXT_ALIGNMENT_OFF,
    )[0]
    out["transparent"] = bool(struct.unpack_from(
        "<I", buf, post_text + _POST_TEXT_TRANSPARENT_OFF,
    )[0])

    return out


def _decode_caption(
    desc: _SiteDescriptor,
    property_block: bytes,
    shared_record_buf: bytes | None = None,
    shared_record_off: int | None = None,
) -> CaptionControl:
    """Caption1 decoder. Rect from `inline_tail[0..16]`; everything else
    walked from the StdFont CLSID landmark via `_decode_label_persist`.

    Multi-Caption pages: BBDESIGN concatenates per-caption records into
    the LAST descriptor's `inline_tail`. `_caption_record_offsets` locates
    each caption's CLSID in shared buffer; passes the (buf, off) pair as
    `shared_record_buf` / `shared_record_off`. Single-Caption pages: the
    descriptor's own inline_tail carries the full persist; the decoder
    scans for the StdFont CLSID landmark there."""
    buf = desc.inline_tail
    if len(buf) < 16:
        return CaptionControl(
            seq=desc.seq, flags=desc.flags, name=desc.name,
            text="", font_name="", size_pt=0, weight=0,
            rect_himetric=(0, 0, 0, 0),
        )
    rect = struct.unpack_from("<iiii", buf, 0x00)

    if shared_record_buf is not None and shared_record_off is not None:
        font_buf = shared_record_buf
        font_off = shared_record_off
    else:
        for src in (buf, property_block):
            off = src.find(_STDFONT_CLSID)
            if off >= 0:
                font_buf = src
                font_off = off
                break
        else:
            return CaptionControl(
                seq=desc.seq, flags=desc.flags, name=desc.name,
                text="", font_name="", size_pt=0, weight=0,
                rect_himetric=rect,
            )

    fields = _decode_label_persist(font_buf, font_off)
    # `color_rgb` legacy field: previous offset (`font_off - 9`) hit a
    # zero region for default captions and the COLORREF low bytes for
    # explicitly-colored ones. New offset reads the full COLORREF inside
    # the 6-B font_pre_clsid wrapper. Both fields kept so any existing
    # text-rendering caller has the same value semantic (0 for default).
    legacy_color = 0
    if font_off >= 9:
        legacy_color = struct.unpack_from("<I", font_buf, font_off - 9)[0]
    return CaptionControl(
        seq=desc.seq,
        flags=desc.flags,
        name=desc.name,
        text=fields["str_caption"],
        font_name=fields["font_name"],
        size_pt=fields["size_cy"] // 10000,
        weight=fields["weight"],
        rect_himetric=rect,
        italic=fields["italic"],
        underline=fields["underline"],
        strikeout=fields["strikeout"],
        charset=fields["charset"],
        back_color=fields["back_color"],
        bevel_width=fields["bevel_width"],
        frame_style=fields["frame_style"],
        bevel_hilight=fields["bevel_hilight"],
        bevel_shadow=fields["bevel_shadow"],
        frame_color=fields["frame_color"],
        id_tag=fields["id_tag"],
        word_wrap=fields["word_wrap"],
        auto_size=fields["auto_size"],
        alignment=fields["alignment"],
        transparent=fields["transparent"],
        color_rgb=legacy_color,
    )


def _decode_compound(
    desc: _SiteDescriptor,
    ctor: type[_CompoundControl],
    property_block: bytes,
) -> _CompoundControl:
    """Compound BBCTL decoder. Names ≤ 7 chars get NUL-padded to 8 B in
    the name field; (x_twips, y_twips) read at the first 4-byte-aligned
    offset within inline_tail. Other property fields TBD — carried as
    `raw_block` (the seq-ordered slice from the property region) until
    BBCTL.OCX persist functions are RE'd."""
    buf = desc.inline_tail
    base = 1 if buf[:1] == b"\x00" else 0
    if len(buf) >= base + 8:
        x_twips, y_twips = struct.unpack_from("<ii", buf, base)
    else:
        x_twips, y_twips = 0, 0
    return ctor(
        seq=desc.seq,
        flags=desc.flags,
        name=desc.name,
        xy_twips=(x_twips, y_twips),
        raw_block=bytes(property_block) or bytes(buf),
    )


def _decode_unknown(desc: _SiteDescriptor, property_block: bytes) -> UnknownControl:
    return UnknownControl(
        seq=desc.seq,
        flags=desc.flags,
        name=desc.name,
        raw_block=bytes(property_block) or bytes(desc.inline_tail),
        clsid=desc.clsid,
    )


# Site-class name → compound-control ctor (None = Caption, dispatched
# via `_decode_caption`). Used both for CLSID-anchored dispatch (via
# `_BBCTL_CLSIDS` → site-class name → this map) and name-prefix
# fallback. Prefix dispatch is order-sensitive: CaptionButton must be
# checked before Caption.
_BBCTL_CTOR: dict[str, type[_CompoundControl] | None] = {
    "Story": StoryControl,
    "Caption": None,                                       # handled by _decode_caption
    "Audio": AudioControl,
    "CaptionButton": CaptionButtonControl,
    "Outline": OutlineControl,
    "Shortcut": ShortcutControl,
}

_NAME_PREFIX_ORDER: tuple[str, ...] = (
    "CaptionButton", "Caption", "Story", "Audio", "Outline", "Shortcut",
)


def _slice_property_region(
    descriptors: tuple[_SiteDescriptor, ...],
) -> dict[int, bytes]:
    """Slice the per-control property region from the LAST descriptor's
    `inline_tail`. Blocks are concatenated in seq order, each `size_i`
    bytes (per plan finding 1, descriptor `size` = property-block
    length). When the combined total exceeds the available bytes (i.e.
    collapsed single-Caption page where the inline tail IS the property
    block), this function returns empty blocks so decoders fall through
    to inline parsing."""
    if not descriptors:
        return {}
    available = descriptors[-1].inline_tail
    total = sum(d.size for d in descriptors)
    if total > len(available):
        return {d.seq: b"" for d in descriptors}
    blocks: dict[int, bytes] = {}
    pos = 0
    for desc in sorted(descriptors, key=lambda d: d.seq):
        blocks[desc.seq] = bytes(available[pos:pos + desc.size])
        pos += desc.size
    return blocks


def _dispatch_class(desc: _SiteDescriptor) -> str | None:
    """Resolve a site to a BBCTL class name. CLSID lookup wins
    (authoritative — pinned in BBCTL.OCX); name-prefix fallback is for
    descriptors where the form's class table is missing or the CLSID
    isn't recognised (e.g. non-BBCTL embeds)."""
    if desc.clsid is not None:
        cls = _BBCTL_CLSIDS.get(desc.clsid)
        if cls is not None:
            return cls
    for prefix in _NAME_PREFIX_ORDER:
        if desc.name.startswith(prefix):
            return prefix
    return None


def _decode_descriptor(
    desc: _SiteDescriptor,
    property_block: bytes,
    shared_record_buf: bytes | None = None,
    shared_record_off: int | None = None,
) -> Control:
    cls = _dispatch_class(desc)
    if cls is None:
        return _decode_unknown(desc, property_block)
    ctor = _BBCTL_CTOR[cls]
    if ctor is None:
        return _decode_caption(
            desc, property_block, shared_record_buf, shared_record_off,
        )
    return _decode_compound(desc, ctor, property_block)


def _caption_record_offsets(
    descriptors: tuple[_SiteDescriptor, ...],
) -> tuple[bytes | None, dict[int, int]]:
    """Locate per-caption StdFont CLSID anchors in the multi-caption
    shared record buffer.

    BBDESIGN packs each caption's font + text record at offset 60 from
    its record start, with records concatenated in seq order inside
    the LAST descriptor's `inline_tail`. Mapping caption seq → CLSID
    offset lets `_decode_caption` read each caption's own record
    instead of every caption falling back to the first CLSID hit.

    Returns `(shared_buf, {seq: clsid_offset})`. `shared_buf` is the
    LAST descriptor's `inline_tail`; `clsid_offsets` is empty when
    there's at most one caption (single-record pages use the existing
    `_decode_caption` fallback)."""
    caption_descs = [d for d in descriptors if _dispatch_class(d) == "Caption"]
    if len(caption_descs) < 2 or not descriptors:
        return (None, {})
    shared_buf = descriptors[-1].inline_tail
    offsets: dict[int, int] = {}
    pos = 0
    for desc in sorted(caption_descs, key=lambda d: d.seq):
        hit = shared_buf.find(_STDFONT_CLSID, pos)
        if hit < 0:
            break
        offsets[desc.seq] = hit
        pos = hit + len(_STDFONT_CLSID)
    return (shared_buf, offsets)


def _decode_controls(raw: bytes) -> tuple[Control, ...]:
    descriptors = _walk_cbform(raw)
    blocks = _slice_property_region(descriptors)
    shared_buf, clsid_offsets = _caption_record_offsets(descriptors)
    return tuple(
        _decode_descriptor(
            d, blocks.get(d.seq, b""),
            shared_buf, clsid_offsets.get(d.seq),
        )
        for d in descriptors
    )


# Handle scheme: high 11 bits = storage table id, low 21 bits = slot
# index. Empirically: CBForm.embedded_vform handle 0xc00000 → table 6
# slot 0 (msn_today/4.ttl); handle 0xe00000 → table 7 slot 0 (showcase
# first title.ttl). Decode pattern confirmed against `\x03handles`
# entries that map back to known objects.
def _handle_to_storage_slot(handle: int) -> tuple[int, int]:
    return (handle >> 21, handle & ((1 << 21) - 1))


def _resolve_cvform_handle(cbform_body: bytes, handles: tuple[int, ...]) -> int | None:
    """Pull CBForm.embedded_vform handle index from the on-disk record
    (CBForm v2: `[version][u8 form_name_len][name][u8 form_mode]
    [u8 embedded_vform_present][u32 handle_idx]...`) and resolve via
    `handles`. Returns None when the page carries no embedded VForm."""
    if not cbform_body or cbform_body[0] != 0x02:
        return None
    form_name_len = cbform_body[1]
    pos = 2 + form_name_len
    if pos + 2 + 4 > len(cbform_body):
        return None
    # pos = form_mode, pos+1 = embedded_vform_present
    if cbform_body[pos + 1] != 0x01:
        return None
    idx = struct.unpack_from("<I", cbform_body, pos + 2)[0]
    return resolve_swizzle(idx, handles)


# ---------------------------------------------------------------------------
# Section-tree DFS (CTitle → CSection → CBForm)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CBFormRef:
    """One CBForm located inside the section tree, plus the CSection
    that owns it (for content-proxy lookups). `owning_section_path` is
    `(table, slot)` for the CSection (or `None` when the form is hung
    directly off CTitle.base_forms, as in 4.ttl)."""
    table: int
    slot: int
    owning_section_path: tuple[int, int] | None


def _refs_to_paths(refs) -> list[tuple[int, int]]:
    paths: list[tuple[int, int]] = []
    for ref in refs:
        if ref.handle is None:
            continue
        paths.append(_handle_to_storage_slot(ref.handle))
    return paths


def _ole_path(path: tuple[int, int], suffix: str) -> list[str]:
    """OLE stream path for a `(table, slot)` storage with a suffix
    (`\\x03object`, `\\x03handles`, `\\x03properties`). Uses lowercase
    hex per nibble (Blackbird storage naming)."""
    return [ole_storage_id(path[0]), ole_storage_id(path[1]), suffix]


def _read_section(
    ole, handles_by_storage: dict[tuple[int, int], tuple[int, ...]],
    path: tuple[int, int],
) -> SectionRecord:
    section_bytes = ole.openstream(_ole_path(path, "\x03object")).read()
    handles = handles_by_storage.get(path, ())
    return parse_section(section_bytes, handles)


def _enumerate_cbforms(
    ole,
    handles_by_storage: dict[tuple[int, int], tuple[int, ...]],
    base_section: SectionRecord,
) -> list[_CBFormRef]:
    """DFS the CSection tree starting from CTitle.base_section. At each
    node, emit `.forms` in declared order BEFORE recursing into
    `.sections` — this matches the BBDESIGN tree order where a section
    lists its own pages first, then nests subsections.

    Returns an empty list when no forms are reachable (caller falls
    back to the single-CBForm-slot-0 path)."""
    out: list[_CBFormRef] = []

    # CTitle.base_forms (4.ttl single-section variant).
    for table, slot in _refs_to_paths(base_section.forms):
        out.append(_CBFormRef(table=table, slot=slot, owning_section_path=None))

    # CSection tree DFS (msn_today, showcase).
    stack: list[tuple[int, int]] = list(reversed(_refs_to_paths(base_section.sections)))
    visited: set[tuple[int, int]] = set()
    while stack:
        section_path = stack.pop()
        if section_path in visited:
            continue
        visited.add(section_path)
        try:
            section = _read_section(ole, handles_by_storage, section_path)
        except Exception as exc:
            log.info(
                "section_parse path=%d/%d failed=%r",
                section_path[0], section_path[1], exc,
            )
            continue
        for table, slot in _refs_to_paths(section.forms):
            out.append(_CBFormRef(
                table=table, slot=slot, owning_section_path=section_path,
            ))
        for sub_path in reversed(_refs_to_paths(section.sections)):
            stack.append(sub_path)
    return out


# ---------------------------------------------------------------------------
# Story content_proxy_ref chase (heuristic — PR1 only; PR2 replaces)
# ---------------------------------------------------------------------------


# Pascal-prefixed ASCII run: `[u8 pascal_len in 4..127][N printable ASCII]`
# where the greedy `[\x20-\x7e]+` enforces a clean non-printable boundary
# after the run.
_PASCAL_NAME_RE = re.compile(
    rb"([\x04-\x7f])([\x20-\x7e]{4,127})",
)


def _extract_proxy_name(raw_block: bytes) -> str | None:
    """First Pascal-prefixed ASCII name in `StoryControl.raw_block` whose
    declared length matches the trailing printable run. Empirical against
    msn_today (`\\x0cHomepage.bdf`) + showcase
    (`\\x16Blackbird Document.bdf`). The leading u32 LE before the Pascal
    byte is NOT a length prefix (observed: `0c 00 00 00` in both samples
    regardless of the Pascal name length), so the heuristic doesn't gate
    on it. PR2 replaces with the BBCTL.OCX persist-stream offset."""
    for m in _PASCAL_NAME_RE.finditer(raw_block):
        plen = m.group(1)[0]
        ascii_run = m.group(2)
        if len(ascii_run) != plen:
            continue
        return ascii_run.decode("ascii", errors="replace")
    return None


def _find_textruns_target(
    ole,
    proxy_path: tuple[int, int],
    proxy_handles: tuple[int, ...],
    content_class_table: int,
) -> tuple[int, tuple[int, int]] | None:
    """Walk a CProxyTable's entries and return `(proxy_key, content_path)`
    for the first entry pointing at a CContent stream whose properties
    advertise `type = TextRuns`. Returns None when no TextRuns target
    is present (e.g. msn_today CProxyTable@7/2 holds only the
    ImageProxy WaveletImage)."""
    proxy_body = ole.openstream(_ole_path(proxy_path, "\x03object")).read()
    entries = parse_proxy_table(proxy_body, proxy_handles)
    for entry in entries:
        if entry.content_handle is None:
            continue
        c_table, c_slot = _handle_to_storage_slot(entry.content_handle)
        if c_table != content_class_table:
            continue
        try:
            props = _read_properties(ole, c_table, c_slot)
        except (OSError, ValueError):
            continue
        if props.get("type") == "TextRuns":
            return entry.proxy_key, (c_table, c_slot)
    return None


def _chase_story_content(
    ole,
    section_path: tuple[int, int],
    section: SectionRecord,
    handles_by_storage: dict[tuple[int, int], tuple[int, ...]],
    content_class_table: int | None,
    story: StoryControl,
) -> StoryControl:
    """Resolve `StoryControl.content` for one Story.

    Heuristic chain:
    1. Pull a Pascal-prefixed name out of `raw_block` (e.g.
       "Homepage.bdf"). Bail if absent.
    2. Walk `section.contents` (typed CProxyTable refs). For each:
       a. Read its properties — match `name` against the Pascal name.
    3. On match, walk the CProxyTable's entries; pick the first whose
       target CContent has `type == "TextRuns"`.
    4. CK-decompress the CContent body and decode.

    Failures at any step → `content_proxy_ref = None`, `content = None`
    (logged at INFO). PR2 replaces this with the persist-stream offset
    pinned via BBCTL.OCX RE."""
    proxy_name = _extract_proxy_name(story.raw_block)
    if proxy_name is None or content_class_table is None:
        return story

    for ref in section.contents:
        if ref.handle is None:
            continue
        proxy_path = _handle_to_storage_slot(ref.handle)
        try:
            props = _read_properties(ole, proxy_path[0], proxy_path[1])
        except (OSError, ValueError):
            continue
        if props.get("name") != proxy_name:
            continue
        try:
            target = _find_textruns_target(
                ole,
                proxy_path,
                handles_by_storage.get(proxy_path, ()),
                content_class_table,
            )
        except (OSError, ValueError) as exc:
            log.info(
                "story_chase section=%d/%d proxy=%s parse_failed=%r",
                section_path[0], section_path[1], proxy_name, exc,
            )
            return story
        if target is None:
            log.info(
                "story_chase section=%d/%d proxy=%s no_textruns_target",
                section_path[0], section_path[1], proxy_name,
            )
            return story
        proxy_key, content_path = target
        try:
            content_raw = maybe_decompress_ck(
                ole.openstream(_ole_path(content_path, "\x03object")).read(),
            )
            if is_texttree(content_raw):
                log.info(
                    "story_chase section=%d/%d proxy=%s content=%d/%d "
                    "is_texttree=1 deferred",
                    section_path[0], section_path[1], proxy_name,
                    content_path[0], content_path[1],
                )
                return StoryControl(
                    seq=story.seq, flags=story.flags, name=story.name,
                    xy_twips=story.xy_twips, raw_block=story.raw_block,
                    content_proxy_ref=proxy_key, content=None,
                )
            decoded = decode_textruns(content_raw)
        except (OSError, ValueError, NotImplementedError) as exc:
            log.info(
                "story_chase section=%d/%d proxy=%s content=%d/%d decode_failed=%r",
                section_path[0], section_path[1], proxy_name,
                content_path[0], content_path[1], exc,
            )
            return story
        return StoryControl(
            seq=story.seq, flags=story.flags, name=story.name,
            xy_twips=story.xy_twips, raw_block=story.raw_block,
            content_proxy_ref=proxy_key, content=decoded,
        )
    log.info(
        "story_chase section=%d/%d proxy=%s no_matching_proxy_table",
        section_path[0], section_path[1], proxy_name,
    )
    return story


# ---------------------------------------------------------------------------
# load_title
# ---------------------------------------------------------------------------


def _read_properties(ole, table: int, slot: int) -> dict[str, object]:
    """Read `<table>/<slot>/\\x03properties`, strip the CK envelope when
    present (CProxyTable / CContent property streams are MSZIP-wrapped)
    and return the decoded property dict."""
    data = ole.openstream(_ole_path((table, slot), "\x03properties")).read()
    return parse_simple_property_table(maybe_decompress_ck(data))


def _read_page_name(ole, table: int, slot: int) -> str:
    try:
        props = _read_properties(ole, table, slot)
    except (OSError, ValueError):
        return ""
    return str(props.get("name", ""))


def _build_page(
    ole,
    cbform_ref: _CBFormRef,
    handles_by_storage: dict[tuple[int, int], tuple[int, ...]],
    cvform_table: int,
) -> LoadedPage:
    cbform_path = (cbform_ref.table, cbform_ref.slot)
    cbform_body = ole.openstream(_ole_path(cbform_path, "\x03object")).read()
    cbform_handles = handles_by_storage.get(cbform_path, ())
    page = _parse_cvform_page(cbform_body)
    cvform_handle = _resolve_cvform_handle(cbform_body, cbform_handles)
    controls: tuple[Control, ...] = ()
    if cvform_handle is not None:
        v_table, v_slot = _handle_to_storage_slot(cvform_handle)
        if v_table == cvform_table:
            cvform_body_raw = ole.openstream(
                _ole_path((v_table, v_slot), "\x03object"),
            ).read()
            controls = _decode_controls(maybe_decompress_ck(cvform_body_raw))
    return LoadedPage(
        name=_read_page_name(ole, cbform_path[0], cbform_path[1]),
        cbform_table=cbform_path[0],
        cbform_slot=cbform_path[1],
        cvform_handle=cvform_handle,
        page_bg=page.background,
        page_pixel_w=page.width_px,
        page_pixel_h=page.height_px,
        scrollbar_flags=page.scrollbar_flags,
        controls=controls,
    )


def _attach_story_content(
    ole,
    pages: list[LoadedPage],
    cbform_refs: list[_CBFormRef],
    handles_by_storage: dict[tuple[int, int], tuple[int, ...]],
    content_class_table: int | None,
) -> list[LoadedPage]:
    """Replace each page's StoryControl with one carrying the resolved
    content + proxy_ref. Pages whose owning section is unknown
    (CTitle.base_forms case in 4.ttl, where there's no enclosing
    CSection) keep their Stories as-is — there's no proxy table to
    consult."""
    if content_class_table is None:
        return pages
    out: list[LoadedPage] = []
    for page, ref in zip(pages, cbform_refs, strict=True):
        if ref.owning_section_path is None:
            out.append(page)
            continue
        try:
            section = _read_section(
                ole, handles_by_storage, ref.owning_section_path,
            )
        except (OSError, ValueError):
            out.append(page)
            continue
        new_controls: list[Control] = []
        for c in page.controls:
            if isinstance(c, StoryControl):
                new_controls.append(_chase_story_content(
                    ole, ref.owning_section_path, section,
                    handles_by_storage, content_class_table, c,
                ))
            else:
                new_controls.append(c)
        out.append(LoadedPage(
            name=page.name,
            cbform_table=page.cbform_table,
            cbform_slot=page.cbform_slot,
            cvform_handle=page.cvform_handle,
            page_bg=page.page_bg,
            page_pixel_w=page.page_pixel_w,
            page_pixel_h=page.page_pixel_h,
            scrollbar_flags=page.scrollbar_flags,
            controls=tuple(new_controls),
        ))
    return out


def load_title(path: pathlib.Path) -> LoadedTitle | None:
    """Read a `.ttl` and return a LoadedTitle, or None on any failure.

    Storage layout is read from `\\x03type_names_map` so non-stock
    arrangements (e.g. showcase: CSection at table 5, CBForm at 6,
    CVForm at 7) parse without special-casing. Every CBForm reachable
    from CTitle's section tree becomes a `LoadedPage`; order matches
    BBDESIGN's tree-view (forms-of-this-section before sub-sections).
    """
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:
        log.info("load_title path=%s open_failed=%r", path, exc)
        return None
    try:
        type_map = parse_type_names_map(
            ole.openstream("\x03type_names_map").read(),
        )
        class_to_table = {name: tid for tid, name in type_map.items()}
        required = {"CTitle", "CBFrame", "CStyleSheet", "CBForm", "CVForm"}
        missing = required - class_to_table.keys()
        if missing:
            raise ValueError(f"type_names_map missing classes: {sorted(missing)}")

        title_table = class_to_table["CTitle"]
        bframe_path = (class_to_table["CBFrame"], 0)
        css_path = (class_to_table["CStyleSheet"], 0)
        cvform_table = class_to_table["CVForm"]
        content_class_table = class_to_table.get("CContent")

        title_name = _parse_title_name(
            ole.openstream(_ole_path((title_table, 0), "\x03properties")).read(),
        )
        caption, rect = _parse_cbframe(
            ole.openstream(_ole_path(bframe_path, "\x03object")).read(),
        )
        font_table = _parse_cstylesheet(
            maybe_decompress_ck(
                ole.openstream(_ole_path(css_path, "\x03object")).read(),
            ),
        )

        handles_by_storage = parse_handles_by_storage(ole)

        # CTitle object is `[u8 title_version][CSection payload]
        # [u32 resource_idx][CCount shortcut][MFC ansi trailing_name]`.
        # `parse_section` only consumes the CSection payload; the title
        # tail bytes are ignored here.
        title_obj = ole.openstream(_ole_path((title_table, 0), "\x03object")).read()
        if not title_obj:
            raise ValueError("empty CTitle object stream")
        title_handles = handles_by_storage.get((title_table, 0), ())
        base_section = parse_section(title_obj[1:], title_handles)

        cbform_refs = _enumerate_cbforms(ole, handles_by_storage, base_section)
        if not cbform_refs:
            # Fall back to slot-0 CBForm (titles that don't list any
            # form anywhere in the section tree — defensive only;
            # 4.ttl / msn_today / showcase all populate the tree).
            cbform_table = class_to_table["CBForm"]
            cbform_refs = [_CBFormRef(
                table=cbform_table, slot=0, owning_section_path=None,
            )]

        pages = [
            _build_page(ole, ref, handles_by_storage, cvform_table)
            for ref in cbform_refs
        ]
        pages = _attach_story_content(
            ole, pages, cbform_refs, handles_by_storage, content_class_table,
        )
    except Exception as exc:
        log.info("load_title path=%s parse_failed=%r", path, exc)
        return None
    finally:
        ole.close()

    left, top, width, height = rect
    return LoadedTitle(
        title_name=title_name,
        caption=caption,
        window_rect=(left, top, width, height),
        font_table=font_table,
        pages=tuple(pages),
    )


# --------------------------------------------------------------------------
# Lowering: LoadedTitle → 9-section title body
# --------------------------------------------------------------------------

_SEC0_HEADER_SIZE = 0x12
_SEC0_FACE_ENTRY_SIZE = 0x20
_SEC0_DESCRIPTOR_SIZE = 0x2A
_SEC0_POINTER_ENTRY_SIZE = 0x04

_SEC06_RECORD_SIZE = 0x98
# Bit 0x08 = inner-pane rect at +0x80..+0x8F is absolute pixels.
# Bit 0x40 = NSR y-anchor (NavigateMosViewPane: NSR.+0x9c = 1 → NSR pinned
# to the bottom of the union, SR claims the top — i.e. SR.top = (0, 0).
# CreateMosViewWindowHierarchy@0x7f3c6b32, NavigateMosViewPane@0x7f3c3670.
_SEC06_FLAG_INNER_RECT_ABSOLUTE = 0x08
_SEC06_FLAG_NSR_ANCHOR_BOTTOM = 0x40
_SEC06_RECT_INHERIT = (-1, -1, -1, -1)
# u16 size field on section 3 caps total record count at this many.
_SEC06_MAX_RECORDS = 0xFFFF // _SEC06_RECORD_SIZE


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


def _resolve_face_slot(font_name: str, font_table: tuple[FaceEntry, ...]) -> int:
    target = font_name.casefold()
    for face in font_table:
        if face.face_name.casefold() == target:
            return face.slot
    return 0


def _title_captions(title: LoadedTitle) -> tuple[CaptionControl, ...]:
    """All CaptionControls across every page, in page order. Used by
    section 0 — the font/style table needs one descriptor per Caption
    (regardless of which page it lives on)."""
    return tuple(
        cap
        for page in title.pages
        for cap in page.captions
    )


def _build_section0(title: LoadedTitle) -> bytes:
    face_count = max((f.slot for f in title.font_table), default=-1) + 1
    face_table = bytearray(face_count * _SEC0_FACE_ENTRY_SIZE)
    for face in title.font_table:
        encoded = face.face_name.encode("ascii", errors="replace")
        off = face.slot * _SEC0_FACE_ENTRY_SIZE
        face_table[off:off + len(encoded)] = encoded

    captions = _title_captions(title)
    descriptors = bytearray()
    for cap in captions:
        face_slot = _resolve_face_slot(cap.font_name, title.font_table)
        descriptor = bytearray(_SEC0_DESCRIPTOR_SIZE)
        struct.pack_into("<HHH", descriptor, 0x00, face_slot, 0, 0)
        # +0x06 text_color (3 B BGR0-LE-low-3), +0x09 back_color (3 B).
        # text_color carries `cap.color_rgb` (legacy field reads the
        # COLORREF at `font_off - 9`, which is 0 for default captions
        # and the explicit color for authored ones — e.g. Caption 2
        # in `4.ttl` page 0 reads as red). back_color carries the
        # full COLORREF at `font_off - 5` (BackColor stock prop).
        descriptor[0x06] = cap.color_rgb & 0xFF
        descriptor[0x07] = (cap.color_rgb >> 8) & 0xFF
        descriptor[0x08] = (cap.color_rgb >> 16) & 0xFF
        descriptor[0x09] = cap.back_color & 0xFF
        descriptor[0x0A] = (cap.back_color >> 8) & 0xFF
        descriptor[0x0B] = (cap.back_color >> 16) & 0xFF
        struct.pack_into(
            "<iiiii",
            descriptor,
            0x0C,
            -cap.size_pt,
            0,
            0,
            0,
            cap.weight,
        )
        descriptor[0x20] = 1 if cap.italic else 0           # lfItalic
        descriptor[0x21] = 1 if cap.underline else 0        # lfUnderline
        descriptor[0x22] = 1 if cap.strikeout else 0        # lfStrikeOut
        descriptor[0x23] = cap.charset & 0xFF               # lfCharSet
        descriptors += descriptor

    pointer_table = b"\x00" * (face_count * _SEC0_POINTER_ENTRY_SIZE)

    face_off = _SEC0_HEADER_SIZE
    descriptor_off = face_off + len(face_table)
    pointer_off = descriptor_off + len(descriptors)

    descriptor_count = len(captions) if captions else 0xFFFF

    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                                                 # +0x00 reserved
        descriptor_count,
        face_off,
        descriptor_off,
        0,                                                 # +0x08 override_count
        pointer_off,
        0,                                                 # +0x0C reserved
    )
    struct.pack_into("<H", header, 0x10, pointer_off)
    return bytes(header) + bytes(face_table) + bytes(descriptors) + pointer_table


def _scrollbar_flags_to_sec06_flag(scrollbar_flags: int) -> int:
    """Map CVForm Page `scrollbar_flags` (bit0=H, bit1=V) to the sec06
    `+0x48` byte. Empirical rules pinned via SoftIce on MOSVIEW
    NavigateMosViewPane:

    - `0` (no scrollbars): set INNER_RECT_ABSOLUTE | NSR_ANCHOR_BOTTOM
      to suppress the scroll-region pane (NSR claims the full content).
    - `2` (V): clear NSR_ANCHOR_BOTTOM — SR pane is sized normally so
      the engine renders its vertical scrollbar.
    - `3` (V|H): V dominates; MOSVIEW doesn't model H, treat as V.
    - `1` (H only): MOSVIEW ignores H entirely; log + degrade to V-mode.
    """
    if scrollbar_flags == 0:
        return _SEC06_FLAG_INNER_RECT_ABSOLUTE | _SEC06_FLAG_NSR_ANCHOR_BOTTOM
    if scrollbar_flags & 0x02:                             # V (or V|H)
        return _SEC06_FLAG_INNER_RECT_ABSOLUTE
    if scrollbar_flags & 0x01:                             # H only — degrade to V
        log.info(
            "scrollbar_flags=H_only is unmodeled by MOSVIEW; degrading to V",
        )
        return _SEC06_FLAG_INNER_RECT_ABSOLUTE
    return _SEC06_FLAG_INNER_RECT_ABSOLUTE | _SEC06_FLAG_NSR_ANCHOR_BOTTOM


def _build_sec06_record(page: LoadedPage, title: LoadedTitle) -> bytes:
    """One sec06 record per `LoadedPage`. Caption / window position come
    from the title-level CBFrame; geometry / colors / scrollbar flag
    come from the page. `outer_rect` (left, top) is the desktop window
    position; (w, h) is the authored content size — chrome is added by
    the engine's compensation helper."""
    record = bytearray(_SEC06_RECORD_SIZE)
    caption_bytes = title.caption.encode("ascii", errors="replace") + b"\x00"
    record[0x15:0x15 + len(caption_bytes)] = caption_bytes
    record[0x48] = _scrollbar_flags_to_sec06_flag(page.scrollbar_flags)
    left, top, _, _ = title.window_rect
    struct.pack_into(
        "<iiii", record, 0x49, left, top, page.page_pixel_w, page.page_pixel_h,
    )
    struct.pack_into("<I", record, 0x5B, page.page_bg)
    struct.pack_into("<II", record, 0x78, page.page_bg, page.page_bg)
    struct.pack_into("<iiii", record, 0x80, *_SEC06_RECT_INHERIT)
    return bytes(record)


_TITLE_DEID_PLACEHOLDER = b"00000000-0000-0000-0000-000000000000\x00"


def lower_to_payload(title: LoadedTitle) -> bytes:
    """Assemble the 9-section TitleOpen body for a LoadedTitle.

    Section 3 carries one sec06 window-scaffold record per `LoadedPage`
    (each 152 B). Caps at `_SEC06_MAX_RECORDS` (430) since section 3's
    u16 length prefix bounds total bytes.
    """
    if len(title.pages) > _SEC06_MAX_RECORDS:
        raise ValueError(
            f"title has {len(title.pages)} pages; sec06 record table "
            f"caps at {_SEC06_MAX_RECORDS}",
        )
    section0 = _build_section0(title)
    sec06 = b"".join(_build_sec06_record(p, title) for p in title.pages)
    caption_text = (title.caption or title.title_name).encode(
        "ascii", errors="replace",
    ) + b"\x00"
    return b"".join(
        [
            _length_prefixed(section0),
            b"\x00\x00",
            b"\x00\x00",
            _length_prefixed(sec06),
            _length_prefixed(caption_text),
            b"\x00\x00",
            _length_prefixed(_TITLE_DEID_PLACEHOLDER),
            b"\x00\x00",
            b"\x00\x00",
        ]
    )


# --------------------------------------------------------------------------
# Lowering: LoadedTitle → bm0 baggage container
# --------------------------------------------------------------------------

# BBCTL Caption stores rects in HIMETRIC (0.01mm per unit). The
# conversion at 96 DPI is `pixels = himetric * 96 / 2540` — 1 inch =
# 25.4 mm = 2540 HIMETRIC units.
_HIMETRIC_PER_INCH = 2540


def _himetric_to_pixels(himetric: int) -> int:
    return (himetric * 96) // _HIMETRIC_PER_INCH


def _empty_kind5_raster(width: int, height: int) -> bytes:
    pixel_byte_count = (width * height) // 8
    raster = build_kind5_raster(
        width=width,
        height=height,
        bpp=1,
        pixel_data=b"\xFF" * pixel_byte_count,
        trailer=build_trailer([], b""),
    )
    return build_baggage_container(raster)


def _twips_to_pixels(twips: int) -> int:
    """Twips → pixels at 96 DPI: 1 inch = 1440 twips = 96 pixels."""
    return (twips * 96) // 1440


def build_bm_baggage(page: LoadedPage, font_table: tuple[FaceEntry, ...]) -> bytes:
    """Per-page baggage container.

    Sources:
    - CaptionControl text: rect_himetric → pixel coords, drawn via the
      kind=8 WMF TextOut path.
    - StoryControl content (TextRuns body resolved by PR1's chase):
      placed at the Story's `xy_twips → pixels` top-left, single string.

    Pages without any caption or resolved Story text fall back to the
    kind=5 1bpp white raster sized to the page. The kind=5 + authored
    trailer attempt (rolled back 2026-05-13) caused the engine to hang
    post-`MVBuildLayoutLine`; kind=8 stays the working baseline. PR3
    extends kind=8 to carry per-page Story text alongside captions.

    UNVERIFIED: per-page bm baggage emission is structural — 86Box
    verification deferred to a follow-up pass. The naming convention
    `bm<idx>` is pinned via MVCL14N `wsprintfA("|bm%d", idx)` in
    HfcStartCacheFetch.
    """
    items: list[TextItem] = []

    for cap in page.captions:
        left = _himetric_to_pixels(cap.rect_himetric[0])
        top = _himetric_to_pixels(cap.rect_himetric[1])
        right = _himetric_to_pixels(cap.rect_himetric[2])
        bottom = _himetric_to_pixels(cap.rect_himetric[3])
        items.append(TextItem(
            x=left,
            y=top,
            text=cap.text,
            font_face=cap.font_name or "Times New Roman",
            font_height=-(cap.size_pt * 96 // 72) if cap.size_pt else -16,
            font_weight=cap.weight or 400,
            italic=cap.italic,
            underline=cap.underline,
            strikeout=cap.strikeout,
            charset=cap.charset,
            color_rgb=cap.color_rgb,
            back_color=cap.back_color,
            transparent=cap.transparent,
            alignment=cap.alignment,
            rect_w=max(0, right - left),
            rect_h=max(0, bottom - top),
            bevel_width=cap.bevel_width,
            bevel_hilight=cap.bevel_hilight,
            bevel_shadow=cap.bevel_shadow,
            frame_style=cap.frame_style,
            frame_color=cap.frame_color,
            word_wrap=cap.word_wrap,
            auto_size=cap.auto_size,
        ))

    for c in page.controls:
        if isinstance(c, StoryControl) and c.content is not None and c.content.text:
            face = font_table[0].face_name if font_table else "Times New Roman"
            items.append(TextItem(
                x=_twips_to_pixels(c.xy_twips[0]),
                y=_twips_to_pixels(c.xy_twips[1]),
                text=c.content.text,
                font_face=face,
                font_height=-16,
                font_weight=400,
            ))

    if not items:
        return _empty_kind5_raster(page.page_pixel_w, page.page_pixel_h)

    metafile = build_text_metafile(items)
    return build_baggage_container(
        build_kind8_baggage(
            metafile,
            mapmode=1,
            viewport_w=page.page_pixel_w,
            viewport_h=page.page_pixel_h,
        )
    )


def build_all_bm_baggage(title: LoadedTitle) -> dict[str, bytes]:
    """Per-title baggage map: `{f"bm{i}": baggage_bytes for i, page}`.
    Handler keys baggage requests by the canonical name extracted from
    the engine's `wsprintfA("|bm%d", idx)` probe."""
    return {
        f"bm{i}": build_bm_baggage(page, title.font_table)
        for i, page in enumerate(title.pages)
    }


def build_bm0_baggage(title: LoadedTitle) -> bytes:
    """Compatibility shim — page-0 baggage. Callers that need per-page
    baggage should use `build_all_bm_baggage`. Retained for the empty-
    title fallback path and existing handler bring-up code; PR3+1
    follow-up will retire this entry point."""
    return build_all_bm_baggage(title)["bm0"]
