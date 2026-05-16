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
    """Caption1: read-only static text. Rect/font/size pulled inline
    from the descriptor; pinned via `docs/cvform-page-objects.md`
    §Caption1 against 4.ttl + showcase Caption1."""
    text: str
    font_name: str
    size_pt: int                             # font_size_cy_lo // 10000
    weight: int                              # 400 = FW_NORMAL
    rect_himetric: tuple[int, int, int, int] # (L, T, R, B) HIMETRIC (0.01mm)


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
    """BBDESIGN-authored title. `pages` is in BBDESIGN tree order; PR1
    callers can still treat the title as page-0 only via the backcompat
    properties (delegating to `pages[0]`). PR3 removes the shims and
    lifts `lower_to_payload` / `build_bm0_baggage` to per-page emission."""
    title_name: str                          # CTitle properties["name"]
    caption: str                             # CBFrame caption — host window title
    window_rect: tuple[int, int, int, int]   # CBFrame (left, top, width, height) pixels
    font_table: tuple[FaceEntry, ...]
    pages: tuple[LoadedPage, ...] = field(default_factory=tuple)

    @property
    def _page0(self) -> LoadedPage:
        return self.pages[0]

    @property
    def page_bg(self) -> int:
        return self._page0.page_bg

    @property
    def page_pixel_w(self) -> int:
        return self._page0.page_pixel_w

    @property
    def page_pixel_h(self) -> int:
        return self._page0.page_pixel_h

    @property
    def scrollbar_flags(self) -> int:
        return self._page0.scrollbar_flags

    @property
    def controls(self) -> tuple[Control, ...]:
        return self._page0.controls

    @property
    def captions(self) -> tuple[CaptionControl, ...]:
        return self._page0.captions


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


def _walk_cbform(raw: bytes) -> tuple[_SiteDescriptor, ...]:
    """Walk site descriptors in a CVForm (Form preamble at +0x00, sites
    starting at +0x28). Each descriptor produces a `_SiteDescriptor`
    with `inline_tail` carrying bytes up to the next site (or to the
    trailing form CLSID at end of file).

    Each descriptor's `flags & 0xFF` indexes into the CVForm preamble's
    class table (parsed via `_parse_cvform_class_table`) to resolve a
    16-B BBCTL class CLSID. CLSID-first dispatch + name-prefix fallback
    happens in `_decode_descriptor`."""
    trailer_off = raw.find(_FORM_CLSID_PREFIX, _FORM_PREAMBLE_END + 4)
    end_of_list = trailer_off if trailer_off >= 0 else len(raw)
    class_table = _parse_cvform_class_table(raw)

    records: list[tuple[int, int, int, str, int, int]] = []
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
        name_off = seq_off + 16
        name_end = name_off
        while name_end < end_of_list and 0x20 <= raw[name_end] < 0x7F:
            name_end += 1
        name = raw[name_off:name_end].decode("ascii", errors="replace")
        records.append((seq, flags, size, name, seq_off, name_end))
        pos = name_end + 1

    descriptors: list[_SiteDescriptor] = []
    for idx, (seq, flags, size, name, seq_off, name_end) in enumerate(records):
        next_start = (
            records[idx + 1][4] if idx + 1 < len(records) else end_of_list
        )
        class_index = flags & 0xFF
        clsid = (
            class_table[class_index]
            if 0 <= class_index < len(class_table)
            else None
        )
        # inline_tail spans name_end..next_start. Names ≤ 7 chars carry a
        # trailing NUL pad; 8-char names (e.g. "Caption1") sit flush against
        # the inline data with no separator. Decoders that depend on the
        # first byte being substantive (Caption: rect) probe by name.
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


def _decode_caption(desc: _SiteDescriptor, property_block: bytes) -> CaptionControl:
    """Caption1 decoder. Rect read from `inline_tail[0..16]`; font/text
    parsed from the StdFont CLSID landmark forward.

    Collapsed format (e.g. 4.ttl, single-Caption pages): everything is
    inline — `property_block` is empty and the StdFont CLSID lives
    inside `inline_tail`. Separate format (showcase: Caption alongside
    Story/Audio/etc.): only the 28-B inline "small tail" carries rect +
    site metadata; font/text live in `property_block`. Decoder scans
    both buffers for the CLSID and parses font/text relative to its
    position.

    When CLSID is absent (block truncated / format not yet RE'd), the
    Control falls back to rect-only with empty font/text — the lowering
    helpers tolerate empty strings."""
    buf = desc.inline_tail
    if len(buf) < 16:
        return CaptionControl(
            seq=desc.seq, flags=desc.flags, name=desc.name,
            text="", font_name="", size_pt=0, weight=0,
            rect_himetric=(0, 0, 0, 0),
        )
    rect = struct.unpack_from("<iiii", buf, 0x00)

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

    # font_off points at the 16-B StdFont CLSID; layout from there is
    # `[16 CLSID][1 version][3 charset/flags][2 weight][4 size_cy_lo]
    # [1 namelen][N namebytes][2 pad][22 trailer_constants][1 textlen]
    # [M textbytes][1 NUL]`. Separate-format Caption blocks (showcase)
    # truncate at the trailer_constants — text lives further into the
    # property region than `size_i` advertises; text decoding is best-
    # effort with bounds checks.
    weight = struct.unpack_from("<H", font_buf, font_off + 0x14)[0]
    size_cy = struct.unpack_from("<I", font_buf, font_off + 0x16)[0]
    nlen = font_buf[font_off + 0x1A]
    font_name = font_buf[font_off + 0x1B:font_off + 0x1B + nlen].decode(
        "ascii", errors="replace",
    )
    text_off = font_off + 0x1B + nlen + 24
    text = ""
    if text_off < len(font_buf):
        cap_len = font_buf[text_off]
        text = font_buf[text_off + 1:text_off + 1 + cap_len].decode(
            "ascii", errors="replace",
        )
    return CaptionControl(
        seq=desc.seq,
        flags=desc.flags,
        name=desc.name,
        text=text,
        font_name=font_name,
        size_pt=size_cy // 10000,
        weight=weight,
        rect_himetric=rect,
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


def _decode_descriptor(desc: _SiteDescriptor, property_block: bytes) -> Control:
    cls = _dispatch_class(desc)
    if cls is None:
        return _decode_unknown(desc, property_block)
    ctor = _BBCTL_CTOR[cls]
    if ctor is None:
        return _decode_caption(desc, property_block)
    return _decode_compound(desc, ctor, property_block)


def _decode_controls(raw: bytes) -> tuple[Control, ...]:
    descriptors = _walk_cbform(raw)
    blocks = _slice_property_region(descriptors)
    return tuple(
        _decode_descriptor(d, blocks.get(d.seq, b""))
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


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


def _resolve_face_slot(font_name: str, font_table: tuple[FaceEntry, ...]) -> int:
    target = font_name.casefold()
    for face in font_table:
        if face.face_name.casefold() == target:
            return face.slot
    return 0


def _build_section0(title: LoadedTitle) -> bytes:
    face_count = max((f.slot for f in title.font_table), default=-1) + 1
    face_table = bytearray(face_count * _SEC0_FACE_ENTRY_SIZE)
    for face in title.font_table:
        encoded = face.face_name.encode("ascii", errors="replace")
        off = face.slot * _SEC0_FACE_ENTRY_SIZE
        face_table[off:off + len(encoded)] = encoded

    descriptors = bytearray()
    for cap in title.captions:
        face_slot = _resolve_face_slot(cap.font_name, title.font_table)
        descriptor = bytearray(_SEC0_DESCRIPTOR_SIZE)
        struct.pack_into("<HHH", descriptor, 0x00, face_slot, 0, 0)
        descriptor[0x06:0x09] = b"\x01\x01\x01"            # text_color = inherit
        descriptor[0x09:0x0C] = b"\x01\x01\x01"            # back_color = inherit
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
        descriptors += descriptor

    pointer_table = b"\x00" * (face_count * _SEC0_POINTER_ENTRY_SIZE)

    face_off = _SEC0_HEADER_SIZE
    descriptor_off = face_off + len(face_table)
    pointer_off = descriptor_off + len(descriptors)

    descriptor_count = len(title.captions) if title.captions else 0xFFFF

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


def _build_sec06_record(title: LoadedTitle) -> bytes:
    record = bytearray(_SEC06_RECORD_SIZE)
    caption_bytes = title.caption.encode("ascii", errors="replace") + b"\x00"
    record[0x15:0x15 + len(caption_bytes)] = caption_bytes
    record[0x48] = _SEC06_FLAG_INNER_RECT_ABSOLUTE | _SEC06_FLAG_NSR_ANCHOR_BOTTOM
    # sec06 outer_rect → CreateMosViewWindowHierarchy passes
    # (left, top, w, h) through ComputeMosViewClientFromAuthoredRect then
    # MoveWindow on the SHELL window; so (left, top) is the desktop
    # position, (w, h) the authored content size (chrome added in by the
    # compensation helper).
    left, top, _, _ = title.window_rect
    struct.pack_into(
        "<iiii", record, 0x49, left, top, title.page_pixel_w, title.page_pixel_h,
    )
    struct.pack_into("<I", record, 0x5B, title.page_bg)
    struct.pack_into("<II", record, 0x78, title.page_bg, title.page_bg)
    struct.pack_into("<iiii", record, 0x80, *_SEC06_RECT_INHERIT)
    return bytes(record)


_TITLE_DEID_PLACEHOLDER = b"00000000-0000-0000-0000-000000000000\x00"


def lower_to_payload(title: LoadedTitle) -> bytes:
    """Assemble the 9-section TitleOpen body for a LoadedTitle.

    PR1 scope: page-0 only — `_build_sec06_record` reads `page_bg`,
    `page_pixel_w`, `page_pixel_h` via the LoadedTitle backcompat shims
    (`pages[0]`). PR3 emits one sec06 record per page."""
    section0 = _build_section0(title)
    sec06 = _build_sec06_record(title)
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


def build_bm0_baggage(title: LoadedTitle) -> bytes:
    """Build the bm0 baggage container for a LoadedTitle.

    With captions: kind=8 WMF with one TextOut per caption (MM_TEXT,
    pixel coords). Without: kind=5 1bpp raster sized to the page.

    Phase-2 kind=5 + authored trailer attempt rolled back 2026-05-13:
    pushing a tag=0x8A child with va=0 caused the engine to hang post-
    `MVBuildLayoutLine` waiting for slot-tag-7 text content we never
    shipped. Reverting to the working kind=8 baseline; revisit once
    MVCL14N is open in Ghidra and the slot-tag-7 text-source path is
    traced.
    """
    if not title.captions:
        return _empty_kind5_raster(title.page_pixel_w, title.page_pixel_h)

    first = title.captions[0]
    items = []
    for cap in title.captions:
        x = _himetric_to_pixels(cap.rect_himetric[0])
        y = _himetric_to_pixels(cap.rect_himetric[1])
        items.append((x, y, cap.text))

    metafile = build_text_metafile(
        items,
        font_face=first.font_name,
        font_height=-(first.size_pt * 96 // 72),
        font_weight=first.weight,
    )
    return build_baggage_container(
        build_kind8_baggage(
            metafile,
            mapmode=1,
            viewport_w=title.page_pixel_w,
            viewport_h=title.page_pixel_h,
        )
    )
