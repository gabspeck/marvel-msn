"""Parse a BBDESIGN-authored `.ttl` and lower its content to MEDVIEW wire.

Scope: shape of `resources/titles/4.ttl` — single page, single Caption
control, one CStyleSheet font block. Anything outside that shape returns
`None` and falls back to the hardcoded MSN Today payload.

Storage IDs (verified empirically against 4.ttl content, not the
`\x03type_names_map` index which appears to mirror the wrong order):
    1 = CTitle, 3 = CBFrame, 4 = CStyleSheet, 5 = CVForm, 6 = CBForm.
"""

from __future__ import annotations

import logging
import pathlib
import struct
import zlib
from dataclasses import dataclass

import olefile

from ...blackbird.wire import (
    build_baggage_container,
    build_kind5_raster,
    build_kind8_baggage,
    build_text_metafile,
    build_trailer,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class FaceEntry:
    slot: int                                # CStyleSheet font key (u16)
    face_name: str                           # LOGFONTA lfFaceName


@dataclass(frozen=True)
class CaptionSite:
    text: str
    font_name: str
    size_pt: int                             # font_size_cy_lo // 10000
    weight: int                              # 400 = FW_NORMAL
    rect_twips: tuple[int, int, int, int]    # (L, T, R, B) per BBCTL Caption


@dataclass(frozen=True)
class LoadedTitle:
    title_name: str                          # CTitle properties["name"]
    caption: str                             # CBFrame caption — host window title
    window_rect: tuple[int, int, int, int]   # CBFrame (left, top, width, height) pixels
    page_bg: int                             # CVForm background COLORREF (u32 LE)
    page_pixel_w: int                        # = window_rect[2]
    page_pixel_h: int                        # = window_rect[3]
    font_table: tuple[FaceEntry, ...]
    captions: tuple[CaptionSite, ...]


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


def _parse_cvform_page_bg(buf: bytes) -> int:
    """CVForm page background COLORREF at +0x10 (u32 LE)."""
    return struct.unpack_from("<I", buf, 0x10)[0]


def _decompress_cbform(buf: bytes) -> bytes:
    """CBForm MSZIP envelope: `[u8 flag=1][u32 uncompressed][u32 compressed]
    [u8 'C'][u8 'K'][deflate stream]`. Returns raw decompressed bytes.
    """
    if buf[0] != 0x01:
        raise ValueError(f"unexpected CBForm flag: {buf[0]}")
    uncompressed_size = struct.unpack_from("<I", buf, 1)[0]
    compressed_size = struct.unpack_from("<I", buf, 5)[0]
    if buf[9:11] != b"CK":
        raise ValueError("missing MSZIP 'CK' magic")
    raw = zlib.decompress(buf[11:11 + compressed_size], -15)
    if len(raw) != uncompressed_size:
        raise ValueError(
            f"decompressed size {len(raw)} != expected {uncompressed_size}"
        )
    return raw


def _parse_caption_site(raw: bytes, marker_off: int) -> CaptionSite | None:
    """Pull a Caption control's (text, font, weight, size, rect) from the
    CBForm body at the given marker offset. Returns None for non-Caption
    sites (Caption / CaptionButton both start with `Caption`; filter the
    button form out)."""
    name_off = marker_off + 12
    name_end = name_off
    while name_end < len(raw) and 0x20 <= raw[name_end] < 0x7F:
        name_end += 1
    name = raw[name_off:name_end].decode("ascii", errors="replace")
    if not name.startswith("Caption") or name.startswith("CaptionButton"):
        return None

    rect = struct.unpack_from("<iiii", raw, name_off + 0x08)

    clsid = raw[name_off + 0x44:name_off + 0x54]
    if clsid != _STDFONT_CLSID:
        raise ValueError(
            f"StdFont CLSID mismatch at offset 0x{name_off + 0x44:x}: "
            f"{clsid.hex()}"
        )

    weight = struct.unpack_from("<H", raw, name_off + 0x58)[0]
    size_cy = struct.unpack_from("<I", raw, name_off + 0x5A)[0]
    size_pt = size_cy // 10000

    nlen = raw[name_off + 0x5E]
    font_name = raw[name_off + 0x5F:name_off + 0x5F + nlen].decode(
        "ascii", errors="replace",
    )

    text_off = name_off + 0x5F + nlen + 24
    cap_len = raw[text_off]
    text = raw[text_off + 1:text_off + 1 + cap_len].decode(
        "ascii", errors="replace",
    )

    return CaptionSite(
        text=text,
        font_name=font_name,
        size_pt=size_pt,
        weight=weight,
        rect_twips=rect,
    )


def _parse_caption_sites(raw: bytes) -> tuple[CaptionSite, ...]:
    sites: list[CaptionSite] = []
    pos = 0
    while True:
        m = raw.find(_BBCTL_SITE_MARKER, pos)
        if m < 0:
            break
        site = _parse_caption_site(raw, m)
        if site is not None:
            sites.append(site)
        pos = m + len(_BBCTL_SITE_MARKER)
    return tuple(sites)


def load_title(path: pathlib.Path) -> LoadedTitle | None:
    """Read a `.ttl` and return a LoadedTitle, or None on any failure."""
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:
        log.info("load_title path=%s open_failed=%r", path, exc)
        return None
    try:
        title_name = _parse_title_name(
            ole.openstream(["1", "0", "\x03properties"]).read(),
        )
        caption, rect = _parse_cbframe(
            ole.openstream(["3", "0", "\x03object"]).read(),
        )
        font_table = _parse_cstylesheet(
            ole.openstream(["4", "0", "\x03object"]).read(),
        )
        page_bg = _parse_cvform_page_bg(
            ole.openstream(["5", "0", "\x03object"]).read(),
        )
        cbform_body = _decompress_cbform(
            ole.openstream(["6", "0", "\x03object"]).read(),
        )
        captions = _parse_caption_sites(cbform_body)
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
        page_bg=page_bg,
        page_pixel_w=width,
        page_pixel_h=height,
        font_table=font_table,
        captions=captions,
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
_SEC06_COLOR_INHERIT = 0xFFFFFFFF
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
    # CBFrame's (left, top) is the design-time desktop position; SR lives
    # in window coordinates, so anchor it at (0, 0).
    _, _, width, height = title.window_rect
    struct.pack_into("<iiii", record, 0x49, 0, 0, width, height)
    struct.pack_into("<I", record, 0x5B, _SEC06_COLOR_INHERIT)
    struct.pack_into("<II", record, 0x78, _SEC06_COLOR_INHERIT, _SEC06_COLOR_INHERIT)
    struct.pack_into("<iiii", record, 0x80, *_SEC06_RECT_INHERIT)
    return bytes(record)


_TITLE_DEID_PLACEHOLDER = b"00000000-0000-0000-0000-000000000000\x00"


def lower_to_payload(title: LoadedTitle) -> bytes:
    """Assemble the 9-section TitleOpen body for a LoadedTitle."""
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

_TWIP_PER_PIXEL = 1440 // 96                                # 15 twips / px at 96 DPI


def _twips_to_pixels(twips: int) -> int:
    return (twips * 96) // 1440


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
        x = _twips_to_pixels(cap.rect_twips[0])
        y = _twips_to_pixels(cap.rect_twips[1])
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
