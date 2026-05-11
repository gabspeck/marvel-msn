"""Hardcoded MEDVIEW payloads for the empty MSN Today render.

Two module-level `bytes` constants assembled at import time:

- `TITLE_OPEN_BODY` — 9-section title body shipped on TitleOpen 0x86
  dynamic. Single window scaffold, single font descriptor, single
  caption "MSN Today". Drives MOSVIEW into a steady idle state with a
  single CBFrame at 640×480.
- `BM0_BAGGAGE` — 38445 B kind=5 raster (640×480 1bpp white, empty
  trailer) wrapped in the multi-bitmap container preamble. Returned by
  selector 0x1A `bm0` and chunked out via 0x1B reads.

`TITLE_OPEN_METADATA` carries the static-section dwords that pin the
TitleOpen reply (slot, va, addr, topic_count, two cache header dwords).
Values are arbitrary nonzero constants — there is no on-disk MVCache_*.tmp
to validate against on the empty path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ...blackbird.wire import (
    build_baggage_container,
    build_kind5_raster,
    build_trailer,
)

# --------------------------------------------------------------------------
# TitleOpen static-section metadata
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TitleOpenMetadata:
    title_slot: int
    file_system_mode: int
    contents_va: int
    addr_base: int
    topic_count: int
    cache_header0: int
    cache_header1: int


TITLE_OPEN_METADATA = TitleOpenMetadata(
    title_slot=0x01,
    file_system_mode=0x01,
    contents_va=0x00001000,
    addr_base=0x00001000,
    topic_count=0x00000001,
    cache_header0=0x12345678,
    cache_header1=0x9ABCDEF0,
)


# --------------------------------------------------------------------------
# Section 0 — minimal font table (96 bytes)
# --------------------------------------------------------------------------
#
# Single descriptor (Times New Roman 12pt 400-weight) with face_slot 0.
# `descriptor_count = 0xFFFF` sign-extends to -1 so MVCL14N's
# `ResolveTextStyleFromViewer` clamps every authored style_id to 0 — any
# layout chunk that references a style resolves to descriptor[0].

_SEC0_HEADER_SIZE = 0x12
_SEC0_FACE_ENTRY_SIZE = 0x20
_SEC0_DESCRIPTOR_SIZE = 0x2A
_SEC0_POINTER_ENTRY_SIZE = 0x04


def _build_section0() -> bytes:
    face_table = b"Times New Roman".ljust(_SEC0_FACE_ENTRY_SIZE, b"\x00")
    descriptor = bytearray(_SEC0_DESCRIPTOR_SIZE)
    struct.pack_into("<HHH", descriptor, 0x00, 0, 0, 0)
    descriptor[0x06:0x09] = b"\x01\x01\x01"  # text_color = inherit
    descriptor[0x09:0x0C] = b"\x01\x01\x01"  # back_color = inherit
    struct.pack_into(
        "<iiiii",
        descriptor,
        0x0C,
        -12,  # lfHeight
        0,    # lfWidth
        0,    # lfEscapement
        0,    # lfOrientation
        400,  # lfWeight
    )
    pointer_table = b"\x00" * _SEC0_POINTER_ENTRY_SIZE

    face_off = _SEC0_HEADER_SIZE
    descriptor_off = face_off + len(face_table)
    pointer_off = descriptor_off + len(descriptor)

    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                   # +0x00 header_word_0
        0xFFFF,              # +0x02 descriptor_count (clamp-to-0)
        face_off,            # +0x04 face_name_table_off
        descriptor_off,      # +0x06 descriptor_table_off
        0,                   # +0x08 override_count
        pointer_off,         # +0x0a override_table_off (= pointer_off)
        0,                   # +0x0c header_word_0c
    )
    struct.pack_into("<H", header, 0x10, pointer_off)
    return bytes(header) + face_table + bytes(descriptor) + pointer_table


# --------------------------------------------------------------------------
# Section 6 — one window scaffold record (152 bytes)
# --------------------------------------------------------------------------
#
# Single CBFrame at (0, 0, 640, 480), caption "MSN Today", inherit-color
# panes. Field semantics per `docs/cbframe-cbform-sec06-mapping.md`.

_SEC06_RECORD_SIZE = 0x98
_SEC06_FLAG_OUTER_RECT_ABSOLUTE = 0x08
_SEC06_COLOR_INHERIT = 0xFFFFFFFF
_SEC06_RECT_INHERIT = (-1, -1, -1, -1)


def _build_sec06_record() -> bytes:
    record = bytearray(_SEC06_RECORD_SIZE)
    caption = b"MSN Today\x00"
    record[0x15:0x15 + len(caption)] = caption
    record[0x48] = _SEC06_FLAG_OUTER_RECT_ABSOLUTE
    struct.pack_into("<iiii", record, 0x49, 0, 0, 640, 480)
    struct.pack_into("<I", record, 0x5B, _SEC06_COLOR_INHERIT)
    struct.pack_into("<II", record, 0x78, _SEC06_COLOR_INHERIT, _SEC06_COLOR_INHERIT)
    struct.pack_into("<iiii", record, 0x80, *_SEC06_RECT_INHERIT)
    return bytes(record)


# --------------------------------------------------------------------------
# 9-section body assembly
# --------------------------------------------------------------------------


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


_TITLE_CAPTION = b"MSN Today\x00"
_TITLE_DEID = b"00000000-0000-0000-0000-000000000000\x00"


def _build_title_open_body() -> bytes:
    section0 = _build_section0()
    sec06 = _build_sec06_record()
    return b"".join(
        [
            _length_prefixed(section0),       # sec0: font table
            b"\x00\x00",                       # sec07: empty
            b"\x00\x00",                       # sec08: empty
            _length_prefixed(sec06),           # sec06: one window scaffold
            _length_prefixed(_TITLE_CAPTION),  # sec01: caption
            b"\x00\x00",                       # sec02: empty
            _length_prefixed(_TITLE_DEID),     # sec6a: deid placeholder
            b"\x00\x00",                       # sec13: empty
            b"\x00\x00",                       # sec04: count=0
        ]
    )


TITLE_OPEN_BODY = _build_title_open_body()
TITLE_CAPTION = _TITLE_CAPTION.rstrip(b"\x00").decode("ascii")


# --------------------------------------------------------------------------
# bm0 baggage — 38445 B kind=5 raster, 640×480 1bpp white
# --------------------------------------------------------------------------
#
# 8B preamble + 30B kind=5 header + 38400B all-FF pixel data + 7B empty
# trailer. Wide-form pixel_byte_count (38400 > 0x7FFF). Engine wrapper
# `MVPaintBitmapRecord` BitBlts the parsed raster into the parent cell
# at the slot's origin; an all-FF 1bpp source paints the DC's background
# color (typically white) across the full pane.

_BM0_WIDTH = 640
_BM0_HEIGHT = 480
_BM0_BPP = 1
_BM0_PIXEL_BYTES = _BM0_WIDTH * _BM0_HEIGHT // 8  # 38400 for 1bpp


def _build_bm0_baggage() -> bytes:
    raster = build_kind5_raster(
        width=_BM0_WIDTH,
        height=_BM0_HEIGHT,
        bpp=_BM0_BPP,
        pixel_data=b"\xFF" * _BM0_PIXEL_BYTES,
        trailer=build_trailer([], b""),
    )
    return build_baggage_container(raster)


BM0_BAGGAGE = _build_bm0_baggage()
